"""Ensemble: rules (A) + contacts (B) + local LLM (C) + calibration -> official score, verdict, type, first alert, warning.

analyze(scenario, use_llm=True, trust_gate=False) -> response dict of PLAN.md section 3. Never raises.
Deterministic: same input (and same LLM answer) -> same output. Message text is never logged or stored.
"""
import json
import os
import re

try:
    from . import rules, contacts
except ImportError:  # run as a script from backend/
    import rules, contacts

try:
    from . import warnings_ro
except ImportError:
    try:
        import warnings_ro
    except Exception:
        warnings_ro = None
except Exception:
    warnings_ro = None

try:
    from . import llm as _llm
except ImportError:
    try:
        import llm as _llm
    except Exception:
        _llm = None
except Exception:
    _llm = None

_HERE = os.path.dirname(os.path.abspath(__file__))

POINTS = {
    "RF_CODE_REQUEST": 35, "RF_REMOTE_ACCESS": 35, "RF_DATA_REQUEST": 30, "RF_PAYMENT_REQUEST": 25,
    "RF_SUSPICIOUS_CONTACT": 25, "RF_NEW_NUMBER": 20, "RF_SECRECY": 20, "RF_TOO_GOOD": 20, "RF_IMPERSONATION": 15,
    "RF_URGENCY": 15, "RF_THREAT": 15, "RF_EMOTIONAL_PRESSURE": 10, "RF_CHANNEL_SWITCH": 10,
}
BANDS = {"SAFE": (0, 24), "SUSPICIOUS": (25, 49), "SCAM": (50, 100)}
SCAM_TYPES = ["BANK_IMPERSONATION", "COURIER_FEE", "AUTHORITY_IMPERSONATION", "FAMILY_EMERGENCY", "TECH_SUPPORT",
              "MARKETPLACE", "ACCOUNT_TAKEOVER", "INVESTMENT", "ROMANCE", "JOB_OFFER", "PRIZE_LOTTERY", "OTHER", "NONE"]
try:
    with open(os.path.join(_HERE, "..", "Cerinte", "official_catalog.json"), encoding="utf-8") as _f:
        _cat = json.load(_f)
    POINTS.update({k: int(v) for k, v in (_cat.get("red_flag_points") or {}).items()})
    BANDS.update({k: tuple(v) for k, v in (_cat.get("verdict_bands") or {}).items()})
    SCAM_TYPES = list(_cat.get("scam_types") or SCAM_TYPES)
except Exception:
    pass

LABELS = {
    "SAFE": {"ro": "Pare în regulă", "en": "Looks fine"},
    "SUSPICIOUS": {"ro": "Atenție, verificați înainte să răspundeți", "en": "Careful, check before you reply"},
    "SCAM": {"ro": "Pare o țeapă! Nu răspundeți", "en": "Looks like a scam! Do not reply"},
}
ALERT_AT = BANDS.get("SUSPICIOUS", (25, 49))[0]
HARD_REQUESTS = {"RF_CODE_REQUEST", "RF_REMOTE_ACCESS", "RF_NEW_NUMBER", "RF_SECRECY", "RF_CHANNEL_SWITCH"}
SOFT_REQUESTS = {"RF_DATA_REQUEST", "RF_PAYMENT_REQUEST"}
TRIPWIRE = {"RF_CODE_REQUEST", "RF_REMOTE_ACCESS", "RF_DATA_REQUEST", "RF_PAYMENT_REQUEST"}


def _calibration():
    try:
        with open(os.path.join(_HERE, "calibration.json"), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"llm_flags": {}}


CAL = _calibration()


def verdict_for(score):
    if score >= BANDS["SCAM"][0]:
        return "SCAM"
    if score >= BANDS["SUSPICIOUS"][0]:
        return "SUSPICIOUS"
    return "SAFE"


def _score(codes):
    return min(100, sum(POINTS.get(c, 0) for c in set(codes)))


# --------------------------------------------------------------------------------------------- input cleanup

def _clean(scenario):
    s = scenario if isinstance(scenario, dict) else {}
    sender = s.get("sender") if isinstance(s.get("sender"), dict) else {}
    known = sender.get("known_contact", s.get("known_contact", False))
    known = bool(known) if not isinstance(known, str) else known.strip().lower() in ("true", "1", "yes", "da")
    channel = s.get("channel") if isinstance(s.get("channel"), str) and s.get("channel") else "sms"
    raw = s.get("messages")
    if isinstance(raw, (str, dict)):
        raw = [raw]
    if not isinstance(raw, list):
        raw = []
    msgs = []
    for i, m in enumerate(raw):
        if isinstance(m, str):
            m = {"from": "sender", "text": m}
        if not isinstance(m, dict):
            continue
        text = m.get("text")
        text = text if isinstance(text, str) else ("" if text is None else str(text))
        frm = str(m.get("from") or "sender").strip().lower()
        frm = "reader" if frm == "reader" else "sender"
        n = m.get("n")
        try:
            n = int(n)
        except Exception:
            n = len(msgs) + 1
        msgs.append({"n": n, "from": frm, "text": text})
    sid = s.get("id")
    return {"id": sid if isinstance(sid, (str, int)) else None, "channel": channel,
            "sender": {"name": sender.get("name"), "address": sender.get("address"), "known_contact": known},
            "known_contact": known, "messages": msgs}


# links contacts.py does not recognise: reserved/demo top-level domains and explicit http(s):// addresses
_EXTRA_LINK_RE = re.compile(
    r"(?<![@\w.-])(?:https?://(?:www\.)?[a-z0-9.-]+\.[a-z]{2,24}|(?:www\.)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
    r"(?:example|test|invalid|localhost))(?![a-z0-9-])(?:[/?#][^\s<>\"']*)?", re.I)


def _extra_links(text, ch):
    try:
        found = []
        for m in _EXTRA_LINK_RE.finditer(text[:rules.MAX_LEN]):
            if any(h["start"] <= m.start() < h["end"] for h in ch.get("highlights") or []):
                continue
            host = re.sub(r"^https?://", "", m.group(0), flags=re.I).split("/")[0].split("?")[0].split("#")[0].lower()
            if contacts.registrable(host) in contacts.OFFICIAL_DOMAINS:
                continue
            found.append({"start": m.start(), "end": m.end(), "flag": "RF_SUSPICIOUS_CONTACT"})
        if not found:
            return ch
        out = dict(ch)
        out["highlights"] = list(ch.get("highlights") or []) + found
        out["flags"] = ["RF_SUSPICIOUS_CONTACT"]
        out["all_official"] = False
        out["unofficial_links"] = list(ch.get("unofficial_links") or []) + [text[f["start"]:f["end"]] for f in found]
        return out
    except Exception:
        return ch


# --------------------------------------------------------------------------------------------- scam type

_TYPE_KW = {
    "TECH_SUPPORT": [(r"suport\w* tehnic|asistenta tehnica|\bwindows\b|microsoft|\bapple\b", 3),
                     (r"virus\w*|calculator\w*|laptop\w*|any ?desk|team ?viewer|de la distanta", 2)],
    "AUTHORITY_IMPERSONATION": [(r"\banaf\b|politi\w*|casa (?:nationala )?de pensii|casei de pensii|\bcnas\b|\bcnpp\b|ministerul|"
                                 r"primari\w*|guvern\w*|contribuabil\w*|procuror\w*|parchet\w*|diicot|\bdna\b|instant\w*|"
                                 r"judecator\w*|executor\w*|fiscul|impozit\w*|ghiseul|anpc|autoritatea", 4),
                                (r"pensi\w*|amenda|dosar\w*|indexar\w*", 1)],
    "BANK_IMPERSONATION": [(r"\bbanca\b|\bbancii\b|banca dunarea|bancadunarea|\bbcr\b|\bbrd\b|\bing\b|raiffeisen|"
                            r"(?<!pe )(?<!prin )(?<!in )\brevolut\b(?! \d)|"
                            r"banca transilvania|internet banking|consilier\w* bancar", 3),
                           (r"card\w* (?:a fost |este |e )?blocat|tranzacti\w* suspect|cont\w* (?:a fost |este )?(?:blocat|suspendat)", 3)],
    "COURIER_FEE": [(r"\bcolet\w*|\bawb\b|curier\w*|posta\w*|\bdhl\b|fan ?courier|cargus|sameday|taxa vamala|vama", 3),
                    (r"livrar\w*|reprogramar\w*", 1)],
    "MARKETPLACE": [(r"piata ?mea|piatamea|\bolx\b|cumparator\w*|vanzator\w*|\banunt\w*|livrare sigura|mai (?:este|e) disponibil\w*|"
                     r"(?:ca sa|pentru a) primiti banii|primiti banii|v-am platit|am platit deja", 4)],
    "FAMILY_EMERGENCY": [(r"\bmami\b|\bmama\b|\bmamico\b|\btati\b|\btata\b|\bbunico\b|\bbuni\b|bunicule|mamaie|tataie|nepot\w*|"
                          r"\bfiul\b|\bfiica\b", 2), (r"accident\w*|spital\w*|arestat|retinut|cautiune", 1)],
    "ACCOUNT_TAKEOVER": [(r"din greseala|ti-am trimis|v-am trimis|mi-l (?:poti|puteti)|trimite-mi codul|codul de 6 cifre|"
                          r"cod de 6 cifre|\d cifre", 3)],
    "INVESTMENT": [(r"investi\w*|crypto|cripto\w*|bitcoin|randament\w*|profit\w*|trading|broker\w*|actiuni|platforma de|"
                    r"portofoliu|dividend\w*|bursa", 3)],
    "ROMANCE": [(r"iubir\w*|te iubesc|te ador|dor de tine|mi-?e (?:foarte |tare )?dor|imi e (?:foarte |tare )?dor|"
                 r"abia astept sa (?:ne vedem|te vad|ne intalnim)|inima mea|dragostea mea|draga mea|dragul meu|sufletul meu|scumpa mea|ne-am cunoscut|vreau sa te (?:vad|cunosc)|"
                 r"soldat|misiune|platforma petroliera|vaduv\w*|singur\w* pe lume", 3),
                # the far-away suitor: offshore / oil rig / ship / army mission, "sa te cunosc mai bine", travel money to come and meet
                (r"platform\w* (?:marin\w*|petrolier\w*|offshore|maritim\w*)|\boffshore\b|oil rig|\bpe (?:un|o) (?:vapor|nava|petrolier)\b|"
                 r"misiune (?:militar\w*|de pace|in strainatate|onu)|militar\w* (?:in|din) (?:misiune|siria|afganistan|irak)|"
                 r"sa te cunosc (?:mai bine|in realitate|personal)|sa ne cunoastem (?:mai bine|personal)|"
                 r"(?:vreau|as vrea|mi-?ar placea|abia astept) sa (?:vin|ajung|zbor) (?:la tine|sa te (?:vad|cunosc|intalnesc))|"
                 r"(?:bilet\w*|zbor\w*|drum\w*|avion\w*|calatori\w*)\b[^.!?\n]{0,40}\b(?:sa (?:vin|ajung) la tine|sa te (?:vad|cunosc|intalnesc))|"
                 r"(?:sa (?:vin|ajung) la tine|sa te (?:vad|cunosc|intalnesc))\b[^.!?\n]{0,60}\b(?:bilet\w*|zbor\w*|avion\w*|calatori\w*)", 3)],
    "JOB_OFFER": [(r"\bjob\w*|angajar\w*|loc de munca|locuri de munca|recrut\w*|like-?uri|aprecieri|recenzi\w*|sarcin\w*|task\w*|"
                   r"part-?time|de acasa|comision\w*", 3)],
    "PRIZE_LOTTERY": [(r"tombola|ati castigat|ai castigat|castigator\w*|premiu\w*|loteri\w*|extragere|ati fost (?:ales|selectat)", 4)],
}
_TYPE_PRIORITY = ["ACCOUNT_TAKEOVER", "TECH_SUPPORT", "MARKETPLACE", "AUTHORITY_IMPERSONATION", "BANK_IMPERSONATION",
                  "COURIER_FEE", "FAMILY_EMERGENCY", "PRIZE_LOTTERY", "INVESTMENT", "JOB_OFFER", "ROMANCE"]
_TYPE_RX = {t: [(re.compile(p), w) for p, w in kws] for t, kws in _TYPE_KW.items()}


def _scam_type(flags, sender_texts, sc, org, llm_type):
    try:
        # normalised text: "B@NCA DUN@REA", "c0dul", "t3amv1ewer" count as the words they hide
        norm = getattr(rules, "norm_text", rules.fold)
        ft = norm(" \n ".join(t[:rules.MAX_LEN] for t in sender_texts))[:40000]
        sname = norm(str(sc["sender"].get("name") or ""))
        blob = ft + " \n " + sname
        sc_ = {t: 0 for t in _TYPE_RX}
        for t, lst in _TYPE_RX.items():
            for rx, w in lst:
                if rx.search(blob):
                    sc_[t] += w
        f = set(flags)
        claims = "RF_IMPERSONATION" in f
        if not claims:
            # an authority / bank word that nobody claims to be ("sunt la poliție") is weak evidence
            for t in ("AUTHORITY_IMPERSONATION", "BANK_IMPERSONATION"):
                sc_[t] = min(sc_[t], 1)
        if "RF_REMOTE_ACCESS" in f:
            sc_["TECH_SUPPORT"] += 3
        if "RF_NEW_NUMBER" in f:
            sc_["FAMILY_EMERGENCY"] += 5
        if "RF_CODE_REQUEST" in f and not claims:
            sc_["ACCOUNT_TAKEOVER"] += 3
            if sc["known_contact"]:
                sc_["ACCOUNT_TAKEOVER"] += 2
        if claims and sc_["BANK_IMPERSONATION"] >= 3:
            sc_["BANK_IMPERSONATION"] += 3
        if "RF_TOO_GOOD" in f:
            sc_["PRIZE_LOTTERY"] += 1
            sc_["INVESTMENT"] += 1
        if "RF_PAYMENT_REQUEST" in f:
            sc_["COURIER_FEE"] += 1 if sc_["COURIER_FEE"] else 0
            sc_["FAMILY_EMERGENCY"] += 1 if sc_["FAMILY_EMERGENCY"] else 0
        if org == "Banca Dunărea":
            sc_["BANK_IMPERSONATION"] += 2
        elif org == "CurierExpres":
            sc_["COURIER_FEE"] += 2
        elif org == "ANAF":
            sc_["AUTHORITY_IMPERSONATION"] += 2
        elif org == "PiațaMea":
            sc_["MARKETPLACE"] += 2
        best = max(sc_.values())
        if best <= 0:
            # no deterministic evidence for any story: the small LLM is not trusted to pick one on its own
            return "OTHER"
        tied = [t for t in _TYPE_PRIORITY if sc_.get(t) == best]
        if len(tied) > 1 and llm_type in tied and CAL.get("llm_scam_type_tiebreak", True):
            return llm_type
        return tied[0]
    except Exception:
        return "OTHER"


# --------------------------------------------------------------------------------------------- LLM

def _llm_run(sc, use_llm):
    """-> (result | None, used, status); status: ok | off | unavailable | invalid_output | no_sender_text.
    llm.analyze retries a failed call twice before giving up, so 'unavailable' means the model really did not answer."""
    if not use_llm:
        return None, False, "off"
    if _llm is None:
        return None, False, "unavailable"
    try:
        res = _llm.analyze({"id": sc["id"], "channel": sc["channel"], "sender": sc["sender"], "messages": sc["messages"]})
        if not isinstance(res, dict):
            st = _llm.last_status() if hasattr(_llm, "last_status") else "unavailable"
            return None, False, ("no_sender_text" if st == "skipped" else st)
        return res, True, "ok"
    except Exception:
        return None, False, "unavailable"


def _llm_flags_by_n(res):
    out = {}
    try:
        for pm in res.get("per_message") or []:
            if not isinstance(pm, dict):
                continue
            try:
                n = int(pm.get("n"))
            except Exception:
                continue
            for fl in pm.get("flags") or []:
                if isinstance(fl, dict) and fl.get("code") in POINTS:
                    out.setdefault(n, []).append((fl.get("code"), str(fl.get("evidence") or "")))
    except Exception:
        pass
    for n in out:   # canonical order: the model's own flag order must not change flag order or signals
        out[n].sort(key=lambda ce: (ce[0], ce[1]))
    return out


def _accept_llm(code, evidence, text, ftext, known):
    cfg = (CAL.get("llm_flags") or {}).get(code) or {}
    if not cfg.get("accept", False):
        return None
    if cfg.get("unknown_sender_only") and known:
        return None
    ev = rules.fold(evidence).strip().strip("\"'„”“ .,")
    if len(ev) < int(cfg.get("min_evidence_chars", 6)):
        return None
    i = ftext.find(ev)
    if i < 0:
        ev2 = re.sub(r"\s+", " ", ev)
        i = re.sub(r"\s+", " ", ftext).find(ev2)
        if i < 0:
            return None
        return (0, 0)
    if code in ("RF_CODE_REQUEST", "RF_REMOTE_ACCESS", "RF_DATA_REQUEST"):
        # the model must not turn a protective sentence ("nu mi-l da", "nu il spune nimanui") into a request
        a = max([0] + [m.end() for m in re.finditer(r"[!?\n]+|\.(?=\s|$)", ftext[:i])])
        if re.search(r"\bnu\b|\bniciodata\b|\bnimanui\b", ftext[a:i + len(ev)]):
            return None
    return (i, i + len(ev))


# --------------------------------------------------------------------------------------------- main

def _empty_result(sc, skipped=False):
    per = []
    for m in sc["messages"]:
        per.append({"n": m["n"], "from": m["from"], "text": m["text"], "new_flags": [], "cumulative_score": 0,
                    "verdict_so_far": "SAFE", "highlights": []})
    res = {"id": sc["id"], "channel": sc["channel"], "known_contact": sc["known_contact"], "verdict": "SAFE",
           "scam_type": "NONE", "risk_score": 0, "first_alert": None, "red_flags": [], "label": dict(LABELS["SAFE"]),
           "warning": {"ro": "", "en": ""}, "per_message": per,
           "signals": {"rules": [], "contacts": [], "llm": [], "llm_used": False, "llm_status": "off", "skipped_by_trust_gate": skipped}}
    res["warning"] = _warning(res, {})
    return res


def _warning(result, extra):
    try:
        if warnings_ro is not None:
            w = warnings_ro.build(result, extra)
            if isinstance(w, dict) and w.get("ro"):
                return {"ro": str(w.get("ro")), "en": str(w.get("en") or "")}
    except Exception:
        pass
    v = result.get("verdict")
    if v == "SCAM":
        return {"ro": "Atenție, pare o țeapă! Nu trimiteți bani, coduri sau date. Sunați persoana sau instituția la un număr pe care îl cunoașteți deja.",
                "en": "Careful, this looks like a scam! Do not send money, codes or personal details. Call the person or institution on a number you already know."}
    if v == "SUSPICIOUS":
        return {"ro": "Atenție, verificați înainte să răspundeți. Nu trimiteți bani, coduri sau date până nu verificați la un număr cunoscut.",
                "en": "Careful, check before you reply. Do not send money, codes or details until you check on a number you know."}
    return {"ro": "Pare în regulă. Nu am găsit semne de țeapă în acest mesaj.",
            "en": "Looks fine. We found no signs of a scam in this message."}


def analyze(scenario, use_llm=True, trust_gate=False):
    try:
        sc = _clean(scenario)
    except Exception:
        sc = {"id": None, "channel": "sms", "sender": {"name": None, "address": None, "known_contact": False},
              "known_contact": False, "messages": []}
    try:
        return _analyze(sc, use_llm, trust_gate)
    except Exception:
        try:
            return _empty_result(sc)
        except Exception:
            return {"id": None, "channel": "sms", "known_contact": False, "verdict": "SAFE", "scam_type": "NONE",
                    "risk_score": 0, "first_alert": None, "red_flags": [], "label": dict(LABELS["SAFE"]),
                    "warning": {"ro": "Pare în regulă.", "en": "Looks fine."}, "per_message": [],
                    "signals": {"rules": [], "contacts": [], "llm": [], "llm_used": False, "skipped_by_trust_gate": False}}


def _analyze(sc, use_llm, trust_gate):
    known = sc["known_contact"]
    sender = sc["sender"]
    channel = sc["channel"]

    # Trust Circle gate: saved contacts are not analysed unless the tiny tripwire trips.
    if trust_gate and known:
        tripped = False
        for m in sc["messages"]:
            if m["from"] != "sender":
                continue
            codes = {h["code"] for h in rules.detect(m["text"], {"channel": channel, "known_contact": known,
                                                                 "sender": sender, "n": m["n"], "prior_flags": []})}
            if codes & TRIPWIRE:
                tripped = True
                break
        if not tripped:
            return _empty_result(sc, skipped=True)

    llm_res, llm_used, llm_status = _llm_run(sc, use_llm)
    llm_by_n = _llm_flags_by_n(llm_res) if llm_res else {}

    seen, order = set(), []
    src = {"rules": [], "contacts": [], "llm": []}
    per = []
    first_alert = None
    orgs = []
    sender_texts = []
    for m in sc["messages"]:
        text = m["text"]
        entry = {"n": m["n"], "from": m["from"], "text": text, "new_flags": [], "cumulative_score": _score(seen),
                 "verdict_so_far": verdict_for(_score(seen)), "highlights": []}
        if m["from"] == "sender":
            sender_texts.append(text)
            ctx = {"channel": channel, "known_contact": known, "sender": sender, "n": m["n"], "prior_flags": list(order)}
            rh = rules.detect(text, ctx)
            ch = contacts.check(text, sender, channel)
            if ch.get("official_org"):
                orgs.append(ch["official_org"])
            ch = _extra_links(text, ch)
            rcodes = {h["code"] for h in rh}
            ccodes = set(ch.get("flags") or [])
            # an unknown sender address alone (no link in the text, no catalog organisation named, nothing requested,
            # no impersonation) is not evidence: a plain reminder must not reach the alert band on that alone
            if (ccodes == {"RF_SUSPICIOUS_CONTACT"} and not ch.get("highlights") and not ch.get("official_org")
                    and not (rcodes & (HARD_REQUESTS | SOFT_REQUESTS | {"RF_TOO_GOOD", "RF_THREAT", "RF_IMPERSONATION"}))):
                ch = dict(ch, flags=[], unofficial_links=[], all_official=True)
                ccodes = set()
            codes = rcodes | ccodes
            # genuine-message guard: official sender or official reference, nothing unofficial, nothing really requested
            genuine = (ch.get("all_official", True) and (ch.get("sender_official") or ch.get("official_refs"))
                       and not (codes & HARD_REQUESTS)
                       and "RF_DATA_REQUEST" not in codes
                       and not ("RF_PAYMENT_REQUEST" in codes
                                and not (ch.get("official_refs") and ch.get("sender_official"))))
            hls = []
            msg_codes = []
            if not genuine:
                for h in rh:
                    if h["end"] > h["start"]:
                        hls.append({"start": h["start"], "end": h["end"], "flag": h["code"]})
                for h in ch.get("highlights") or []:
                    hls.append(dict(h))
                # ties broken by code name: set order varies between processes (string hash randomisation)
                for c in sorted(codes, key=lambda c: (min([h["start"] for h in rh if h["code"] == c] or
                                                          [h["start"] for h in ch.get("highlights") or []] or [0]), c)):
                    msg_codes.append(c)
                    if c in rcodes and c not in src["rules"]:
                        src["rules"].append(c)
                    if c in ccodes and c not in src["contacts"]:
                        src["contacts"].append(c)
                ftext = rules.fold(text[:rules.MAX_LEN])
                for code, ev in llm_by_n.get(m["n"], []):
                    if code in codes:
                        if code not in src["llm"]:
                            src["llm"].append(code)
                        continue
                    span = _accept_llm(code, ev, text, ftext, known)
                    if span is None:
                        continue
                    codes.add(code)
                    msg_codes.append(code)
                    if code not in src["llm"]:
                        src["llm"].append(code)
                    if span[1] > span[0]:
                        hls.append({"start": span[0], "end": span[1], "flag": code})
            new = []
            for c in msg_codes:
                if c not in seen:
                    seen.add(c)
                    order.append(c)
                    new.append(c)
            entry["new_flags"] = new
            hls.sort(key=lambda h: (h["start"], h["end"]))
            entry["highlights"] = hls
            score = _score(seen)
            entry["cumulative_score"] = score
            entry["verdict_so_far"] = verdict_for(score)
            if first_alert is None and score >= ALERT_AT:
                first_alert = m["n"]
        per.append(entry)

    score = _score(seen)
    verdict = verdict_for(score)
    org = orgs[0] if orgs else None
    llm_type = (llm_res or {}).get("scam_type") if llm_res else None
    scam_type = "NONE" if verdict == "SAFE" else _scam_type(order, sender_texts, sc, org, llm_type)
    if verdict == "SAFE":
        first_alert = None

    # details for the warning text (deterministic first, LLM only if its value occurs in the thread)
    person = None
    for t in sender_texts:
        person = rules.person_name(t)
        if person:
            break
    if not person and llm_res and CAL.get("llm_person_name", True):
        pn = llm_res.get("person_name")
        if isinstance(pn, str) and 2 < len(pn) < 30 and any(pn in t for t in sender_texts):
            person = pn.strip()
    claimed = org
    if not claimed and llm_res:
        co = llm_res.get("claimed_org")
        if isinstance(co, str) and co.strip() and any(rules.fold(co) in rules.fold(t) for t in sender_texts):
            claimed = co.strip()

    result = {
        "id": sc["id"], "channel": channel, "known_contact": known,
        "verdict": verdict, "scam_type": scam_type, "risk_score": score, "first_alert": first_alert,
        "red_flags": list(order), "label": dict(LABELS[verdict]), "warning": {"ro": "", "en": ""},
        "per_message": per,
        "signals": {"rules": src["rules"], "contacts": src["contacts"], "llm": src["llm"], "llm_used": bool(llm_used),
                    "llm_status": llm_status, "skipped_by_trust_gate": False},
    }
    extra = {"claimed_org": claimed, "catalog_org": org, "person_name": person,
             "sender_name": sender.get("name"), "sender_texts_folded": [rules.fold(t[:4000]) for t in sender_texts]}
    result["warning"] = _warning(result, extra)
    return result
