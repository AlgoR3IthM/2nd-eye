"""Signal B: links, e-mail addresses and phone numbers vs the official catalog.

check(text, sender, channel) -> {
    "flags": ["RF_SUSPICIOUS_CONTACT"] or [],
    "official_org": str | None,          # catalog organisation named / referenced in the message
    "unofficial_links": [str],           # unofficial domains / e-mails / phones (never shown to the user as usable)
    "highlights": [{"start","end","flag"}],
    # extras used by fusion
    "official_refs": bool,               # message contains an official website / phone of a catalog org
    "sender_official": bool,             # sender address is the org's own sender id or official e-mail domain
    "sender_org": str | None,            # catalog org the sender address belongs to
    "all_official": bool,                # nothing unofficial found (links, e-mails, phones, sender e-mail)
    "lookalike": bool,                   # an unofficial domain imitates an official brand
}
Never raises.
"""
import json
import os
import re
import unicodedata

_HERE = os.path.dirname(os.path.abspath(__file__))
_CATALOG_PATH = os.path.join(_HERE, "..", "Cerinte", "official_catalog.json")


def _load_catalog():
    try:
        with open(_CATALOG_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"official_contacts": []}


CATALOG = _load_catalog()


def _fold(s):
    """lowercase, no diacritics, same length as input."""
    out = []
    for ch in s or "":
        d = unicodedata.normalize("NFKD", ch)
        b = "".join(c for c in d if not unicodedata.combining(c))
        b = (b[:1] or ch).lower()
        out.append(b[:1] or " ")
    return "".join(out)


def _compact(s):
    return re.sub(r"[^a-z0-9]", "", _fold(s))


def _digits(s):
    d = re.sub(r"\D", "", s or "")
    if d.startswith("0040"):
        d = "0" + d[4:]
    elif d.startswith("40") and len(d) == 11:
        d = "0" + d[2:]
    return d


ORGS = []  # [{name, website, phone, token, phone_digits, text_re}]
for _c in CATALOG.get("official_contacts", []) or []:
    try:
        _name = _c.get("organisation") or ""
        _web = (_c.get("website") or "").lower().strip()
        _tok = _compact(_name)
        # "Banca Dunărea" -> banca\s*dunarea ; "PiațaMea" -> piata\s*mea ; "ANAF" -> anaf
        _base = "".join(c for c in unicodedata.normalize("NFKD", _name) if not unicodedata.combining(c))
        _parts = [x.lower() for x in re.findall(r"[A-Z][a-z]+|[A-Z0-9]+(?![a-z])|[a-z0-9]+", _base)]
        _pat = r"\s*-?\s*".join(_parts) if _parts else re.escape(_tok)
        ORGS.append({
            "name": _name, "website": _web, "phone": _c.get("phone"), "token": _tok,
            "phone_digits": _digits(_c.get("phone")) if _c.get("phone") else None,
            "text_re": re.compile(r"(?<![a-z0-9])" + _pat + r"(?![a-z0-9])"),
        })
    except Exception:
        pass

OFFICIAL_DOMAINS = {o["website"]: o for o in ORGS if o["website"]}
OFFICIAL_PHONES = {o["phone_digits"]: o for o in ORGS if o["phone_digits"]}

FREEMAIL = {"gmail.com", "yahoo.com", "yahoo.ro", "outlook.com", "hotmail.com", "icloud.com", "live.com",
            "ymail.com", "protonmail.com", "proton.me", "gmx.com", "gmx.net", "mail.com", "aol.com"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "t.ly", "shorturl.at"}

_TLDS = ("ro|com|net|org|info|eu|io|co|biz|xyz|top|online|site|me|app|ly|link|click|shop|store|live|uk|de|it|fr|md|"
         "ru|cc|tk|ml|ga|cf|gq|ws|pw|us|club|vip|win|icu|cn|ua|hu|bg|es|nl|pl|tv|gl|at|ch|be|cloud|support|help|"
         "services|service|website|page|cam|buzz|work|pro|mobi|name|asia|in|tr|gov|edu|ly")
_URL_RE = re.compile(
    r"(?<![@\w.-])(?:https?://)?(?:www\.)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:" + _TLDS + r"))(?![a-z0-9-])(?:[/?#:][^\s<>\"']*)?",
    re.I)
_EMAIL_RE = re.compile(r"[a-z0-9._%+-]+@((?:[a-z0-9-]+\.)+[a-z]{2,})", re.I)
_PHONE_RE = re.compile(r"(?<![\w+])(?:\+|00)?(?:40[\s.-]?)?\(?0?[2378x][\dx]{1,3}\)?(?:[\s.-]?[\dx]{2,4}){2,3}(?!\w)", re.I)


def registrable(domain):
    d = (domain or "").lower().strip(".")
    if d.startswith("www."):
        d = d[4:]
    parts = d.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "gov", "net", "ac", "edu"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _lev(a, b):
    if abs(len(a) - len(b)) > 2:
        return 9
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def domain_org(domain):
    """(org, official:bool, lookalike:bool) for a domain."""
    reg = registrable(domain)
    if reg in OFFICIAL_DOMAINS:
        return OFFICIAL_DOMAINS[reg], True, False
    comp = re.sub(r"[^a-z0-9]", "", reg.rsplit(".", 1)[0])
    full = re.sub(r"[^a-z0-9]", "", (domain or "").lower())
    for o in ORGS:
        t = o["token"]
        if not t:
            continue
        if len(t) <= 4:
            # short tokens (anaf): must be a separate label part, e.g. anaf-rambursari.net, anaf.gov-ro.com
            if re.search(r"(?<![a-z0-9])" + t + r"(?![a-z0-9])", reg.replace(".", " ").replace("-", " ")) or \
               re.search(r"(?<![a-z0-9])" + t + r"(?![a-z0-9])", (domain or "").lower().replace(".", " ").replace("-", " ")):
                return o, False, True
        elif t in comp or t in full:
            return o, False, True
        else:
            label = reg.rsplit(".", 1)[0]
            if _lev(re.sub(r"[^a-z0-9]", "", label), t) <= 2:
                return o, False, True
    return None, False, False


def _sender_info(sender):
    """(sender_org, sender_official, sender_unofficial_email, org_claim_in_name)"""
    if not isinstance(sender, dict):
        return None, False, None, None
    addr = str(sender.get("address") or "")
    name = str(sender.get("name") or "")
    m = _EMAIL_RE.search(addr)
    if m:
        dom = m.group(1).lower()
        org, official, _look = domain_org(dom)
        if official:
            return org, True, None, org
        name_org = None
        for o in ORGS:
            if o["text_re"].search(_fold(name)):
                name_org = o
        return (org or name_org), False, dom, name_org
    ca = _compact(addr)
    for o in ORGS:
        if ca and ca == o["token"]:
            return o, True, None, o
    return None, False, None, None


def check(text, sender, channel):
    res = {"flags": [], "official_org": None, "unofficial_links": [], "highlights": [],
           "official_refs": False, "sender_official": False, "sender_org": None,
           "all_official": True, "lookalike": False}
    try:
        text = text if isinstance(text, str) else ("" if text is None else str(text))
        t = text[:20000]
        ft = _fold(t)
        orgs_named = []
        unofficial = []
        hl = []

        # e-mail addresses in the text
        email_spans = []
        for m in _EMAIL_RE.finditer(t):
            email_spans.append((m.start(), m.end()))
            dom = m.group(1).lower()
            org, official, look = domain_org(dom)
            if org:
                orgs_named.append(org)
            if official:
                res["official_refs"] = True
            elif look or dom not in FREEMAIL:
                unofficial.append(m.group(0))
                res["lookalike"] = res["lookalike"] or look
                hl.append({"start": m.start(), "end": m.end(), "flag": "RF_SUSPICIOUS_CONTACT"})

        # links
        for m in _URL_RE.finditer(t):
            if any(a <= m.start() < b for a, b in email_spans):
                continue
            dom = m.group(1).lower()
            # skip things like "dvs.ro"? only real TLD list matches; skip pure-number labels
            if re.fullmatch(r"[\d.]+", dom):
                continue
            org, official, look = domain_org(dom)
            if org:
                orgs_named.append(org)
            if official:
                res["official_refs"] = True
                continue
            unofficial.append(m.group(0))
            res["lookalike"] = res["lookalike"] or look
            hl.append({"start": m.start(), "end": m.end(), "flag": "RF_SUSPICIOUS_CONTACT"})

        # organisations named in plain text (outside links)
        for o in ORGS:
            for m in o["text_re"].finditer(ft):
                inside_link = any(h["start"] <= m.start() < h["end"] for h in hl)
                if not inside_link:
                    orgs_named.append(o)
                    break

        sorg, sofficial, s_bad_email, _ = _sender_info(sender)
        res["sender_official"] = bool(sofficial)
        res["sender_org"] = sorg["name"] if sorg else None
        if sorg:
            orgs_named.insert(0, sorg)
        if s_bad_email:
            org_claim = bool(sorg) or bool(orgs_named)
            if s_bad_email not in FREEMAIL or org_claim:
                unofficial.append(str((sender or {}).get("address") or s_bad_email))

        # phone numbers in the text: only suspicious when an organisation is named and the number is not its official one
        for m in _PHONE_RE.finditer(t):
            raw = m.group(0)
            dg = _digits(raw)
            if len(re.sub(r"\D", "", raw)) + raw.lower().count("x") < 9:
                continue
            if any(h["start"] <= m.start() < h["end"] for h in hl):
                continue
            if dg in OFFICIAL_PHONES:
                res["official_refs"] = True
                orgs_named.append(OFFICIAL_PHONES[dg])
                continue
            if orgs_named:
                unofficial.append(raw)
                hl.append({"start": m.start(), "end": m.end(), "flag": "RF_SUSPICIOUS_CONTACT"})

        if orgs_named:
            res["official_org"] = orgs_named[0]["name"]
        res["unofficial_links"] = unofficial
        res["highlights"] = hl
        res["all_official"] = not unofficial
        if unofficial:
            res["flags"] = ["RF_SUSPICIOUS_CONTACT"]
    except Exception:
        pass
    return res


def org_info(name):
    """catalog entry by organisation name (for warnings)."""
    for o in ORGS:
        if o["name"] == name:
            return {"organisation": o["name"], "website": o["website"], "phone": o["phone"]}
    return None
