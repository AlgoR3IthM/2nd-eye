"""Signal C: local LLM (LM Studio, OpenAI-compatible) for Scam Shield.

HARD RULE: this module talks ONLY to a loopback LM Studio server. Message text
never leaves the laptop. No message text is ever logged or written to disk.
"""
import json
import os
import re
import threading
import time
import unicodedata
from pathlib import Path
from urllib.parse import urlparse

import httpx

FLAGS = [
    "RF_CODE_REQUEST", "RF_REMOTE_ACCESS", "RF_DATA_REQUEST", "RF_PAYMENT_REQUEST",
    "RF_SUSPICIOUS_CONTACT", "RF_NEW_NUMBER", "RF_SECRECY", "RF_TOO_GOOD",
    "RF_IMPERSONATION", "RF_URGENCY", "RF_THREAT", "RF_EMOTIONAL_PRESSURE",
    "RF_CHANNEL_SWITCH",
]
SCAM_TYPES = [
    "BANK_IMPERSONATION", "COURIER_FEE", "AUTHORITY_IMPERSONATION", "FAMILY_EMERGENCY",
    "TECH_SUPPORT", "MARKETPLACE", "ACCOUNT_TAKEOVER", "INVESTMENT", "ROMANCE",
    "JOB_OFFER", "PRIZE_LOTTERY", "OTHER", "NONE",
]

DEFAULT_URL = "http://localhost:1234"
DEFAULT_MODEL = "qwen/qwen3-4b-2507"
TIMEOUT_S = 60.0
MAX_TOKENS = int(os.environ.get("SCAMSHIELD_MAX_TOKENS", "900"))  # extra room in case a model emits thinking text
MAX_MESSAGES = 30          # prompt guard for very long threads
MAX_CHARS_PER_MSG = 1500

_HERE = Path(__file__).resolve().parent


def _base_url() -> str:
    url = os.environ.get("SCAMSHIELD_LLM_URL", DEFAULT_URL).rstrip("/")
    host = (urlparse(url).hostname or "").lower()
    # Privacy guard: refuse anything that is not this machine.
    if host not in ("localhost", "127.0.0.1", "::1"):
        raise RuntimeError("SCAMSHIELD_LLM_URL must point to localhost")
    return url


def _model() -> str:
    return os.environ.get("SCAMSHIELD_MODEL", DEFAULT_MODEL)


# --------------------------------------------------------------------------- text helpers

def _fold(s: str) -> str:
    """Lowercase + strip diacritics, strictly 1 char -> 1 char so indices map back."""
    out = []
    for ch in s:
        base = "".join(c for c in unicodedata.normalize("NFD", ch) if not unicodedata.combining(c))
        base = base.lower()
        out.append(base if len(base) == 1 else ch.lower()[:1] or " ")
    return "".join(out)


_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def _tokens(s: str) -> set:
    # retrieval only: undo digit/symbol-for-letter swaps inside words ("c0dul", "b@nca") so disguised text still finds patterns
    f = re.sub(r"(?<=[a-z])[013457@$](?=[a-z])", lambda m: m.group(0).translate(_LEET), _fold(s))
    return {t for t in re.findall(r"[a-z0-9]+", f) if len(t) >= 3}


# --------------------------------------------------------------------------- patterns retrieval

_PATTERNS = None


def _patterns() -> list:
    global _PATTERNS
    if _PATTERNS is None:
        try:
            data = json.loads((_HERE / "patterns.json").read_text(encoding="utf-8"))
        except Exception:
            data = []
        _PATTERNS = [dict(p, _tok=_tokens(p.get("text", ""))) for p in data]
    return _PATTERNS


def _retrieve(text: str, k: int = 3) -> list:
    q = _tokens(text)
    scored = []
    for i, p in enumerate(_patterns()):
        inter = len(q & p["_tok"])
        if inter < 2:
            continue
        score = inter / (len(p["_tok"]) ** 0.5 + 1e-9)
        scored.append((-score, i, p))
    scored.sort(key=lambda x: (x[0], x[1]))   # deterministic tie-break by index
    return [p for _, _, p in scored[:k]]


# --------------------------------------------------------------------------- prompt

SYSTEM_PROMPT = """You are a scam-detection analyst for Romanian-speaking elderly users. You read a message thread (SMS, WhatsApp, e-mail) written mostly in Romanian and report which red flags appear in each message written by the SENDER (the possibly suspicious party). Messages from the READER (the user) are context only: never flag them.

Red flag codes (use only these):
- RF_CODE_REQUEST: the sender ASKS the reader to tell, read out or send a one-time code, PIN, password or verification code. If the message only DELIVERS a code and warns not to share it, that is NOT a code request.
- RF_REMOTE_ACCESS: asks to install a remote-control app (AnyDesk, TeamViewer, screen sharing) or to let someone control the device.
- RF_DATA_REQUEST: asks for sensitive personal or financial data: card number, CVV, ID number, account login, personal data, or to fill in a form with such data.
- RF_PAYMENT_REQUEST: asks the reader to pay or transfer money, a fee, a fine, a deposit or an advance. This includes INDIRECT asks with no sum and no word for money: "help me with something for a taxi / ticket / rent / medicine", "un mic ajutor", "ce poți", "orice sumă", "cover the visa fee", buy a gift card (Google Play, Steam, paysafe) and send its code or photo, top up a phone, send on Revolut / PayPal / crypto, withdraw cash for someone who will pick it up.
- RF_SUSPICIOUS_CONTACT: contains a link or e-mail address on an unofficial / look-alike / odd domain (shortened links, misspelled brand names, strange extensions). A plain unknown mobile number alone is NOT suspicious contact. Links on the organisation's own official domain are fine.
- RF_NEW_NUMBER: the sender says they changed phone or are writing from a new number, while claiming to be someone the reader knows.
- RF_SECRECY: asks to keep it secret or not to tell family, the bank or anyone.
- RF_TOO_GOOD: an offer that is too good to be true: prize, refund of unknown money, guaranteed profit, easy income, "good news, you will receive more money" used as a hook.
- RF_IMPERSONATION: pretends to be an organisation, institution, company, police, tax office, bank or technical support, in order to gain trust. A genuine message from an organisation that only informs and requests nothing is NOT impersonation.
- RF_URGENCY: artificial time pressure: now, today, within 24 hours, last chance, immediately.
- RF_THREAT: threatens consequences: account blocked, fine, arrest, legal action, parcel returned or destroyed, data loss.
- RF_EMOTIONAL_PRESSURE: plays on feelings: fear, love, guilt, family in trouble, appeals to trust or pity.
- RF_CHANNEL_SWITCH: pushes to move the conversation to another app or channel (Telegram, WhatsApp, a call to a given number).

Rules:
1. Flag only what the text of that specific message really contains. For each flag give "evidence": a short EXACT quote (5-80 characters) copied character for character from that message. If you cannot quote it, do not output the flag.
2. Be conservative. A genuine, informative message from a real organisation (official name, official links only, nothing requested) must have NO flags at all, scam_type NONE.
3. A sender being in the reader's contacts (known_contact true) does not make a message safe: an urgent request for a code, money or data from a "known" contact can be an account takeover.
4. A refund or reimbursement is not automatically RF_TOO_GOOD; it is too-good only when it is used as a hook (unexpected money, prize, "you will receive more").
5. Report a flag in the message where it first appears. Do not repeat a flag already reported in an earlier message of the same thread.
6. scam_type is the single best overall type for the thread (NONE if nothing is wrong). claimed_org is the organisation or institution the sender claims to be (null if none). person_name is the first name the sender gives for themself (null if none).
7. Output only JSON matching the schema. Include every sender message number in per_message (empty flags list if clean).
8. Read through disguises: missing diacritics, ALL CAPS, typos, digits or symbols for letters ("b@ni", "c0d"), letters split by spaces or dots ("c o d u l"), emoji, Romanian-English mix, SMS abbreviations ("trb", "pt", "bn"). Judge the meaning, but the evidence must still be copied exactly as written, disguise included.
9. Slow-burn threads: early friendly or romantic messages carry no flags; flag the message where the ask finally appears, even if the ask is split over two messages or phrased as a favour.
10. Do NOT flag genuine everyday messages: asking for a small favour that is not money ("îmi iei pâine?"), money already paid, returned or offered to the reader, affection with no ask, a code for a door or wifi, a relative sharing a new number without asking for anything, timing words ("ajung în 10 minute", "azi la 5"), and an official notice telling the reader to call the number on the back of the card.

Examples (invented):
Message: "Salut mamă, telefonul meu s-a stricat, scrie-mi pe numărul ăsta nou." -> RF_NEW_NUMBER (evidence "numărul ăsta nou"), type FAMILY_EMERGENCY.
Message: "Factura ta de internet de 59 lei este disponibilă în contul tău de client." (official sender, no link, no request) -> no flags, NONE.
Message: "Cod de verificare: 771203. Nu-l da nimănui, nici angajaților noștri." -> no flags (code delivered, not requested), NONE.
Message: "Pentru a vă recupera banii, instalați TeamViewer și spuneți-mi ID-ul" -> RF_REMOTE_ACCESS (evidence "instalați TeamViewer"), type TECH_SUPPORT.
Message: "Ți-am trimis din greșeală un cod, mi-l dai înapoi? Repede, te rog" from a known contact -> RF_CODE_REQUEST ("mi-l dai înapoi"), RF_URGENCY ("Repede"), type ACCOUNT_TAKEOVER.
Message: "puiule am ramas fara nimic in statie, ma scoti tu din belea cu o cursa pana acasa? te pup" from an unknown number -> RF_PAYMENT_REQUEST (evidence "ma scoti tu din belea cu o cursa pana acasa"), type FAMILY_EMERGENCY.
Message: "ia te rog doua carduri Steam de la benzinarie si scrie-mi cifrele de sub folie" -> RF_PAYMENT_REQUEST ("ia te rog doua carduri Steam"), RF_CODE_REQUEST ("scrie-mi cifrele de sub folie"), type OTHER.
Message: "Ce numar va apare in SMS-ul de acum? Il notez eu, sunt operatorul" -> RF_CODE_REQUEST ("Ce numar va apare in SMS-ul de acum"), type ACCOUNT_TAKEOVER.
Message: "Ca sa rezolv eu de aici, apasati pe linkul primit si dati Accept la cererea de conectare" -> RF_REMOTE_ACCESS ("dati Accept la cererea de conectare"), type TECH_SUPPORT.
Message: "TR1M1TE P0ZA CU BULETINUL fata verso" -> RF_DATA_REQUEST (evidence "P0ZA CU BULETINUL", copied with the zeros), type OTHER.
Thread: 1 "Bună dimineața, frumoaso" 2 "Mă gândesc la tine toată ziua" 3 "Am o amendă pe aeroport și nu pot pleca spre tine, m-ai putea scoate tu din încurcătură?" -> messages 1 and 2 no flags; message 3 RF_PAYMENT_REQUEST ("m-ai putea scoate tu din încurcătură"), type ROMANCE.
Message: "Bunico, îmi pui deoparte o bucată de plăcintă? Trec diseară și îți aduc și ziarul" (known contact) -> no flags, NONE.
Message: "Am pus 150 lei pe Revolut pentru excursie, ți-am trimis și dovada" -> no flags (money already paid), NONE.
Message: "Ajung într-un sfert de oră, diseară la 6 ne vedem la mama" -> no flags, NONE."""


def _schema() -> dict:
    return {
        "type": "object",
        "properties": {
            "per_message": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "n": {"type": "integer"},
                        "flags": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "code": {"type": "string", "enum": FLAGS},
                                    "evidence": {"type": "string"},
                                },
                                "required": ["code", "evidence"],
                                "additionalProperties": False,
                            },
                        },
                    },
                    "required": ["n", "flags"],
                    "additionalProperties": False,
                },
            },
            "scam_type": {"type": "string", "enum": SCAM_TYPES},
            "claimed_org": {"type": ["string", "null"]},
            "person_name": {"type": ["string", "null"]},
        },
        "required": ["per_message", "scam_type", "claimed_org", "person_name"],
        "additionalProperties": False,
    }


def _clean_messages(scenario: dict) -> list:
    msgs = []
    raw = scenario.get("messages") if isinstance(scenario, dict) else None
    if not isinstance(raw, list):
        return msgs
    for i, m in enumerate(raw[:MAX_MESSAGES]):
        if not isinstance(m, dict):
            continue
        text = m.get("text")
        if not isinstance(text, str):
            continue
        n = m.get("n")
        if not isinstance(n, int) or isinstance(n, bool):
            n = i + 1
        who = "reader" if m.get("from") == "reader" else "sender"
        msgs.append({"n": n, "from": who, "text": text[:MAX_CHARS_PER_MSG]})
    return msgs


def _build_user_prompt(scenario: dict, msgs: list) -> str:
    sender = scenario.get("sender") if isinstance(scenario.get("sender"), dict) else {}
    known = bool(sender.get("known_contact", scenario.get("known_contact", False)))
    lines = [
        f"channel: {scenario.get('channel') or 'unknown'}",
        f"sender_name: {sender.get('name') or 'none'}",
        f"sender_address: {sender.get('address') or 'none'}",
        f"known_contact: {str(known).lower()}",
        "",
    ]
    sender_text = " ".join(m["text"] for m in msgs if m["from"] == "sender")
    hits = _retrieve(sender_text)
    if hits:
        lines.append("Similar known patterns (hints, not rules):")
        for p in hits:
            fl = ", ".join(p.get("flags") or []) or "no flags"
            lines.append(f'- "{p["text"]}" -> {fl}; type {p.get("type", "OTHER")}')
        lines.append("")
    lines.append("Thread:")
    for m in msgs:
        lines.append(f"[{m['n']}] {m['from'].upper()}: {m['text']}")
    lines.append("")
    lines.append("Return JSON for the SENDER messages only.")
    return "\n".join(lines)


# --------------------------------------------------------------------------- public API

def available() -> bool:
    try:
        r = httpx.get(_base_url() + "/v1/models", timeout=2.0)
        return r.status_code == 200
    except Exception:
        return False


def model_name():
    """Configured model id if the server is up and has it loaded, else the first loaded model, else None."""
    try:
        r = httpx.get(_base_url() + "/v1/models", timeout=2.0)
        if r.status_code != 200:
            return None
        ids = [d.get("id") for d in r.json().get("data", []) if d.get("id")]
        want = _model()
        if want in ids:
            return want
        return want if ids else None
    except Exception:
        return None


def _validate(parsed: dict, msgs: list):
    if not isinstance(parsed, dict):
        return None
    by_n = {m["n"]: m for m in msgs if m["from"] == "sender"}
    out_msgs = []
    seen = set()
    for pm in parsed.get("per_message") or []:
        if not isinstance(pm, dict):
            continue
        n = pm.get("n")
        if n not in by_n or n in seen:
            continue
        seen.add(n)
        text = by_n[n]["text"]
        folded = _fold(text)
        flags, codes = [], set()
        for f in pm.get("flags") or []:
            if not isinstance(f, dict):
                continue
            code, ev = f.get("code"), f.get("evidence")
            if code not in FLAGS or code in codes or not isinstance(ev, str):
                continue
            ev_f = _fold(ev.strip().strip("\"'").replace("…", "").replace("...", "")).strip()
            if len(ev_f) < 2:
                continue
            idx = folded.find(ev_f)
            if idx < 0:
                continue
            codes.add(code)
            flags.append({"code": code, "evidence": text[idx: idx + len(ev_f)]})
        out_msgs.append({"n": n, "flags": flags})
    for n in by_n:
        if n not in seen:
            out_msgs.append({"n": n, "flags": []})
    out_msgs.sort(key=lambda x: x["n"])
    st = parsed.get("scam_type")
    if st not in SCAM_TYPES:
        st = "OTHER"

    def _s(v):
        return v.strip() if isinstance(v, str) and v.strip() and v.strip().lower() not in ("null", "none") else None

    return {
        "per_message": out_msgs,
        "scam_type": st,
        "claimed_org": _s(parsed.get("claimed_org")),
        "person_name": _s(parsed.get("person_name")),
    }


def _parse_json(content: str):
    """Strip reasoning text (<think>...</think>) and code fences, then parse the JSON object."""
    content = re.sub(r"<think>.*?</think>", "", content or "", flags=re.S)
    content = re.sub(r"^.*?</think>", "", content, flags=re.S)   # unterminated opening tag
    start, end = content.find("{"), content.rfind("}")
    if start < 0 or end < start:
        return None
    return json.loads(content[start:end + 1])


_TL = threading.local()
_HEALTH = {"ok_at": 0.0, "fail": False, "ping_at": 0.0, "ping_ok": False}
RETRIES = 2            # a failed call is retried twice before the caller falls back to rules
RETRY_PAUSE_S = 1.0


def last_status() -> str:
    """Outcome of the last analyze() call in this thread: ok | unavailable | invalid_output | skipped."""
    return getattr(_TL, "status", "skipped")


def _post(body: dict):
    # short connect timeout: with LM Studio down, each attempt must fail fast instead of hanging on the socket
    r = httpx.post(_base_url() + "/v1/chat/completions", json=body, timeout=httpx.Timeout(TIMEOUT_S, connect=1.0))
    if r.status_code != 200:
        raise RuntimeError("http " + str(r.status_code))
    return r.json()


def _call_with_retry(body: dict, msgs: list):
    """Prime + real call, retried. Returns (validated dict | None, status)."""
    status = "unavailable"
    # if the model was already found dead in the last minute, probe once instead of waiting through every retry again
    tries = 1 if (_HEALTH["fail"] and time.time() - _HEALTH["ok_at"] < 60) else RETRIES + 1
    for attempt in range(tries):
        if attempt:
            time.sleep(RETRY_PAUSE_S * attempt)
        try:
            # LM Studio reuses the cached prompt prefix of the previous request, and a cache hit changes the numerics
            # of the first generated tokens (same seed, temperature 0, different output). Send the identical prompt
            # once with max_tokens=1 so the real call always starts from a fully cached prompt, whatever came before.
            _post(dict(body, max_tokens=1))
            content = _post(body)["choices"][0]["message"]["content"]
        except Exception:
            status = "unavailable"
            continue
        try:
            out = _validate(_parse_json(content), msgs)
        except Exception:
            out = None
        if out is not None:
            return out, "ok"
        status = "invalid_output"
    return None, status


def healthy() -> bool:
    """True only if the model really answers (not merely that the server lists it)."""
    now = time.time()
    if not available():
        return False
    # a successful analysis a moment ago is the best proof, and a busy single slot cannot answer a ping anyway
    if _HEALTH["ok_at"] and not _HEALTH["fail"] and now - _HEALTH["ok_at"] < 20:
        return True
    if now - _HEALTH["ping_at"] < 5:
        return _HEALTH["ping_ok"]
    ok = False
    try:
        r = httpx.post(_base_url() + "/v1/chat/completions", timeout=12.0, json={
            "model": _model(), "messages": [{"role": "user", "content": "ok"}], "max_tokens": 1, "temperature": 0})
        ok = r.status_code == 200
    except Exception:
        ok = False
    _HEALTH.update(ping_at=time.time(), ping_ok=ok)
    return ok


def analyze(scenario: dict):
    """One LLM call per scenario (plus retries). Returns validated dict or None on any failure; see last_status()."""
    _TL.status = "skipped"
    try:
        if not isinstance(scenario, dict):
            return None
        msgs = _clean_messages(scenario)
        if not any(m["from"] == "sender" for m in msgs):
            return None
        body = {
            "model": _model(),
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _build_user_prompt(scenario, msgs)},
            ],
            "temperature": 0,
            "top_p": 1,
            "top_k": 1,
            "seed": 42,
            "max_tokens": MAX_TOKENS,
            "stream": False,
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "scam_analysis", "strict": True, "schema": _schema()},
            },
        }
        out, status = _call_with_retry(body, msgs)
        _TL.status = status
        _HEALTH.update(ok_at=time.time(), fail=(out is None))   # ok_at = time of the last finished attempt series
        return out
    except Exception:
        _TL.status = "unavailable"
        _HEALTH.update(ok_at=time.time(), fail=True)
        return None
