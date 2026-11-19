"""2nd Eye mail watcher: Gmail over IMAP (app password), analysed by the local detector API.

Mail goes from Google straight to this laptop (imap.gmail.com:993, TLS); the analysis is done by the local API
(default http://localhost:8000). Nothing is sent anywhere else.

    .venv\\Scripts\\python.exe integrations\\mail\\mail_watcher.py            # last 7 days, then every 30 s
    .venv\\Scripts\\python.exe integrations\\mail\\mail_watcher.py --no-llm   # rules only (use_llm=false)

Credentials come from .env in the project root: GMAIL_ADDRESS and GMAIL_APP_PASSWORD.
Read-only: mailboxes are opened with EXAMINE and bodies fetched with BODY.PEEK, so nothing is marked as read.
Privacy: mail content is kept in memory only while a thread is analysed; it is never written to disk, printed or
logged. Console lines are service, verdict, score and a short hash. Alerts (verdict, score, sender, the Romanian
warning) are served on http://127.0.0.1:8011 and /alerts.json in the same shape as the WhatsApp watcher (8010).
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import email
import email.policy
import email.utils
import hashlib
import html
import html.parser
import http.server
import imaplib
import json
import os
import re
import sys
import threading
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
ENV_FILE = ROOT / ".env"
TRUSTED_FILE = HERE / "trusted.txt"          # one address per line (git-ignored)
SERVICE = "gmail"
IMAP_HOST, IMAP_PORT = "imap.gmail.com", 993
MAX_CHARS = 2000            # per message
MAX_MSGS = 30               # per thread (latest kept)
FETCH_BYTES = 1_500_000     # partial fetch: text parts come before big attachments

HELP_RO = """\
Lipsesc datele de acces Gmail. Creați o parolă de aplicație (o singură dată):
  1. Deschideți Contul Google (myaccount.google.com) -> Securitate.
  2. Activați Verificarea în doi pași (2-Step Verification), dacă nu este deja activă.
  3. Deschideți https://myaccount.google.com/apppasswords , scrieți un nume (de ex. 2nd Eye) și apăsați Creați.
  4. Copiați cele 16 caractere afișate.
  5. În fișierul .env din dosarul proiectului scrieți:
       GMAIL_ADDRESS=adresa@gmail.com
       GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx
"""
HELP_EN = """\
Gmail credentials are missing. Create an app password (once):
  1. Open your Google Account (myaccount.google.com) -> Security.
  2. Turn on 2-Step Verification if it is not on yet.
  3. Open https://myaccount.google.com/apppasswords , type a name (e.g. 2nd Eye) and press Create.
  4. Copy the 16 characters shown.
  5. In the .env file in the project folder write:
       GMAIL_ADDRESS=address@gmail.com
       GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx
"""


def say(line: str) -> None:
    print(line, flush=True)


def short(s: str) -> str:
    return hashlib.sha1(str(s).encode("utf-8")).hexdigest()[:8]


# ------------------------------------------------------------------ credentials
def load_env(path: Path = ENV_FILE) -> dict:
    out: dict = {}
    try:
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            if k.startswith("export "):
                k = k[7:].strip()
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            out[k] = v
    except Exception:
        pass
    return out


def credentials() -> tuple[str, str] | None:
    env = load_env()
    addr = (os.environ.get("GMAIL_ADDRESS") or env.get("GMAIL_ADDRESS") or "").strip()
    pw = (os.environ.get("GMAIL_APP_PASSWORD") or env.get("GMAIL_APP_PASSWORD") or "").replace(" ", "").strip()
    if "@" not in addr or len(pw) < 16:
        return None
    return addr, pw


# ------------------------------------------------------------------ text extraction
class _HTMLText(html.parser.HTMLParser):
    BLOCK = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "section", "article",
             "header", "footer", "ul", "ol", "hr", "pre"}
    SKIP = {"script", "style", "head", "title", "blockquote", "noscript"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.skip += 1
        elif tag in self.BLOCK:
            self.parts.append("\n")
        if tag == "div" and not self.skip:
            cls = dict(attrs).get("class") or ""
            if "gmail_quote" in cls and "gmail_attr" not in cls:
                self.parts.append("\n")

    def handle_startendtag(self, tag, attrs):
        if tag in ("br", "hr") and not self.skip:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP:
            self.skip = max(0, self.skip - 1)
        elif tag in self.BLOCK:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def html_to_text(src: str) -> str:
    p = _HTMLText()
    try:
        p.feed(src)
        p.close()
    except Exception:
        pass
    text = "".join(p.parts).replace("\xa0", " ")
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


_ATTR_START = re.compile(r"^\s*(on|în|in|pe|le|am|el|il)\b", re.I)
_ATTR_END = re.compile(r"(wrote|a scris|écrit|schrieb|escribió|ha scritto)\s*:\s*$", re.I)
_CUT_LINE = re.compile(r"^\s*(-{2,}\s*(original message|mesaj original|mesajul original)\s*-{2,}|_{10,})\s*$", re.I)
_OUTLOOK_FROM = re.compile(r"^\s*\**\s*(from|de la|de)\s*:\**\s", re.I)
_OUTLOOK_SENT = re.compile(r"^\s*\**\s*(sent|trimis|date|data)\s*:\**\s", re.I)
_SIG = re.compile(r"^\s*--\s*$")
_MOBILE = re.compile(r"^\s*(sent from my|trimis de pe|trimis de pe dispozitivul|get outlook for|obțineți outlook)\b", re.I)


def clean_body(text: str) -> str:
    """Drop quoted earlier replies, '>' lines, signatures and phone footers. Keeps forwarded content."""
    lines = (text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        ln = lines[i]
        if _ATTR_START.match(ln):
            joined = ln
            hit = bool(_ATTR_END.search(joined))
            j = i
            while not hit and j < i + 3 and j + 1 < len(lines):
                j += 1
                joined += " " + lines[j]
                hit = bool(_ATTR_END.search(joined))
            if hit:
                break
        if _CUT_LINE.match(ln) or _SIG.match(ln):
            break
        if _OUTLOOK_FROM.match(ln) and any(_OUTLOOK_SENT.match(x) for x in lines[i + 1:i + 4]) \
                and not any("forward" in x.lower() or "redirecționat" in x.lower() for x in lines[max(0, i - 2):i]):
            break
        if ln.lstrip().startswith(">") or _MOBILE.match(ln):
            i += 1
            continue
        out.append(ln.rstrip())
        i += 1
    body = re.sub(r"\n{3,}", "\n\n", "\n".join(out)).strip()
    return body


def _part_text(part) -> str:
    try:
        return part.get_content()
    except Exception:
        try:
            raw = part.get_payload(decode=True) or b""
            return raw.decode(part.get_content_charset() or "utf-8", errors="replace")
        except Exception:
            return ""


def body_text(msg) -> str:
    plain, htm = [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        if part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain":
            plain.append(_part_text(part))
        elif ctype == "text/html":
            htm.append(_part_text(part))
    if any(p.strip() for p in plain):
        return "\n".join(plain)
    return "\n".join(html_to_text(h) for h in htm)


def cap(text: str, n: int = MAX_CHARS) -> str:
    text = text.strip()
    if len(text) <= n:
        return text
    cut = text[:n]
    sp = cut.rfind(" ")
    return (cut[:sp] if sp > n * 0.8 else cut).rstrip() + " …"


def _addr(s: str) -> str:
    return (s or "").strip().strip("<>").lower()


def parse_message(raw: bytes, own: set[str], from_sent: bool = False, thrid: str | None = None) -> dict:
    """One RFC 822 message -> {thrid, msgid, date, from_name, from_addr, subject, text, mine}. Memory only."""
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    try:
        name, addr = email.utils.parseaddr(str(msg.get("From") or ""))
    except Exception:
        name, addr = "", ""
    addr = _addr(addr)
    try:
        subject = str(msg.get("Subject") or "")
    except Exception:
        subject = ""
    subject = re.sub(r"\s+", " ", subject).strip()
    try:
        date = email.utils.parsedate_to_datetime(str(msg.get("Date")))
        if date.tzinfo is None:
            date = date.replace(tzinfo=dt.timezone.utc)
    except Exception:
        date = None
    try:
        body = clean_body(body_text(msg))
    except Exception:
        body = ""
    mid = str(msg.get("Message-ID") or "").strip() or hashlib.sha1(raw[:4096]).hexdigest()
    return {"thrid": thrid, "msgid": mid, "date": date, "from_name": name.strip().strip('"'), "from_addr": addr,
            "subject": subject, "text": body, "mine": from_sent or addr in own}


# ------------------------------------------------------------------ threads -> scenario
_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)


def group_threads(items: list[dict]) -> dict:
    """thread id -> messages in date order, duplicates (same Message-ID) removed (a Sent copy wins)."""
    out: dict = collections.OrderedDict()
    for it in items:
        lst = out.setdefault(it.get("thrid"), [])
        same = next((x for x in lst if x["msgid"] == it["msgid"]), None)
        if same is None:
            lst.append(it)
        elif it["mine"] and not same["mine"]:
            lst[lst.index(same)] = it
    for k in out:
        out[k].sort(key=lambda m: m["date"] or _EPOCH)
    return out


def other_parties(msgs: list[dict]) -> list[dict]:
    seen, out = set(), []
    for m in msgs:
        if not m["mine"] and m["from_addr"] and m["from_addr"] not in seen:
            seen.add(m["from_addr"])
            out.append({"name": m["from_name"], "address": m["from_addr"]})
    return out


def build_scenario(msgs: list[dict], known: bool, sid: str) -> dict | None:
    """Thread (date order) -> standard scenario. Subject goes on the first message. None if nothing to analyse."""
    parties = other_parties(msgs)
    if not parties:
        return None                       # only her own mail
    rows = []
    for i, m in enumerate(msgs):
        text = m["text"]
        if i == 0 and m["subject"]:
            text = (m["subject"] + "\n" + text).strip()
        text = cap(text)
        if text:
            rows.append(("reader" if m["mine"] else "sender", text))
    rows = rows[-MAX_MSGS:]
    if not any(f == "sender" for f, _ in rows):
        return None                       # no-content system mail
    s = parties[0]
    sender = {"name": s["name"] or s["address"], "address": s["address"], "known_contact": known}
    return {"id": sid, "channel": "email", "known_contact": known, "sender": sender, "live_stranger": not known,
            "messages": [{"n": i + 1, "from": f, "text": t} for i, (f, t) in enumerate(rows)]}


# ------------------------------------------------------------------ trust circle
def load_trusted(path: Path = TRUSTED_FILE) -> set[str]:
    try:
        return {_addr(x) for x in path.read_text(encoding="utf-8-sig").splitlines()
                if "@" in x and not x.strip().startswith("#")}
    except Exception:
        return set()


class Trust:
    """Known = she has ever mailed that address (Sent folder, looked up once per address) or it is in trusted.txt."""

    def __init__(self, sent_lookup, trusted: set[str] | None = None) -> None:
        self.lookup = sent_lookup
        self.trusted = load_trusted() if trusted is None else trusted
        self.cache: dict[str, bool] = {}

    def known(self, address: str) -> bool:
        a = _addr(address)
        if not a:
            return False
        if a in self.trusted:
            return True
        if a not in self.cache:
            try:
                self.cache[a] = bool(self.lookup(a))
            except Exception:
                return False                # not cached: retried next time
        return self.cache[a]

    def all_known(self, parties: list[dict]) -> bool:
        return bool(parties) and all(self.known(p["address"]) for p in parties)


# ------------------------------------------------------------------ alerts (memory only; same JSON as watcher.py)
VERDICT_UI = {
    "SUSPICIOUS": ("⚠", "Atenție, verificați înainte să răspundeți", "#ffb300", "#1a1a1a"),
    "SCAM": ("✖", "Pare o țeapă! Nu răspundeți", "#b71c1c", "#ffffff"),
}
ORDER = {"SCAM": 0, "SUSPICIOUS": 1, "SAFE": 2}


class Conversations:
    """Last analysed threads WITH the full API result, for the local web UI. Memory only: never on disk,
    never printed. One entry per thread, replaced on re-analysis; served only on 127.0.0.1."""

    def __init__(self, keep: int = 40) -> None:
        self.items: "collections.OrderedDict[str, dict]" = collections.OrderedDict()
        self.keep = keep
        self.lock = threading.Lock()

    def add(self, cid: str, service: str, sender: str, result: dict, quiet: bool = False) -> None:
        with self.lock:
            self.items.pop(cid, None)
            self.items[cid] = {"id": cid, "service": service, "sender": sender,
                               "time": time.strftime("%Y-%m-%dT%H:%M:%S"), "result": result, "quiet": quiet}
            while len(self.items) > self.keep:
                self.items.popitem(last=False)

    def feed(self) -> dict:
        with self.lock:
            return {"conversations": list(reversed(self.items.values()))}

    def clear(self) -> None:
        with self.lock:
            self.items.clear()


class Alerts:
    def __init__(self, keep: int = 100) -> None:
        self.items: "collections.OrderedDict[str, dict]" = collections.OrderedDict()
        self.keep = keep
        self.lock = threading.Lock()
        self.started = time.strftime("%H:%M:%S")
        self.checked = 0
        self.conv = Conversations()

    def add(self, thread_key: str, sender: str, verdict: str, score, warning: str, label: str, state: str,
            when: str | None = None, red_flags=None, scam_type=None) -> None:
        """when = local ISO time of the newest mail in the thread, so the notifier does not replay old mail."""
        aid = hashlib.sha1("|".join([SERVICE, thread_key, verdict, state]).encode("utf-8")).hexdigest()[:16]
        with self.lock:
            if thread_key not in self.items:
                self.checked += 1
            self.items.pop(thread_key, None)
            self.items[thread_key] = {"service": SERVICE, "sender": sender, "verdict": verdict, "score": score,
                                      "warning": warning, "label": label, "time": time.strftime("%H:%M:%S"),
                                      "id": aid, "iso": when or time.strftime("%Y-%m-%dT%H:%M:%S"),
                                      "red_flags": list(red_flags or []), "scam_type": scam_type}
            while len(self.items) > self.keep:
                self.items.popitem(last=False)

    def feed(self) -> dict:
        return {"alerts": [{"id": a["id"], "time": a["iso"], "service": a["service"], "sender": a["sender"],
                            "verdict": a["verdict"], "risk_score": a["score"], "label_ro": a["label"],
                            "warning_ro": a["warning"], "red_flags": a.get("red_flags") or [],
                            "scam_type": a.get("scam_type")} for a in self.snapshot()]}

    def snapshot(self) -> list[dict]:
        with self.lock:
            return list(reversed(self.items.values()))


def render_status(alerts: Alerts, info: dict) -> str:
    items = alerts.snapshot()
    bad = sorted([a for a in items if a["verdict"] in VERDICT_UI], key=lambda a: ORDER.get(a["verdict"], 1))
    e = html.escape
    out = ["<!doctype html><html lang='ro'><head><meta charset='utf-8'><meta http-equiv='refresh' content='10'>"
           "<meta name='viewport' content='width=device-width,initial-scale=1'><title>2nd Eye - Gmail</title>"
           "<style>body{font:22px/1.4 Segoe UI,Arial,sans-serif;margin:0;background:#f4f4f4;color:#111}"
           "header{background:#1a237e;color:#fff;padding:16px 24px}h1{margin:0;font-size:30px}"
           "main{padding:16px 24px;max-width:1000px}"
           ".card{border-radius:14px;padding:16px 20px;margin:0 0 16px;display:flex;gap:18px;align-items:flex-start}"
           ".ic{font-size:48px;font-weight:700;line-height:1}.lb{font-size:28px;font-weight:800}.mt{font-size:18px;opacity:.9;margin-top:4px}"
           ".none{background:#2e7d32;color:#fff}.small{font-size:18px;color:#444}</style></head><body>"
           "<header><h1>\U0001F6E1 2nd Eye – Gmail</h1>"
           f"<div style='font-size:18px'>Pornit la {e(alerts.started)} · {e(info.get('state', ''))} · se actualizează singur</div>"
           "</header><main>"]
    if not bad:
        out.append("<div class='card none'><div class='ic'>✔</div><div><div class='lb'>Nicio alertă</div>"
                   "<div class='mt'>Nu am găsit e-mailuri periculoase.</div></div></div>")
    for a in bad:
        icon, label, bg, fg = VERDICT_UI[a["verdict"]]
        out.append(f"<div class='card' style='background:{bg};color:{fg}'><div class='ic'>{icon}</div><div>"
                   f"<div class='lb'>{e(label)}</div><div>{e(a['warning'] or '')}</div>"
                   f"<div class='mt'>Gmail · {e(a['sender'])} · scor {e(str(a['score']))} · {e(a['time'])}</div></div></div>")
    out.append(f"<p class='small'>Conversații verificate: {alerts.checked}. Textul e-mailurilor nu este salvat.</p>")
    out.append("</main></body></html>")
    return "".join(out)


def start_status_server(alerts: Alerts, info: dict, port: int):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a, **k):
            pass

        def _clear(self):
            alerts.conv.clear()
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_DELETE(self):
            if self.path.startswith("/conversations"):
                return self._clear()
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):
            if self.path.startswith("/conversations/clear"):
                return self._clear()
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):
            if self.path.startswith("/conversations.json"):
                body = json.dumps(alerts.conv.feed(), ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path.startswith("/alerts.json"):
                if not info.get("ready", True):     # start-up scan still running: notifier keeps waiting
                    self.send_response(503)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = json.dumps(alerts.feed(), ensure_ascii=False).encode("utf-8")
                ctype = "application/json; charset=utf-8"
            else:
                body = render_status(alerts, info).encode("utf-8")
                ctype = "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ------------------------------------------------------------------ local API
def post_json(url: str, body: dict, timeout: float = 120) -> dict | None:
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None


def newest_local_iso(msgs: list[dict]) -> str | None:
    dates = [m["date"] for m in msgs if m.get("date")]
    if not dates:
        return None
    d = min(max(dates), dt.datetime.now(dt.timezone.utc))
    return d.astimezone().strftime("%Y-%m-%dT%H:%M:%S")


def analyze_url(api: str, known: bool, use_llm: bool) -> str:
    q = []
    if known:
        q.append("trust_gate=true")
    if not use_llm:
        q.append("use_llm=false")
    return api.rstrip("/").replace("//localhost", "//127.0.0.1") + "/api/analyze" + ("?" + "&".join(q) if q else "")


class Analyzer:
    """Thread messages -> scenario -> API -> alert. Results in memory only."""

    def __init__(self, api: str, use_llm: bool, alerts: Alerts, trust: Trust) -> None:
        self.api, self.use_llm, self.alerts, self.trust = api, use_llm, alerts, trust
        self.cache: "collections.OrderedDict[str, dict]" = collections.OrderedDict()
        self.api_down = False

    def run(self, thread_key: str, msgs: list[dict]) -> str:
        """Returns 'ok', 'skip' or 'retry' (API not reachable)."""
        parties = other_parties(msgs)
        if not parties:
            return "skip"
        known = self.trust.all_known(parties)
        sc = build_scenario(msgs, known, "gmail-" + short(thread_key))
        if sc is None:
            return "skip"
        url = analyze_url(self.api, known, self.use_llm)
        key = hashlib.sha1(json.dumps([url, sc], sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
        raw = self.cache.get(key)
        if raw is None:
            raw = post_json(url, sc)
            if not isinstance(raw, dict) or "verdict" not in raw:
                if not self.api_down:
                    say(f"[{SERVICE}] detector API not reachable at {self.api} - will retry")
                self.api_down = True
                return "retry"
            self.api_down = False
            self.cache[key] = raw
            while len(self.cache) > 500:
                self.cache.popitem(last=False)
        res = {k: raw.get(k) for k in ("verdict", "risk_score", "first_alert", "label", "warning", "red_flags")}
        flags = [f.replace("RF_", "") for f in (res.get("red_flags") or [])]
        # Live e-mail is not the challenge's fictional world: almost every real newsletter has links and a
        # company name that are not on the 5-entry official catalog, so link + company name alone scores 25-40.
        # For the live watcher we therefore warn only when the mail ASKS her for something (money, a code,
        # card or personal data, remote access). The detector's verdict itself is unchanged; files, pasted
        # text and the dashboard are scored exactly as before.
        asks = {"RF_DATA_REQUEST", "RF_CODE_REQUEST", "RF_PAYMENT_REQUEST", "RF_REMOTE_ACCESS"}
        quiet = res.get("verdict") in ("SUSPICIOUS", "SCAM") and not (asks & set(res.get("red_flags") or []))
        say(f"[{SERVICE}] {res.get('verdict')} {res.get('risk_score')} #{short(thread_key)}"
            + (" (known)" if known else "") + (" " + ",".join(flags) if flags else "")
            + (" (quiet: nothing is asked)" if quiet else ""))
        who = sc["sender"].get("name") or sc["sender"].get("address") or "necunoscut"
        self.alerts.conv.add(short(thread_key), SERVICE, str(who)[:60], raw, quiet)
        if quiet:
            return "ok"
        self.alerts.add(thread_key, str(who)[:60], str(res.get("verdict")), res.get("risk_score"),
                        str((res.get("warning") or {}).get("ro") or ""), str((res.get("label") or {}).get("ro") or ""),
                        key, newest_local_iso(msgs), raw.get("red_flags"), raw.get("scam_type"))
        return "ok"


# ------------------------------------------------------------------ IMAP (read-only)
class LoginError(Exception):
    pass


_LIST_RE = re.compile(rb'^\((?P<flags>[^)]*)\)\s+(?P<delim>"[^"]*"|NIL)\s+(?P<name>.+)$')


class Gmail:
    def __init__(self, address: str, password: str) -> None:
        self.address = address
        self._pw = password
        self.M: imaplib.IMAP4_SSL | None = None
        self.cur: str | None = None
        self.sent: str | None = None

    def connect(self) -> None:
        self.close()
        M = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, timeout=60)
        try:
            M.login(self.address, self._pw)
        except imaplib.IMAP4.error:
            try:
                M.logout()
            except Exception:
                pass
            raise LoginError()
        self.M, self.cur = M, None
        self.sent = self._find_sent()

    def close(self) -> None:
        if self.M is not None:
            try:
                self.M.logout()
            except Exception:
                pass
        self.M, self.cur = None, None

    def _find_sent(self) -> str | None:
        typ, data = self.M.list()
        if typ != "OK":
            return None
        for line in data or []:
            if not isinstance(line, bytes):
                continue
            m = _LIST_RE.match(line.strip())
            if m and b"\\sent" in m.group("flags").lower():
                name = m.group("name").decode("ascii", "replace").strip()
                return name if name.startswith('"') else '"' + name + '"'
        return '"[Gmail]/Sent Mail"'

    def select(self, folder: str, force: bool = False) -> None:
        if force or self.cur != folder:
            typ, _ = self.M.select(folder, readonly=True)          # EXAMINE: never changes flags
            if typ != "OK":
                raise imaplib.IMAP4.error("select failed")
            self.cur = folder

    def search(self, folder: str, *criteria: str, force: bool = False) -> list[int]:
        self.select(folder, force)
        typ, data = self.M.uid("SEARCH", *criteria)
        if typ != "OK" or not data or not data[0]:
            return []
        return sorted(int(x) for x in data[0].split())

    def thread_ids(self, folder: str, uids: list[int]) -> dict[int, str]:
        self.select(folder)
        out: dict[int, str] = {}
        for i in range(0, len(uids), 200):
            chunk = ",".join(str(u) for u in uids[i:i + 200])
            typ, data = self.M.uid("FETCH", chunk, "(X-GM-THRID)")
            if typ != "OK":
                continue
            for item in data or []:
                line = item[0] if isinstance(item, tuple) else item
                if not isinstance(line, bytes):
                    continue
                u = re.search(rb"UID (\d+)", line)
                t = re.search(rb"X-GM-THRID (\d+)", line)
                if u and t:
                    out[int(u.group(1))] = t.group(1).decode()
        return out

    def fetch_raw(self, folder: str, uid: int) -> bytes | None:
        self.select(folder)
        typ, data = self.M.uid("FETCH", str(uid), f"(BODY.PEEK[]<0.{FETCH_BYTES}>)")
        if typ != "OK":
            return None
        for item in data or []:
            if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], bytes):
                return item[1]
        return None

    def thread_messages(self, thrid: str, inbox_days: int | None = None) -> list[dict]:
        own = {self.address.lower()}
        items = []
        for folder, mine in (("INBOX", False), (self.sent, True)):
            if not folder:
                continue
            try:
                uids = self.search(folder, "X-GM-THRID", thrid)
            except imaplib.IMAP4.error:
                continue
            for uid in uids[-MAX_MSGS:]:
                raw = self.fetch_raw(folder, uid)
                if raw:
                    items.append(parse_message(raw, own, from_sent=mine, thrid=thrid))
        return group_threads(items).get(thrid, [])

    def sent_to(self, address: str) -> bool:
        if not self.sent or re.search(r'["\\\s]', address):
            return False
        cur = self.cur
        hit = bool(self.search(self.sent, "OR", "TO", f'"{address}"', "CC", f'"{address}"'))
        if cur and cur != self.cur:
            self.select(cur)
        return hit


def imap_date(days: int) -> str:
    d = dt.date.today() - dt.timedelta(days=max(0, days))
    return f"{d.day:02d}-{('Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split())[d.month - 1]}-{d.year}"


# ------------------------------------------------------------------ main loop
def run(a, address: str, password: str) -> None:
    alerts = Alerts()
    info = {"state": "pornire", "ready": False}
    srv = start_status_server(alerts, info, a.status_port)
    say(f"Status page: http://127.0.0.1:{a.status_port}  (alerts: /alerts.json)")
    g = Gmail(address, password)
    trust = Trust(g.sent_to)
    an = Analyzer(a.api, not a.no_llm, alerts, trust)
    last_inbox = last_sent = 0
    validity = None
    pending: set[str] = set()        # thread ids waiting to be (re)analysed
    tracked: set[str] = set()        # threads with at least one INBOX message seen
    backoff = 5
    first = True
    try:
        while True:
            try:
                if g.M is None:
                    g.connect()
                    say(f"[{SERVICE}] connected (read-only), sent folder found: {'yes' if g.sent else 'no'}")
                    backoff = 5
                g.select("INBOX", force=True)
                v = g.M.untagged_responses.get("UIDVALIDITY", [None])[0]
                if v != validity:                      # first run or mailbox reset: start over
                    validity = v
                    if not first:
                        last_inbox = last_sent = 0
                if first or last_inbox == 0:
                    uids = g.search("INBOX", "SINCE", imap_date(a.days))
                    if a.max_threads and len(uids) > a.max_threads * 3:
                        uids = uids[-a.max_threads * 3:]
                    sent_now = g.search(g.sent, "ALL") if g.sent else []
                    last_sent = sent_now[-1] if sent_now else 0
                    all_inbox = g.search("INBOX", "ALL")
                    last_inbox = all_inbox[-1] if all_inbox else 0
                    th = g.thread_ids("INBOX", uids)
                    order = []                          # newest thread first
                    for u in sorted(th, reverse=True):
                        if th[u] not in order:
                            order.append(th[u])
                    if a.max_threads:
                        order = order[:a.max_threads]
                    tracked.update(order)
                    pending.update(order)
                    say(f"[{SERVICE}] start: {len(uids)} messages from the last {a.days} days in {len(order)} threads")
                    queue = order
                else:
                    new = [u for u in g.search("INBOX", "UID", f"{last_inbox + 1}:*") if u > last_inbox]
                    if new:
                        last_inbox = max(new)
                        th = g.thread_ids("INBOX", new)
                        tracked.update(th.values())
                        pending.update(th.values())
                    if g.sent:
                        snew = [u for u in g.search(g.sent, "UID", f"{last_sent + 1}:*", force=True) if u > last_sent]
                        if snew:
                            last_sent = max(snew)
                            for t in g.thread_ids(g.sent, snew).values():
                                if t in tracked:            # her reply in a thread we watch: re-check it
                                    pending.add(t)
                    queue = sorted(pending, key=lambda t: int(t), reverse=True)
                first = False
                # alerts may flow while the start-up scan runs (newest thread first); old mail is still not
                # replayed because each alert carries the date of its newest mail and the notifier skips old ones
                info["ready"] = True
                info["state"] = f"conectat · verific la {a.interval} s"
                for t in queue:
                    if t not in pending:
                        continue
                    msgs = g.thread_messages(t)
                    r = an.run(t, msgs)
                    del msgs
                    if r != "retry":
                        pending.discard(t)
                info["ready"] = True
                if a.once:
                    break
            except LoginError:
                say("Gmail login refused / autentificare refuzată: check GMAIL_ADDRESS and the app password in .env "
                    "(IMAP may also be disabled by a Workspace admin).")
                say(HELP_EN)
                raise SystemExit(2)
            except (imaplib.IMAP4.abort, imaplib.IMAP4.error, OSError, EOFError) as e:
                info["state"] = "fără conexiune, reîncerc"
                say(f"[{SERVICE}] connection problem ({type(e).__name__}), retrying in {backoff} s")
                g.close()
                if a.once:
                    break
                time.sleep(backoff)
                backoff = min(backoff * 2, 300)
                continue
            time.sleep(a.interval)
    finally:
        g.close()
        srv.shutdown()


def main() -> None:
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="2nd Eye mail watcher (Gmail over IMAP, read-only)")
    ap.add_argument("--days", type=int, default=7, help="look at INBOX mail from the last N days on start (default 7)")
    ap.add_argument("--interval", type=int, default=30, help="seconds between checks for new mail (default 30)")
    ap.add_argument("--api", default="http://localhost:8000", help="detector API base URL")
    ap.add_argument("--no-llm", action="store_true", help="call the API with use_llm=false (rules only)")
    ap.add_argument("--status-port", type=int, default=8011, help="local status page port (default 8011)")
    ap.add_argument("--max-threads", type=int, default=150, help="at most this many threads on start (newest first)")
    ap.add_argument("--once", action="store_true", help="check once and exit (test)")
    a = ap.parse_args()
    cred = credentials()
    if cred is None:
        say(HELP_RO)
        say(HELP_EN)
        sys.exit(1)
    try:
        run(a, *cred)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
