"""2nd Eye watcher: one Chromium instance, one injected reader per messaging service.

Modes
  default        background: Chromium in new headless mode (no window), same persistent profile, chat lists are polled
  --login        visible window so a relative can sign in once; exits when the window is closed (no analysis)
  --show         visible window with the in-page warning banner (demo)
  --hidden-window  background, but as a real window parked off-screen (fallback if a site refuses headless)

Readers (readers/*.js) hand text to this process through exposed bindings (page CSP blocks calls to localhost);
this process asks the local detector API and keeps the latest alerts IN MEMORY ONLY for a status page on
http://127.0.0.1:8010. Message text is only sent to the local API: never printed, logged, stored or served.
Console output is service name, verdict and score only.
"""
from __future__ import annotations

import argparse
import asyncio
import collections
import functools
import hashlib
import html
import http.server
import json
import re
import socketserver
import sys
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
READERS = HERE / "readers"
DEMO = HERE / "demo"
PROFILE = HERE / ".profile"
TRUSTED = HERE / "trusted.json"          # identifiers only, never message text (git-ignored)

BROWSERS = ["chrome", "msedge", "chromium"]
LAUNCH_ARGS = ["--disable-blink-features=AutomationControlled", "--no-first-run", "--no-default-browser-check"]
LITE_ARGS = ["--disable-extensions", "--disable-background-networking", "--disable-sync", "--disable-gpu",
             "--renderer-process-limit=1", "--js-flags=--max-old-space-size=256"]


# ------------------------------------------------------------------ reader discovery (drop in a file = new service)
def discover() -> dict[str, str]:
    """service name -> start url, from the first line of each readers/*.js:  // @service name url"""
    found: dict[str, str] = {}
    for f in sorted(READERS.glob("*.js")):
        if f.name == "common.js":
            continue
        try:
            first = f.read_text(encoding="utf-8").splitlines()[0]
        except Exception:
            continue
        m = re.match(r"//\s*@service\s+(\S+)\s+(\S+)", first)
        if m:
            found[m.group(1)] = m.group(2)
    return found


def init_scripts(cfg: dict) -> list[str]:
    files = [READERS / "common.js"] + [f for f in sorted(READERS.glob("*.js")) if f.name != "common.js"]
    return ["window.__SB_CFG = " + json.dumps(cfg) + ";"] + [f.read_text(encoding="utf-8") for f in files]


# ------------------------------------------------------------------ trusted identifiers
def _norm(s: str | None) -> str:
    return re.sub(r"[\s().\-]+", "", (s or "").strip().lower())


def sender_keys(sender: dict) -> list[str]:
    return [k for k in (_norm(sender.get("address")), _norm(sender.get("name"))) if k]


class Trusted:
    def __init__(self) -> None:
        self.data: dict[str, list[str]] = {}
        try:
            d = json.loads(TRUSTED.read_text(encoding="utf-8"))
            if isinstance(d, dict):
                self.data = {str(k): [str(x) for x in v] for k, v in d.items() if isinstance(v, list)}
        except Exception:
            pass

    def has(self, service: str, sender: dict) -> bool:
        have = set(self.data.get(service, []))
        return any(k in have for k in sender_keys(sender))

    def add(self, service: str, sender: dict) -> None:
        keys = sender_keys(sender)
        if not keys:
            return
        cur = self.data.setdefault(service, [])
        if keys[0] not in cur:             # the address when there is one, else the name
            cur.append(keys[0])
        TRUSTED.write_text(json.dumps(self.data, indent=1), encoding="utf-8")


# ------------------------------------------------------------------ alerts (memory only, never message text)
VERDICT_UI = {
    "SAFE": ("✔", "Pare în regulă", "#2e7d32", "#ffffff"),
    "SUSPICIOUS": ("⚠", "Atenție, verificați înainte să răspundeți", "#ffb300", "#1a1a1a"),
    "SCAM": ("✖", "Pare o țeapă! Nu răspundeți", "#b71c1c", "#ffffff"),
}
ORDER = {"SCAM": 0, "SUSPICIOUS": 1, "SAFE": 2}


class Conversations:
    """Last analysed conversations WITH the full API result, for the local web UI. Memory only: never on disk,
    never printed. One entry per conversation, replaced on re-analysis; served only on 127.0.0.1."""

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
    def __init__(self, keep: int = 50) -> None:
        self.items: "collections.OrderedDict[tuple, dict]" = collections.OrderedDict()
        self.keep = keep
        self.lock = threading.Lock()
        self.started = time.strftime("%H:%M:%S")
        self.conv = Conversations()

    def add(self, service: str, sender: str, verdict: str, score, warning: str, label: str, state: str = "",
            red_flags=None, scam_type=None) -> None:
        # id = stable hash of service + sender + verdict + conversation state (a hash, never the text itself)
        aid = hashlib.sha1("|".join([service, sender, verdict, state]).encode("utf-8")).hexdigest()[:16]
        with self.lock:
            self.items.pop((service, sender), None)
            self.items[(service, sender)] = {"service": service, "sender": sender, "verdict": verdict, "score": score,
                                             "warning": warning, "label": label, "time": time.strftime("%H:%M:%S"),
                                             "id": aid, "iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
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


def render_status(alerts: Alerts, mode: str) -> str:
    items = alerts.snapshot()
    bad = sorted([a for a in items if a["verdict"] != "SAFE"], key=lambda a: ORDER.get(a["verdict"], 1))
    ok = [a for a in items if a["verdict"] == "SAFE"]
    e = html.escape
    out = ["<!doctype html><html lang='ro'><head><meta charset='utf-8'><meta http-equiv='refresh' content='5'>"
           "<meta name='viewport' content='width=device-width,initial-scale=1'><title>2nd Eye - stare</title>"
           "<style>body{font:22px/1.4 Segoe UI,Arial,sans-serif;margin:0;background:#f4f4f4;color:#111}"
           "header{background:#1a237e;color:#fff;padding:16px 24px}h1{margin:0;font-size:30px}"
           "main{padding:16px 24px;max-width:1000px}"
           ".card{border-radius:14px;padding:16px 20px;margin:0 0 16px;display:flex;gap:18px;align-items:flex-start}"
           ".ic{font-size:48px;font-weight:700;line-height:1}.lb{font-size:28px;font-weight:800}.mt{font-size:18px;opacity:.9;margin-top:4px}"
           ".none{background:#2e7d32;color:#fff}.small{font-size:18px;color:#444}</style></head><body>"
           "<header><h1>\U0001F6E1 2nd Eye – stare</h1>"
           f"<div style='font-size:18px'>Pornit la {e(alerts.started)} · mod: {e(mode)} · se actualizează singur</div></header><main>"]
    if not bad:
        out.append("<div class='card none'><div class='ic'>✔</div><div><div class='lb'>Nicio alertă</div>"
                   "<div class='mt'>Nu am găsit mesaje periculoase în mesajele necitite.</div></div></div>")
    for a in bad:
        icon, label, bg, fg = VERDICT_UI.get(a["verdict"], VERDICT_UI["SUSPICIOUS"])
        out.append(f"<div class='card' style='background:{bg};color:{fg}'><div class='ic'>{icon}</div><div>"
                   f"<div class='lb'>{e(label)}</div><div>{e(a['warning'] or '')}</div>"
                   f"<div class='mt'>{e(a['service'])} · {e(a['sender'])} · scor {e(str(a['score']))} · {e(a['time'])}</div></div></div>")
    if ok:
        out.append("<p class='small'>✔ Verificate, în regulă: " +
                   e(", ".join(f"{a['service']}: {a['sender']}" for a in ok[:12])) + "</p>")
    out.append("</main></body></html>")
    return "".join(out)


def start_status_server(alerts: Alerts, mode: str, port: int):
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
            if self.path.startswith("/alerts.json"):
                body = json.dumps(alerts.feed(), ensure_ascii=False).encode("utf-8")
                ctype = "application/json; charset=utf-8"
            elif self.path.startswith("/conversations.json"):
                body = json.dumps(alerts.conv.feed(), ensure_ascii=False).encode("utf-8")
                ctype = "application/json; charset=utf-8"
            else:
                body = render_status(alerts, mode).encode("utf-8")
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


# ------------------------------------------------------------------ local API call
def _post(url: str, body: dict) -> dict | None:
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None


class Bridge:
    def __init__(self, api: str, use_llm: bool, alerts: Alerts) -> None:
        self.api = api.rstrip("/").replace("//localhost", "//127.0.0.1")
        self.use_llm = use_llm
        self.alerts = alerts
        self.trusted = Trusted()
        self.last_line: dict[str, str] = {}
        self.cache: "collections.OrderedDict[str, dict]" = collections.OrderedDict()   # sha1 -> result, memory only

    async def analyze(self, source, payload) -> dict:
        try:
            service = str(payload["service"])
            sc = dict(payload["scenario"])
            sender = dict(sc.get("sender") or {})
            known = bool(sc.get("known_contact")) or self.trusted.has(service, sender)
            sender["known_contact"] = known
            sc.update({"id": service + "-watcher", "sender": sender, "known_contact": known})
            q = []
            if known:
                q.append("trust_gate=true")
            if not self.use_llm:
                q.append("use_llm=false")
            url = self.api + "/api/analyze" + ("?" + "&".join(q) if q else "")
            key = hashlib.sha1(json.dumps([url, sc], sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
            full = self.cache.get(key)
            if full is None:
                full = await asyncio.to_thread(_post, url, sc)
                if not isinstance(full, dict) or "verdict" not in full:
                    return {"ok": False}
                self.cache[key] = full
                while len(self.cache) > 300:
                    self.cache.popitem(last=False)
            res = {k: full.get(k) for k in ("verdict", "risk_score", "first_alert", "label", "warning")}
            line = f"[{service}] {res.get('verdict')} {res.get('risk_score')}"
            if self.last_line.get(service) != line:        # service, verdict, score only
                self.last_line[service] = line
                print(line, flush=True)
            who = sender.get("name") or sender.get("address") or "necunoscut"
            self.alerts.add(service, str(who)[:60], str(res.get("verdict")), res.get("risk_score"),
                            str((res.get("warning") or {}).get("ro") or ""), str((res.get("label") or {}).get("ro") or ""), key,
                            full.get("red_flags"), full.get("scam_type"))
            cid = hashlib.sha1((service + "|" + str(who)).encode("utf-8")).hexdigest()[:16]
            self.alerts.conv.add(cid, service, str(who)[:60], full)
            return {"ok": True, "known": known, "result": res}
        except Exception:
            return {"ok": False}

    async def input(self, source, payload) -> bool:
        """Real mouse / keyboard input for a reader: a click at page coordinates, or Escape. Nothing else."""
        try:
            page = source["page"]
            if payload.get("type") == "click":
                await page.mouse.click(float(payload["x"]), float(payload["y"]),
                                       button="right" if payload.get("button") == "right" else "left")
                return True
            if payload.get("type") == "key" and payload.get("key") == "Escape":
                await page.keyboard.press("Escape")
                return True
        except Exception:
            pass
        return False

    async def note(self, source, payload) -> bool:
        """Counts and yes/no only, printed so the open -> analyse -> restore flow can be checked."""
        try:
            yn = lambda v: "yes" if v else "no"
            print(f"[{payload.get('service')}] flow opened={yn(payload.get('opened'))} msgs={int(payload.get('msgs') or 0)} "
                  f"from_them={int(payload.get('incoming') or 0)} from_her={int(payload.get('outgoing') or 0)} "
                  f"direction_unknown={int(payload.get('unknownDir') or 0)} "
                  + ("dir_signals=" + ",".join(f"{k}:{int(v)}" for k, v in (payload.get("dirCounts") or {}).items()) + " "
                     if isinstance(payload.get("dirCounts"), dict) else "") +
                  f"was_unread={yn(payload.get('wasUnread'))} closed={yn(payload.get('closed'))} "
                  f"restored_unread={yn(payload.get('restored'))}", flush=True)
        except Exception:
            pass
        return True

    async def trust(self, source, payload) -> bool:
        try:
            self.trusted.add(str(payload["service"]), dict(payload.get("sender") or {}))
            print(f"[{payload['service']}] contact marcat ca cunoscut", flush=True)
            return True
        except Exception:
            return False


# ------------------------------------------------------------------ demo server
def start_demo_server() -> tuple[socketserver.TCPServer, int]:
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *a, **k):  # no access log
            pass

    handler = functools.partial(Quiet, directory=str(DEMO))
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


# ------------------------------------------------------------------ browser
async def launch(pw, order: list[str], demo: bool, mode: str, a):
    args = list(LAUNCH_ARGS)
    if a.lite:
        args += LITE_ARGS
    if mode == "background":
        args += ["--window-position=-32000,-32000", "--start-minimized"] if a.hidden_window else ["--headless=new"]
    elif a.minimized:
        args.append("--start-minimized")
    last = None
    for b in order:
        d = PROFILE / (b + ("-demo" if demo else ""))
        d.mkdir(parents=True, exist_ok=True)
        kw = dict(headless=False, no_viewport=True, args=args, ignore_default_args=["--enable-automation"])
        if b != "chromium":
            kw["channel"] = b
        try:
            ctx = await pw.chromium.launch_persistent_context(str(d), **kw)
            print(f"browser: {b} ({mode})", flush=True)
            return ctx
        except Exception as e:
            last = e
            print(f"browser {b} not available ({type(e).__name__})", flush=True)
    raise SystemExit(f"No browser could be started ({type(last).__name__}). Run: python -m playwright install chromium")


async def hide_headless_ua(ctx, page) -> None:
    """New headless Chrome announces itself as HeadlessChrome; present the normal user agent instead."""
    try:
        cdp = await ctx.new_cdp_session(page)
        ua = (await cdp.send("Browser.getVersion"))["userAgent"].replace("HeadlessChrome", "Chrome")
        await cdp.send("Emulation.setUserAgentOverride", {"userAgent": ua})
    except Exception:
        pass


async def block_heavy(route) -> None:
    if route.request.resource_type in ("image", "media", "font"):
        await route.abort()
    else:
        await route.continue_()


LOGIN_RE = re.compile(r"login|log_in|signin|sign_in|checkpoint|challenge|recaptcha|accounts\.google\.com|/auth|\bqr\b", re.I)


async def diag_line(name: str, page, errs: list, key: bool) -> str:
    """One counts-only line for a page. Booleans, numbers, error name@line; never any page text."""
    try:
        u = urllib.parse.urlparse(page.url)
        host = u.hostname or "-"
        login = bool(LOGIN_RE.search(host + u.path)) or bool(await page.evaluate(
            "!!document.querySelector('input[type=password]')"))
        d = await page.evaluate("window.__SB && window.__SB.diag ? window.__SB.diag() : null")
    except Exception as e:
        return f"[{name}] evaluate failed ({type(e).__name__})"
    parts = [f"[{name}]", f"host={host}", f"login_wall={'yes' if login else 'no'}",
             f"common_js={'yes' if d else 'NO'}"]
    if d:
        parts.append(f"booted={'yes' if d['booted'] else 'no'}")
        parts.append(f"reader={'yes' if d['reader'] else 'NO'}")
        if d["reader"]:
            parts.append(f"list(rows={d['rows']} unread={d['unread']} strangers={d['strangers']})")
            if d.get("wa"):
                w = d["wa"]
                parts.append(f"all_rows(items={w.get('items')} titled={w.get('titled')} with_preview={w.get('withPreview')})")
            parts.append(f"open(header={'yes' if d['header'] else 'no'} msgs={d['msgs']} in={d['incoming']} out={d['outgoing']} "
                         f"known={'-' if d['known'] is None else ('yes' if d['known'] else 'no')})")
        if d["errors"]:
            parts.append("reader_errors=" + ",".join(d["errors"]))
    if errs:
        parts.append("page_errors=" + ",".join(sorted(set(errs))[:6]))
    if key:
        try:
            await page.keyboard.press("Control+Shift+S")
            await asyncio.sleep(0.4)
            r = await page.evaluate("""() => { const b = document.getElementById('sb-diag'); if (!b) return [false, false];
                const r = b.getBoundingClientRect(); const e = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
                const vis = r.width > 0 && r.height > 0 && (e === b || b.contains(e)); b.remove(); return [true, vis]; }""")
            parts.append(f"shortcut(overlay={'yes' if r[0] else 'NO'} visible={'yes' if r[1] else 'NO'})")
        except Exception as e:
            parts.append(f"shortcut(failed {type(e).__name__})")
    return " ".join(parts)


async def run_diag(ctx, names: list[str], urls: dict, a) -> None:
    """--diag: counts-only check of every reader on the real pages. Prints one line per service every 10 s."""
    errs: dict[str, list] = {n: [] for n in names}
    pages: dict = {}
    keep = ctx.pages[:]
    for i, n in enumerate(names):
        p = keep[i] if i < len(keep) else await ctx.new_page()
        pages[n] = p

        def on_err(e, n=n):
            m = re.search(r":(\d+):\d+", getattr(e, "stack", "") or "")
            errs[n].append((getattr(e, "name", "Error") or "Error") + ("@" + m.group(1) if m else ""))
        p.on("pageerror", on_err)
        try:
            await p.goto(urls[n], wait_until="domcontentloaded", timeout=60000)
        except Exception as e:
            print(f"[{n}] could not open ({type(e).__name__})", flush=True)
    for p in keep[len(names):]:            # tabs restored from the previous session carry no injected scripts
        try:
            await p.close()
        except Exception:
            pass
    await asyncio.sleep(a.settle)
    t_end = time.time() + a.diag_for
    first = True
    while True:
        for n in names:
            if a.diag_open is not None:
                try:
                    xy = await pages[n].evaluate(f"window.__SB.openRead({int(a.diag_open)})")
                    ok = bool(xy)
                    if xy:
                        await pages[n].mouse.click(xy[0], xy[1])
                    print(f"[{n}] opened a read row: {'yes' if ok else 'no'}", flush=True)
                except Exception as e:
                    print(f"[{n}] open failed ({type(e).__name__})", flush=True)
        if a.diag_open is not None:
            await asyncio.sleep(4)
            a.diag_open = None
        for n in names:
            print(await diag_line(n, pages[n], errs[n], first and not a.no_key), flush=True)
            if a.skel and first:
                sel, depth, kids = (a.skel.split("|") + ["4", "6"])[:3]
                try:
                    print(f"[{n}] skeleton of {sel}:\n" + await pages[n].evaluate(
                        "([s,d,k]) => window.__SB.skeleton(s, d, k)", [sel, int(depth), int(kids)]), flush=True)
                except Exception as e:
                    print(f"[{n}] skeleton failed ({type(e).__name__})", flush=True)
        first = False
        if time.time() >= t_end:
            break
        await asyncio.sleep(min(10, max(0, t_end - time.time())))


async def run(a) -> None:
    from playwright.async_api import async_playwright

    mode = "login" if a.login else ("show" if (a.show or a.diag) else "background")
    avail = discover()
    names = list(avail) if a.services == "all" else [s.strip() for s in a.services.split(",") if s.strip()]
    bad = [n for n in names if n not in avail]
    if bad:
        raise SystemExit(f"unknown service {bad}; available: {', '.join(avail)}")

    srv = None
    status = None
    if a.demo:
        srv, port = start_demo_server()
        urls = {n: f"http://127.0.0.1:{port}/{n}.html" for n in names}
    else:
        urls = {n: avail[n] for n in names}

    alerts = Alerts()
    bridge = Bridge(a.api, not (a.no_llm or a.lite), alerts)
    order = [a.browser] if a.browser != "auto" else BROWSERS
    async with async_playwright() as pw:
        ctx = await launch(pw, order, a.demo, mode, a)
        if mode != "login":
            status = start_status_server(alerts, mode, a.status_port)
            if a.diag:        # self-check: nothing is analysed, no text leaves the page
                async def _off(source, payload):
                    return {"ok": False}
                await ctx.expose_binding("__sbAnalyze", _off)
                await ctx.expose_binding("__sbTrust", _off)
            else:
                await ctx.expose_binding("__sbAnalyze", bridge.analyze)
                await ctx.expose_binding("__sbTrust", bridge.trust)
            await ctx.expose_binding("__sbInput", bridge.input)
            await ctx.expose_binding("__sbNote", bridge.note)
            cfg = {"banner": mode == "show" and not a.diag, "list": not a.diag, "openStrangers": a.open_strangers,
                   "pollMs": a.poll * 1000}
            for code in init_scripts(cfg):
                await ctx.add_init_script(code)
            if mode == "background" and not a.hidden_window:
                ctx.on("page", lambda p: asyncio.ensure_future(hide_headless_ua(ctx, p)))
            if a.lite and mode == "background":
                await ctx.route("**/*", block_heavy)      # not in --login: QR code and login pages need images
        first = ctx.pages[0] if ctx.pages else await ctx.new_page()
        if mode == "background" and not a.hidden_window:
            await hide_headless_ua(ctx, first)

        closed = asyncio.Event()
        ctx.on("close", lambda *_: closed.set())

        if a.diag:
            try:
                await run_diag(ctx, names, urls, a)
            finally:
                try:
                    await ctx.close()
                except Exception:
                    pass
                for s in (srv, status):
                    if s:
                        s.shutdown()
            return

        async def open_url(p, n):
            try:
                await p.goto(urls[n], wait_until="domcontentloaded", timeout=60000)
            except Exception as e:
                print(f"[{n}] could not open ({type(e).__name__})", flush=True)

        if a.lite and mode != "login":
            print(f"lite: one tab, rotating every {a.rotate}s through {', '.join(names)}", flush=True)
        else:
            restored = [p for p in ctx.pages if p is not first]
            for i, n in enumerate(names):
                # reuse tabs restored from an earlier session (they have no injected scripts until navigated)
                if i == 0:
                    pg = first
                elif restored:
                    pg = restored.pop(0)
                else:
                    pg = await ctx.new_page()
                await open_url(pg, n)
            if mode != "login":
                for p in restored:
                    try:
                        await p.close()
                    except Exception:
                        pass
        if mode != "login":
            print(f"Status page: http://127.0.0.1:{a.status_port}", flush=True)
        print({"login": "Login window open: sign in to each service, then close the window.",
               "show": "Watcher running (visible). Close the window or press Ctrl+C to stop.",
               "background": "Watcher running in the background. Press Ctrl+C to stop."}[mode], flush=True)
        try:
            if a.lite and mode != "login":
                i = 0
                while not closed.is_set():
                    await open_url(first, names[i % len(names)])
                    i += 1
                    try:
                        await asyncio.wait_for(closed.wait(), timeout=a.rotate)
                    except asyncio.TimeoutError:
                        pass
            else:
                await closed.wait()
        finally:
            try:
                await ctx.close()
            except Exception:
                pass
            for s in (srv, status):
                if s:
                    s.shutdown()


def main() -> None:
    ap = argparse.ArgumentParser(description="2nd Eye watcher")
    ap.add_argument("--services", default="all", help="comma list, default all (found in readers/*.js)")
    ap.add_argument("--browser", default="auto", choices=["auto"] + BROWSERS, help="chrome, msedge or chromium (default: first available)")
    ap.add_argument("--api", default="http://localhost:8000", help="detector API base URL")
    ap.add_argument("--demo", action="store_true", help="open the local demo pages instead of the real sites")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--login", action="store_true", help="visible window to sign in once; exits when closed")
    g.add_argument("--show", action="store_true", help="visible window with the in-page banner (demo)")
    ap.add_argument("--diag", action="store_true",
                    help="self-check: visible window (like --show), prints counts-only lines per service every 10 s, then exits")
    ap.add_argument("--diag-for", type=int, default=60, help="--diag: seconds to keep checking (default 60)")
    ap.add_argument("--settle", type=int, default=12, help="--diag: seconds to let pages settle first (default 12)")
    ap.add_argument("--diag-open", type=int, default=None, metavar="N",
                    help="--diag: click the N-th list row that has NO unread marker, to test the open-conversation reader")
    ap.add_argument("--skel", default=None, metavar="CSS[|depth|kids]",
                    help="--diag: also print a redacted structural skeleton (tags, roles, attribute names, counts) of CSS")
    ap.add_argument("--no-key", action="store_true", help="--diag: skip the Ctrl+Shift+S overlay test")
    ap.add_argument("--hidden-window", action="store_true", help="background mode as an off-screen window instead of headless")
    ap.add_argument("--minimized", action="store_true", help="with --show: start the window minimised")
    ap.add_argument("--open-strangers", action="store_true",
                    help="open an unread chat from a stranger to read the full thread (this MARKS IT AS READ)")
    ap.add_argument("--lite", action="store_true", help="one tab at a time (rotating), no images/media/fonts in background, rules only (use_llm=false)")
    ap.add_argument("--rotate", type=int, default=60, help="--lite: seconds per service (default 60)")
    ap.add_argument("--poll", type=int, default=20, help="seconds between chat-list polls (default 20)")
    ap.add_argument("--status-port", type=int, default=8010, help="local status page port (default 8010)")
    ap.add_argument("--no-llm", action="store_true", help="call the API with use_llm=false")
    a = ap.parse_args()
    try:
        asyncio.run(run(a))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
