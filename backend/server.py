"""Scam Shield local API (FastAPI). Run: uvicorn backend.server:app --host 0.0.0.0 --port 8000 --no-access-log

API: POST /api/analyze (scenario), POST /api/analyze-text, POST /api/parse-chat (pasted or exported chat -> participants + messages),
POST /api/analyze-chat (chat + which participant is "me" -> same result as /api/analyze), GET /api/health, GET /api/catalog, DELETE /api/memo.

Privacy: message text is never logged or stored; the only outbound call is to the local LM Studio.
"""
import copy
import hashlib
import json
import os
import sys
import threading
from collections import OrderedDict
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
WEB = ROOT / "web"
CATALOG = ROOT / "Cerinte" / "official_catalog.json"

if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import llm  # noqa: E402
import chatparse  # noqa: E402

try:
    import fusion  # noqa: E402
except Exception:  # fusion may be missing or broken; report per request, never crash the server
    fusion = None

app = FastAPI(title="Scam Shield", docs_url=None, redoc_url=None)
# Listening on the local network only; "*" also covers Origin "null" (file://) and chrome-extension://.
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
                   allow_credentials=False)

_LOCK = threading.Lock()   # one analysis (one LLM call) at a time


def _flag(v: str, default: bool) -> bool:
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


# Result memo: repeatability guarantee within one server session. Memory only, never written to disk, bounded,
# gone when the process ends. Key = SHA-256 of canonical scenario JSON + model id + use_llm + trust_gate.
_MEMO = OrderedDict()
_MEMO_MAX = 256


def _memo_key(scenario, use_llm: bool, trust_gate: bool):
    try:
        canon = json.dumps(scenario, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return None
    model = os.environ.get("SCAMSHIELD_MODEL", llm.DEFAULT_MODEL) if use_llm else "-"
    raw = canon + "\x00" + model + "\x00" + ("1" if use_llm else "0") + ("1" if trust_gate else "0")
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def _run(scenario, use_llm: bool, trust_gate: bool) -> dict:
    with _LOCK:
        if fusion is None:
            raise RuntimeError("fusion module unavailable")
        key = _memo_key(scenario, use_llm, trust_gate)
        if key is not None and key in _MEMO:
            _MEMO.move_to_end(key)
            return copy.deepcopy(_MEMO[key])
        result = fusion.analyze(scenario, use_llm=use_llm, trust_gate=trust_gate)
        sig = result.get("signals") or {}
        # a result produced while the model failed to answer is never remembered: the next try may get the model
        if key is not None and not (use_llm and sig.get("llm_status") in ("unavailable", "invalid_output")):
            _MEMO[key] = copy.deepcopy(result)
            while len(_MEMO) > _MEMO_MAX:
                _MEMO.popitem(last=False)
        return result


def _error(code: int, msg: str):
    return JSONResponse({"error": msg}, status_code=code)


async def _body(request: Request):
    try:
        return json.loads((await request.body()).decode("utf-8", errors="replace"))
    except Exception:
        return None


async def _analyze(scenario, request: Request):
    q = request.query_params
    use_llm = _flag(q.get("use_llm"), True)
    trust_gate = _flag(q.get("trust_gate"), False)
    try:
        result = await run_in_threadpool(_run, scenario, use_llm, trust_gate)
        return JSONResponse(result)
    except Exception as e:   # type name only, never message content
        return _error(500, "analysis failed: " + type(e).__name__)


@app.post("/api/analyze")
async def api_analyze(request: Request):
    scenario = await _body(request)
    if not isinstance(scenario, dict):
        scenario = {"id": "INVALID", "channel": "unknown", "messages": []}
    return await _analyze(scenario, request)


@app.post("/api/analyze-text")
async def api_analyze_text(request: Request):
    body = await _body(request)
    if not isinstance(body, dict):
        body = {}
    text = body.get("text")
    text = text if isinstance(text, str) else ""
    known = body.get("known_contact") is True
    channel = body.get("channel") if isinstance(body.get("channel"), str) else "sms"
    scenario = {
        "id": "TEXT",
        "channel": channel,
        "sender": {"name": None, "address": None, "known_contact": known},
        "messages": [{"n": 1, "from": "sender", "text": text}],
    }
    return await _analyze(scenario, request)


_CHAT_MAX = 400_000


def _chat_text(body) -> str:
    t = body.get("text") if isinstance(body, dict) else None
    return t[:_CHAT_MAX] if isinstance(t, str) else ""


@app.post("/api/parse-chat")
async def api_parse_chat(request: Request):
    p = chatparse.parse(_chat_text(await _body(request)))
    return JSONResponse({"format": p["format"], "participants": p["participants"],
                         "count": len(p["messages"]), "messages": p["messages"]})


@app.post("/api/analyze-chat")
async def api_analyze_chat(request: Request):
    body = await _body(request)
    if not isinstance(body, dict):
        body = {}
    parsed = chatparse.parse(_chat_text(body))
    me = body.get("me") if isinstance(body.get("me"), str) else None
    channel = body.get("channel") if isinstance(body.get("channel"), str) and body.get("channel") else "whatsapp"
    scenario = chatparse.to_scenario(parsed, me, channel, body.get("known_contact") is True)
    return await _analyze(scenario, request)


def _health_probe() -> dict:
    ok = llm.healthy()   # the model must really answer, not just be listed by LM Studio
    return {"ok": True, "llm": ok, "model": llm.model_name() if ok else None}


@app.delete("/api/memo")
async def api_memo_clear():
    with _LOCK:
        n = len(_MEMO)
        _MEMO.clear()
    return {"cleared": n}


@app.get("/api/health")
async def api_health():
    return await run_in_threadpool(_health_probe)


_LIVE = {"whatsapp": "http://127.0.0.1:8010", "gmail": "http://127.0.0.1:8011"}


def _live_fetch(base: str):
    import urllib.request
    try:
        with urllib.request.urlopen(base + "/conversations.json", timeout=2) as r:
            items = json.loads(r.read().decode("utf-8")).get("conversations") or []
        return True, [i for i in items if isinstance(i, dict)]
    except Exception:
        return False, []


def _live_all() -> dict:
    out, items = {}, []
    for name, base in _LIVE.items():
        on, got = _live_fetch(base)
        out[name] = {"on": on}
        items.extend(got)
    items.sort(key=lambda i: str(i.get("time") or ""), reverse=True)
    out["items"] = items
    return out


def _live_clear() -> dict:
    import urllib.request
    res = {}
    for name, base in _LIVE.items():
        try:
            req = urllib.request.Request(base + "/conversations.json", method="DELETE")
            with urllib.request.urlopen(req, timeout=2):
                res[name] = True
        except Exception:
            res[name] = False
    return res


@app.get("/api/live")
async def api_live():
    return JSONResponse(await run_in_threadpool(_live_all), headers={"Cache-Control": "no-store"})


@app.delete("/api/live")
async def api_live_clear():
    return await run_in_threadpool(_live_clear)


@app.get("/api/catalog")
async def api_catalog():
    try:
        return JSONResponse(json.loads(CATALOG.read_text(encoding="utf-8")))
    except Exception:
        return _error(404, "catalog not found")


@app.get("/")
async def index():
    f = WEB / "index.html"
    if f.exists():
        return FileResponse(f, media_type="text/html; charset=utf-8")
    return HTMLResponse("<h1>2nd Eye</h1><p>web/index.html lipsește încă. API: /api/health</p>")


if WEB.is_dir():
    app.mount("/web", StaticFiles(directory=str(WEB)), name="web")
    app.mount("/static", StaticFiles(directory=str(WEB)), name="static")
