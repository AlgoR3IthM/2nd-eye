from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import asyncio
import re
from engine import analyze_scenario
from fastapi.responses import HTMLResponse
from pathlib import Path

app = FastAPI(title="Scam Shield Neuro-Symbolic API")

# Only this dashboard (served from localhost) may read the API cross-origin; "*" would let any website read results.
LOCAL_ORIGIN = r"^http://(localhost|127\.0\.0\.1)(:\d+)?$"
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=LOCAL_ORIGIN,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# Conexiuni WebSocket active pentru Live Feed în Dashboard-ul GUI
active_connections: List[WebSocket] = []


async def broadcast_live_alert(result: Dict[str, Any]):
    for ws in list(active_connections):
        try:
            await ws.send_json(result)
        except Exception:
            active_connections.remove(ws)


class ScenarioPayload(BaseModel):
    id: Optional[str] = "LIVE_INPUT"
    channel: Optional[str] = "whatsapp"
    sender: Optional[Dict[str, Any]] = {"name": None, "address": "unknown", "known_contact": False}
    messages: List[Dict[str, Any]]


@app.post("/analyze")
async def analyze_single(payload: ScenarioPayload):
    result = analyze_scenario(payload.model_dump())
    await broadcast_live_alert(result)
    return result


@app.post("/analyze-batch")
async def analyze_batch(scenarios: List[ScenarioPayload]):
    results = [analyze_scenario(s.model_dump()) for s in scenarios]
    results.sort(key=lambda x: x["id"])
    summary = {
        "total": len(results),
        "SCAM": sum(1 for r in results if r["verdict"] == "SCAM"),
        "SUSPICIOUS": sum(1 for r in results if r["verdict"] == "SUSPICIOUS"),
        "SAFE": sum(1 for r in results if r["verdict"] == "SAFE"),
    }
    return {"summary": summary, "results": results}


@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    # WebSockets are not covered by CORS: without this check any website open in the browser could connect and
    # receive every analysed conversation, message text included.
    if not re.match(LOCAL_ORIGIN, websocket.headers.get("origin") or ""):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await asyncio.sleep(10)
    except WebSocketDisconnect:
        if websocket in active_connections:
            active_connections.remove(websocket)

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    html_path = Path(__file__).parent / "dashboard.html"
    return html_path.read_text(encoding="utf-8")