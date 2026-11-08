"""Swarm web server — FastAPI + WebSocket. Serves the live dashboard, streams the 5 agents'
conversation, and lets the human chat in / start / stop / queue targets.

Run:  uvicorn swarm.server:app --host 0.0.0.0 --port 8080
"""
from __future__ import annotations
import asyncio, json, time
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from . import config, orchestrator, targets, kilo

app = FastAPI(title="Cyber Swarm")
UI = Path(__file__).parent / "ui" / "index.html"

class Hub:
    def __init__(self):
        self.clients: set[WebSocket] = set()
        self.buffer: list[dict] = []        # recent events for late joiners
        self.swarm: orchestrator.Swarm | None = None
        self.task: asyncio.Task | None = None

    async def broadcast(self, ev: dict):
        self.buffer.append(ev)
        if len(self.buffer) > 400:
            self.buffer = self.buffer[-400:]
        dead = []
        for ws in self.clients:
            try:
                await ws.send_json(ev)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.clients.discard(ws)

    async def start(self):
        if self.swarm and self.swarm.running:
            return
        self.swarm = orchestrator.Swarm(emit=self.broadcast)
        stream = targets.make_stream(emit=self.broadcast)
        self.task = asyncio.create_task(self.swarm.run(stream))

    def stop(self):
        if self.swarm:
            self.swarm.stop()

hub = Hub()


@app.get("/")
async def index():
    if UI.exists():
        return HTMLResponse(UI.read_text())
    return HTMLResponse("<h1>Cyber Swarm</h1><p>UI file missing.</p>")


@app.get("/api/status")
async def status():
    s = hub.swarm
    warn = config.sanity()
    return JSONResponse({
        "running": bool(s and s.running),
        "paused": bool(s and s.paused),
        "stats": s.stats if s else {"targets": 0, "calls": 0, "findings": 0},
        "calls_today": kilo.calls_today(),
        "target": s.target if s else None,
        "findings": (s.findings if s else []),
        "warnings": warn,
        "models": {r: config.role_model(r) for r in ["RECON", "ATTACKER", "SKEPTIC", "EXPLOIT_DEV", "REFEREE"]},
    })


@app.websocket("/ws")
async def ws(ws: WebSocket):
    await ws.accept()
    hub.clients.add(ws)
    # replay recent buffer so a late joiner sees context
    for ev in hub.buffer[-120:]:
        try: await ws.send_json(ev)
        except Exception: break
    try:
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except Exception:
                continue
            action = msg.get("action")
            if action == "start":
                await hub.start()
            elif action == "stop":
                hub.stop()
            elif action == "chat" and msg.get("text"):
                if hub.swarm:
                    hub.swarm.inject(msg["text"])
                await hub.broadcast({"type": "message", "role": "TEAM_LEAD",
                                     "content": msg["text"], "ts": time.time()})
            elif action == "add_target" and msg.get("address"):
                await targets.queue_target(msg.get("chain", "ethereum"),
                                           msg["address"], msg.get("name", "manual"))
                await hub.broadcast({"type": "system",
                                     "content": f"queued target {msg['address']}", "ts": time.time()})
            elif action == "pause" and hub.swarm:
                hub.swarm.paused = not hub.swarm.paused
                await hub.broadcast({"type": "system",
                                     "content": f"paused={hub.swarm.paused}", "ts": time.time()})
    except WebSocketDisconnect:
        pass
    finally:
        hub.clients.discard(ws)


@app.on_event("startup")
async def _startup():
    w = config.sanity()
    if w:
        print("[swarm] config warnings:")
        for x in w: print("  -", x)
    print(f"[swarm] UI on http://{config.HOST}:{config.PORT}  models:",
          {r: config.role_model(r) for r in ['RECON','ATTACKER','SKEPTIC','EXPLOIT_DEV','REFEREE']})
