"""
WScan Monitor Server
FastAPI + WebSocket server for real-time scan monitoring dashboard.
"""
import asyncio
import json
import time
from pathlib import Path
from typing import Set, Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles


TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


class MonitorServer:
    """Real-time monitoring server for scan progress."""

    def __init__(self, port: int = 8765):
        self.port = port
        self.clients: Set[WebSocket] = set()
        self._queue: asyncio.Queue = asyncio.Queue()
        self.app = self._create_app()
        self._started = False
        self.event_history: list[dict] = []

    def _create_app(self) -> FastAPI:
        app = FastAPI(title="WScan Monitor", docs_url=None, redoc_url=None)

        @app.get("/", response_class=HTMLResponse)
        async def dashboard():
            html_path = TEMPLATES_DIR / "dashboard.html"
            if html_path.exists():
                return html_path.read_text(encoding="utf-8")
            return "<h1>Dashboard not found</h1>"

        @app.websocket("/ws")
        async def websocket_endpoint(ws: WebSocket):
            await ws.accept()
            self.clients.add(ws)
            # Send event history to newly connected client
            try:
                for event in self.event_history[-200:]:
                    await ws.send_text(json.dumps(event))
                # Keep connection alive and receive messages
                while True:
                    try:
                        await asyncio.wait_for(ws.receive_text(), timeout=30)
                    except asyncio.TimeoutError:
                        # Send ping to keep alive
                        await ws.send_text(json.dumps({"type": "ping"}))
            except (WebSocketDisconnect, Exception):
                pass
            finally:
                self.clients.discard(ws)

        @app.get("/health")
        async def health():
            return {"status": "ok", "clients": len(self.clients)}

        return app

    async def emit(self, event_type: str, data: Any = None):
        """Send an event to all connected monitoring clients."""
        event = {
            "type": event_type,
            "timestamp": time.time(),
            "data": data or {},
        }
        self.event_history.append(event)
        # Broadcast to all clients
        dead = set()
        for client in list(self.clients):
            try:
                await client.send_text(json.dumps(event))
            except Exception:
                dead.add(client)
        self.clients -= dead

    async def emit_status(self, message: str, state: str = "running"):
        """Emit a status update."""
        await self.emit("status", {"message": message, "state": state})

    async def emit_finding(self, finding: dict):
        """Emit a vulnerability finding."""
        await self.emit("finding", finding)

    async def emit_screenshot(self, screenshot_b64: str, label: str = ""):
        """Emit a screenshot (base64 encoded PNG)."""
        await self.emit("screenshot", {"image": screenshot_b64, "label": label})

    async def emit_request(self, req: dict):
        """Emit an HTTP request."""
        await self.emit("request", req)

    async def emit_response(self, resp: dict):
        """Emit an HTTP response."""
        await self.emit("response", resp)

    async def emit_page_start(self, url: str):
        """Emit page scan start."""
        await self.emit("page_start", {"url": url})

    async def emit_payload_test(self, field: str, payload: str, check_type: str):
        """Emit payload test event."""
        await self.emit("payload_test", {
            "field": field,
            "payload": payload,
            "check_type": check_type,
        })

    async def emit_progress(self, current: int, total: int, message: str = ""):
        """Emit progress update."""
        await self.emit("progress", {
            "current": current,
            "total": total,
            "percent": int(current / total * 100) if total > 0 else 0,
            "message": message,
        })
