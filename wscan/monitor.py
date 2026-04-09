"""
WScan Monitor Server
FastAPI + WebSocket server for real-time scan monitoring dashboard.
"""
import asyncio
import json
import time
from pathlib import Path
from typing import Set, Any, Optional

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

        # ── Intervention / plan-confirm channels ──────────────────────
        # Commands arriving from the web UI (pause / resume / skip_field / skip_page / abort)
        self.command_queue: asyncio.Queue = asyncio.Queue()
        # Set when the operator clicks "Start Attack" in the plan review modal
        self.plan_confirm_event: asyncio.Event = asyncio.Event()
        # Plan edits returned by the operator (field overrides sent from web UI)
        self.confirmed_plan_edits: dict = {}   # {url: {field_name: {risk, checks, payloads}}}
        # U-3: Manual payload requests from web UI
        self.manual_payload_queue: asyncio.Queue = asyncio.Queue()
        # Scan config submitted from the dashboard (serve mode)
        self.scan_request_event: asyncio.Event = asyncio.Event()
        self.scan_request_data: dict = {}

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
                # Keep connection alive and process incoming messages
                while True:
                    try:
                        raw = await asyncio.wait_for(ws.receive_text(), timeout=30)
                        self._handle_client_message(raw)
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

    # ------------------------------------------------------------------
    # Client message handler (called from WebSocket coroutine)
    # ------------------------------------------------------------------

    def _handle_client_message(self, raw: str) -> None:
        """Parse and dispatch a JSON message sent from the browser."""
        try:
            msg = json.loads(raw)
        except Exception:
            return

        action = msg.get("action", "")

        if action == "intervention":
            # e.g. {"action": "intervention", "command": "pause"}
            cmd = msg.get("command", "")
            if cmd:
                self.command_queue.put_nowait(cmd)

        elif action == "plan_confirm":
            # e.g. {"action": "plan_confirm", "edits": { url: {field: {risk, checks}} }}
            self.confirmed_plan_edits = msg.get("edits", {})
            self.plan_confirm_event.set()

        elif action == "manual_payload":
            # U-3: {"action": "manual_payload", "url": ..., "field": ..., "payload": ..., "check_type": ...}
            self.manual_payload_queue.put_nowait(msg)

        elif action == "start_scan":
            # Serve mode: dashboard submits full scan config
            self.scan_request_data = msg.get("config", {})
            self.scan_request_event.set()

    # ------------------------------------------------------------------
    # Broadcast helpers
    # ------------------------------------------------------------------

    async def emit(self, event_type: str, data: Any = None):
        """Send an event to all connected monitoring clients."""
        event = {
            "type": event_type,
            "timestamp": time.time(),
            "data": data or {},
        }
        self.event_history.append(event)
        if len(self.event_history) > 2000:
            self.event_history = self.event_history[-1000:]  # trim to last 1000
        dead = set()
        for client in list(self.clients):
            try:
                await client.send_text(json.dumps(event))
            except Exception:
                dead.add(client)
        self.clients -= dead

    async def emit_status(self, message: str, state: str = "running"):
        await self.emit("status", {"message": message, "state": state})

    async def emit_finding(self, finding: dict):
        await self.emit("finding", finding)

    async def emit_screenshot(self, screenshot_b64: str, label: str = ""):
        await self.emit("screenshot", {"image": screenshot_b64, "label": label})

    async def emit_request(self, req: dict):
        await self.emit("request", req)

    async def emit_response(self, resp: dict):
        await self.emit("response", resp)

    async def emit_scan_config(
        self,
        url: str,
        checks: list,
        depth: int,
        concurrency: int,
        timeout: int,
    ):
        """Send scan configuration to the dashboard so it can render dynamic badges."""
        await self.emit("scan_config", {
            "url": url,
            "checks": checks,
            "depth": depth,
            "concurrency": concurrency,
            "timeout": timeout,
        })

    async def emit_awaiting_config(self):
        """Tell the dashboard to show the scan configuration form (serve mode)."""
        await self.emit("awaiting_config", {})

    async def emit_scan_started(self, config: dict):
        """Tell the dashboard the scan has started with the given config."""
        await self.emit("scan_started", config)

    async def emit_page_start(self, url: str):
        await self.emit("page_start", {"url": url})

    async def emit_payload_test(self, field: str, payload: str, check_type: str, url: str = "") -> None:
        await self.emit("payload_test", {
            "field": field,
            "payload": payload,
            "check_type": check_type,
            "url": url,
        })

    async def emit_progress(self, current: int, total: int, message: str = ""):
        await self.emit("progress", {
            "current": current,
            "total": total,
            "percent": int(current / total * 100) if total > 0 else 0,
            "message": message,
        })

    async def emit_phase(self, phase: str) -> None:
        """Emit current scan phase: 'crawl' | 'plan' | 'attack' | 'report'"""
        await self.emit("phase", {"phase": phase})

    async def emit_url_start(self, url: str, total_urls: int = 0) -> None:
        """Emit when a URL begins being attacked."""
        await self.emit("url_start", {"url": url, "total_urls": total_urls})

    async def emit_url_complete(self, url: str) -> None:
        """Emit when a URL has finished being attacked."""
        await self.emit("url_complete", {"url": url})

    async def emit_plan_review(self, plans_data: list):
        """
        Send plan data to the dashboard for operator review/edit.
        The dashboard will show the plan modal and wait for the operator
        to click 'Start Attack'.
        """
        self.plan_confirm_event.clear()
        await self.emit("plan_review", {"plans": plans_data})

    async def emit_intervention_state(self, paused: bool):
        """Tell the dashboard whether the scan is paused."""
        await self.emit("intervention_state", {"paused": paused})

    # ------------------------------------------------------------------
    # Blocking wait helpers (called from engine coroutine)
    # ------------------------------------------------------------------

    async def wait_for_plan_confirm(self, timeout: float = 600.0) -> dict:
        """
        Block until the operator clicks 'Start Attack' in the web UI.
        Auto-confirms with no edits after `timeout` seconds so the scan
        never hangs when no dashboard client is connected.
        Returns the edits dict (may be empty if no changes were made).
        """
        try:
            await asyncio.wait_for(
                self.plan_confirm_event.wait(),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            pass  # auto-confirm
        return self.confirmed_plan_edits
