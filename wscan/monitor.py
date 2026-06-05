"""
WScan Monitor Server
FastAPI + WebSocket server for real-time scan monitoring dashboard.
"""
import asyncio
import collections
import datetime
import hashlib
import io
import json
import secrets
import shutil
import time
import zipfile
from pathlib import Path
from typing import Set, Any, Optional

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    FileResponse,
    RedirectResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles


TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
# Where ScanEngine writes each scan's artifacts (output/<timestamp>/...).
# Defined here to avoid importing the heavy engine module (pulls in Playwright).
OUTPUT_BASE = Path(__file__).parent.parent / "output"

# Name of the session cookie set after a successful token login.
SESSION_COOKIE = "wscan_session"
# Paths that never require authentication (health checks, the login page itself).
_PUBLIC_PATHS = {"/health", "/login", "/favicon.ico"}


def _session_value(token: str) -> str:
    """Derive an opaque cookie value from the shared token.

    The raw token is never stored in the browser cookie; instead we store a
    SHA-256 digest so a leaked cookie cannot be replayed against the Bearer
    API and the token itself is not exposed in client storage.
    """
    return hashlib.sha256(("wscan:" + token).encode("utf-8")).hexdigest()


class MonitorServer:
    """Real-time monitoring server for scan progress."""

    def __init__(self, port: int = 8765, auth_token: str = ""):
        self.port = port
        # Shared access token. Empty string => authentication disabled.
        self.auth_token: str = (auth_token or "").strip()
        self._session_value: str = _session_value(self.auth_token) if self.auth_token else ""
        self.clients: Set[WebSocket] = set()
        self._queue: asyncio.Queue = asyncio.Queue()
        self.app = self._create_app()
        self._started = False
        self.event_history: collections.deque = collections.deque(maxlen=1000)

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
        # True while a scan is actually executing in persistent serve mode.
        # Used to reject (rather than silently drop) concurrent scan requests.
        self.scan_in_progress: bool = False
        # Output directory name (timestamp) of the scan currently running, set by
        # the engine. Lets the portal map the live scan to its artifacts folder.
        self.current_scan_id: str = ""
        # Crawl review (AeyeScan-style pause between crawl and plan)
        self.crawl_review_event: asyncio.Event = asyncio.Event()
        self.crawl_review_action: dict = {}
        # LLM config for auto-config HTTP endpoint (set by main.py after init)
        self.llm_cfg: dict = {}
        self.default_scan_cfg: dict = {}
        # D: CI/CD REST API state
        self.api_scan_id: str = ""
        self.api_scan_status: str = "idle"   # idle / scanning / done / error
        self.api_findings: list[dict] = []   # emit_finding() で自動蓄積
        self.api_report_path: Optional[str] = None
        self.manual_crawl_session = None
        # Optional RequestLogger (set by ScanEngine). Persists tested payloads
        # to payloads.jsonl alongside the HTTP request audit log.
        self.request_logger = None

    # ------------------------------------------------------------------
    # Authentication helpers
    # ------------------------------------------------------------------

    def _token_ok(self, token: Optional[str]) -> bool:
        """Constant-time comparison of a presented raw token."""
        if not self.auth_token:
            return True
        if not token:
            return False
        return secrets.compare_digest(token, self.auth_token)

    def _request_authorized(self, request: Request) -> bool:
        """True if the HTTP request carries valid credentials."""
        if not self.auth_token:
            return True
        # 1. Session cookie set by the login page.
        cookie = request.cookies.get(SESSION_COOKIE)
        if cookie and secrets.compare_digest(cookie, self._session_value):
            return True
        # 2. Authorization: Bearer <token>  (API / CI clients).
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            if self._token_ok(auth[7:].strip()):
                return True
        # 3. X-Auth-Token header (convenience for scripts).
        if self._token_ok(request.headers.get("x-auth-token")):
            return True
        return False

    def _ws_authorized(self, ws: WebSocket) -> bool:
        """True if a WebSocket upgrade request is authenticated."""
        if not self.auth_token:
            return True
        cookie = ws.cookies.get(SESSION_COOKIE)
        if cookie and secrets.compare_digest(cookie, self._session_value):
            return True
        # Non-browser clients may pass ?token=... on the WS URL.
        token = ws.query_params.get("token")
        return self._token_ok(token)

    def _create_app(self) -> FastAPI:
        app = FastAPI(title="WScan Monitor", docs_url=None, redoc_url=None)

        @app.middleware("http")
        async def _auth_middleware(request: Request, call_next):
            if not self.auth_token:
                return await call_next(request)
            path = request.url.path
            if path in _PUBLIC_PATHS or self._request_authorized(request):
                return await call_next(request)
            # Browsers asking for HTML get redirected to the login page;
            # API/XHR callers get a clean 401 so they can react.
            accept = request.headers.get("accept", "")
            wants_html = "text/html" in accept and not path.startswith("/api/")
            if wants_html:
                return RedirectResponse(url="/login", status_code=303)
            return JSONResponse(
                {"error": "認証が必要です。Authorization: Bearer <token> ヘッダーを付与してください。"},
                status_code=401,
            )

        @app.get("/login", response_class=HTMLResponse)
        async def login_page(request: Request):
            if not self.auth_token or self._request_authorized(request):
                return RedirectResponse(url="/", status_code=303)
            return HTMLResponse(self._login_html())

        @app.post("/login")
        async def login_submit(request: Request):
            form = await request.form()
            token = (form.get("token") or "").strip()
            if self._token_ok(token):
                resp = RedirectResponse(url="/", status_code=303)
                resp.set_cookie(
                    SESSION_COOKIE,
                    self._session_value,
                    httponly=True,
                    samesite="lax",
                    max_age=60 * 60 * 12,  # 12 hours
                )
                return resp
            return HTMLResponse(self._login_html(error=True), status_code=401)

        @app.get("/logout")
        async def logout():
            resp = RedirectResponse(url="/login", status_code=303)
            resp.delete_cookie(SESSION_COOKIE)
            return resp

        @app.get("/", response_class=HTMLResponse)
        async def portal():
            # Server front door: scan history, report viewing, scan management.
            html_path = TEMPLATES_DIR / "portal.html"
            if html_path.exists():
                return html_path.read_text(encoding="utf-8")
            # Fall back to the live monitor if the portal template is missing.
            return RedirectResponse(url="/monitor", status_code=307)

        @app.get("/monitor", response_class=HTMLResponse)
        async def dashboard():
            html_path = TEMPLATES_DIR / "dashboard.html"
            if html_path.exists():
                return html_path.read_text(encoding="utf-8")
            return "<h1>Dashboard not found</h1>"

        @app.websocket("/ws")
        async def websocket_endpoint(ws: WebSocket):
            if not self._ws_authorized(ws):
                await ws.close(code=4401)  # 4401: custom "unauthorized"
                return
            await ws.accept()
            self.clients.add(ws)
            # Send event history to newly connected client
            try:
                for event in list(self.event_history)[-200:]:
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

        @app.get("/api/auth-status")
        async def api_auth_status():
            """Lets the dashboard know whether the logout control applies."""
            return {"auth_enabled": bool(self.auth_token)}

        @app.get("/api/config/defaults")
        async def api_config_defaults():
            """Return config/wscan.yaml-derived defaults for the dashboard form."""
            return JSONResponse(self.default_scan_cfg or {})

        @app.post("/api/auto-config")
        async def api_auto_config(request: Request):
            """自然言語の説明からスキャン設定を生成するHTTPエンドポイント。"""
            try:
                body = await request.json()
            except Exception:
                return JSONResponse({"error": "Invalid JSON"}, status_code=400)

            description = (body.get("description") or "").strip()
            if not description:
                return JSONResponse({"error": "description is required"}, status_code=400)

            cfg = dict(self.llm_cfg or {})
            body_cfg = body.get("llm_config") or {}
            if isinstance(body_cfg, dict):
                cfg.update(body_cfg)
            if not cfg or cfg.get("provider", "none") == "none":
                return JSONResponse(
                    {"error": "LLMが設定されていません。LLM設定タブでプロバイダーを選択してください。"},
                    status_code=400,
                )

            try:
                from wscan.payload_gen import PayloadGenerator
                from wscan.auto_config import generate_from_description

                gen = PayloadGenerator(
                    provider=cfg.get("provider", "none"),
                    ollama_model=cfg.get("ollama_model", "llama3"),
                    ollama_url=cfg.get("ollama_url", "http://localhost:11434"),
                    openai_model=cfg.get("openai_model", "gpt-4o-mini"),
                    gemini_model=cfg.get("gemini_model", "gemini-2.0-flash"),
                    claude_model=cfg.get("claude_model", "claude-haiku-4-5-20251001"),
                    role_models=cfg.get("role_models", {}) or {},
                )
                result = await generate_from_description(gen, description)
                if result is None:
                    return JSONResponse(
                        {"error": "LLMが応答しませんでした。APIキーとプロバイダー設定を確認してください。"},
                        status_code=500,
                    )
                return JSONResponse(result)
            except Exception as exc:
                return JSONResponse({"error": str(exc)}, status_code=500)

        # ── D: CI/CD REST API ─────────────────────────────────────────────────

        @app.post("/api/v1/scan")
        async def api_scan_start(request: Request):
            """
            スキャン開始エンドポイント。
            Body: {"config": {url, checks, depth, ...}}  (config キーはなくても可)
            Returns: {"status": "accepted", "scan_id": "<timestamp>"}
            """
            try:
                body = await request.json()
            except Exception:
                return JSONResponse({"error": "Invalid JSON"}, status_code=400)

            config = body.get("config", body)
            if not config.get("url"):
                return JSONResponse({"error": "url is required"}, status_code=400)

            # Reject instead of silently dropping a scan submitted while another
            # one is already running in persistent serve mode.
            if self.scan_in_progress or self.scan_request_event.is_set():
                return JSONResponse(
                    {
                        "error": "スキャンが既に実行中です。完了後に再試行してください。",
                        "status": self.api_scan_status,
                        "scan_id": self.api_scan_id,
                    },
                    status_code=409,
                )

            self.scan_request_data = config
            self.scan_request_event.set()
            self.api_scan_id = str(int(time.time()))
            self.api_scan_status = "scanning"
            self.api_findings = []
            self.api_report_path = None
            return JSONResponse({
                "status": "accepted",
                "scan_id": self.api_scan_id,
                "message": "スキャンを開始しました。/api/v1/scan/status でステータスを確認してください。",
            })

        @app.get("/api/v1/scan/status")
        async def api_scan_status():
            """スキャンステータスを返す。"""
            return JSONResponse({
                "status": self.api_scan_status,
                "scan_id": self.api_scan_id,
                "findings_count": len(self.api_findings),
            })

        @app.get("/api/v1/scan/findings")
        async def api_scan_findings():
            """検出結果を JSON で返す (スキャン中も随時取得可)。"""
            return JSONResponse({
                "scan_id": self.api_scan_id,
                "status": self.api_scan_status,
                "findings": self.api_findings,
                "findings_count": len(self.api_findings),
            })

        @app.get("/api/v1/scan/report")
        async def api_scan_report():
            """生成済み HTML レポートをファイルとして返す。"""
            if not self.api_report_path or not Path(self.api_report_path).exists():
                return JSONResponse(
                    {"error": "レポートがまだ生成されていません。スキャン完了後に再試行してください。"},
                    status_code=404,
                )
            return FileResponse(
                self.api_report_path,
                media_type="text/html",
                filename="report.html",
            )

        @app.get("/api/v1/scan/results")
        async def api_scan_results():
            """findings + metadata をまとめて返す (CI/CD パイプライン用)。"""
            return JSONResponse({
                "scan_id": self.api_scan_id,
                "status": self.api_scan_status,
                "findings": self.api_findings,
                "findings_count": len(self.api_findings),
                "critical_count": sum(1 for f in self.api_findings if f.get("severity") == "critical"),
                "high_count": sum(1 for f in self.api_findings if f.get("severity") == "high"),
                "report_available": bool(self.api_report_path and Path(self.api_report_path).exists()),
            })

        @app.post("/api/v1/manual-crawl/start")
        async def api_manual_crawl_start(request: Request):
            """Start a visible manual crawl recorder."""
            try:
                body = await request.json()
            except Exception:
                return JSONResponse({"error": "Invalid JSON"}, status_code=400)

            url = (body.get("url") or "").strip()
            if not url:
                return JSONResponse({"error": "url is required"}, status_code=400)
            output_path = (body.get("output_path") or "flows/manual_crawl.json").strip()
            headless = bool(body.get("headless", False))
            proxy = (body.get("proxy") or "").strip()

            try:
                from wscan.manual_crawl import ManualCrawlSession
                if self.manual_crawl_session and self.manual_crawl_session.running:
                    return JSONResponse(
                        {"error": "manual crawl is already running", "status": self.manual_crawl_session.status()},
                        status_code=409,
                    )
                self.manual_crawl_session = ManualCrawlSession()
                status = await self.manual_crawl_session.start(
                    start_url=url,
                    output_path=output_path,
                    headless=headless,
                    proxy=proxy,
                )
                await self.emit("manual_crawl_status", status)
                return JSONResponse(status)
            except Exception as exc:
                return JSONResponse({"error": str(exc)}, status_code=500)

        @app.post("/api/v1/manual-crawl/stop")
        async def api_manual_crawl_stop():
            """Stop the active manual crawl recorder and save JSON."""
            if not self.manual_crawl_session:
                return JSONResponse({"error": "manual crawl is not running"}, status_code=404)
            try:
                status = await self.manual_crawl_session.stop()
                await self.emit("manual_crawl_status", status)
                return JSONResponse(status)
            except Exception as exc:
                return JSONResponse({"error": str(exc)}, status_code=500)

        @app.get("/api/v1/manual-crawl/status")
        async def api_manual_crawl_status():
            if not self.manual_crawl_session:
                return JSONResponse({"running": False})
            return JSONResponse(self.manual_crawl_session.status())

        # ── Scan management portal: history, reports, downloads ───────────────

        @app.post("/api/v1/scan/abort")
        async def api_scan_abort():
            """Request the running scan to stop (saves a partial report)."""
            if not self.scan_in_progress:
                return JSONResponse(
                    {"error": "実行中のスキャンはありません。"}, status_code=409
                )
            self.command_queue.put_nowait("abort")
            return JSONResponse({"status": "aborting"})

        @app.get("/api/v1/scans")
        async def api_scans():
            """List all scans found under the output directory (history)."""
            return JSONResponse({"scans": self._list_scans()})

        @app.get("/api/v1/scans/{scan_id}/download")
        async def api_scan_download(scan_id: str):
            """Download a scan's whole artifact folder as a zip archive."""
            d = self._scan_dir(scan_id)
            if d is None or not d.is_dir():
                return JSONResponse({"error": "not found"}, status_code=404)

            def _iter_zip():
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                    for path in sorted(d.rglob("*")):
                        if path.is_file():
                            zf.write(path, arcname=path.relative_to(d.parent))
                buf.seek(0)
                yield from buf

            return StreamingResponse(
                _iter_zip(),
                media_type="application/zip",
                headers={
                    "Content-Disposition": f'attachment; filename="wscan-{scan_id}.zip"'
                },
            )

        @app.delete("/api/v1/scans/{scan_id}")
        async def api_scan_delete(scan_id: str):
            """Delete a scan's artifact folder."""
            if self.scan_in_progress and scan_id == self.current_scan_id:
                return JSONResponse(
                    {"error": "実行中のスキャンは削除できません。"}, status_code=409
                )
            d = self._scan_dir(scan_id)
            if d is None or not d.is_dir():
                return JSONResponse({"error": "not found"}, status_code=404)
            try:
                shutil.rmtree(d)
            except Exception as exc:
                return JSONResponse({"error": str(exc)}, status_code=500)
            return JSONResponse({"status": "deleted", "scan_id": scan_id})

        @app.get("/reports/{scan_id}/{file_path:path}")
        async def serve_report(scan_id: str, file_path: str = ""):
            """Serve report.html and its sibling assets straight from a scan's
            output folder so they can be viewed in the browser."""
            d = self._scan_dir(scan_id)
            if d is None or not d.is_dir():
                return JSONResponse({"error": "not found"}, status_code=404)
            rel = file_path or "report.html"
            target = (d / rel).resolve()
            # Path-traversal guard: the resolved path must stay inside the folder.
            try:
                target.relative_to(d.resolve())
            except ValueError:
                return JSONResponse({"error": "forbidden"}, status_code=403)
            if not target.is_file():
                return JSONResponse({"error": "not found"}, status_code=404)
            return FileResponse(str(target))

        return app

    # ------------------------------------------------------------------
    # Scan artifact / history helpers
    # ------------------------------------------------------------------

    def _scan_dir(self, scan_id: str) -> Optional[Path]:
        """Resolve a scan id to its output folder, rejecting path traversal."""
        if not scan_id or "/" in scan_id or "\\" in scan_id or scan_id in (".", ".."):
            return None
        d = (OUTPUT_BASE / scan_id).resolve()
        try:
            d.relative_to(OUTPUT_BASE.resolve())
        except ValueError:
            return None
        return d

    def _list_scans(self) -> list[dict]:
        """Index the output directory into a list of scan summaries."""
        scans: list[dict] = []
        if not OUTPUT_BASE.is_dir():
            return scans
        for d in OUTPUT_BASE.iterdir():
            if not d.is_dir():
                continue
            info: dict[str, Any] = {
                "id": d.name,
                "target": "",
                "started_at": "",
                "findings_count": 0,
                "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "report_available": (d / "report.html").is_file(),
                "status": "done",
                "size_bytes": 0,
            }
            # Prefer evidence.json (authoritative result), fall back to config.
            evidence = d / "evidence.json"
            cfg = d / "scan_config.json"
            try:
                if evidence.is_file():
                    data = json.loads(evidence.read_text(encoding="utf-8"))
                    info["target"] = data.get("target", "") or ""
                    info["started_at"] = data.get("scan_date", "") or ""
                    findings = data.get("findings", []) or []
                    info["findings_count"] = len(findings)
                    for f in findings:
                        sev = (f.get("severity") or "info").lower()
                        if sev in info["severity"]:
                            info["severity"][sev] += 1
                elif cfg.is_file():
                    data = json.loads(cfg.read_text(encoding="utf-8"))
                    info["target"] = (data.get("config", {}) or {}).get("url", "") or ""
                    info["started_at"] = data.get("submitted_at", "") or ""
            except Exception:
                pass
            if not info["started_at"]:
                try:
                    info["started_at"] = datetime.datetime.fromtimestamp(
                        d.stat().st_mtime
                    ).isoformat(timespec="seconds")
                except Exception:
                    info["started_at"] = ""
            # Running scan: no evidence yet but it is the active output folder.
            if self.scan_in_progress and d.name == self.current_scan_id:
                info["status"] = "scanning"
            elif not evidence.is_file() and not info["report_available"]:
                info["status"] = "incomplete"
            try:
                info["size_bytes"] = sum(
                    p.stat().st_size for p in d.rglob("*") if p.is_file()
                )
            except Exception:
                pass
            scans.append(info)
        # Newest first (timestamps sort lexicographically; fall back to mtime).
        scans.sort(key=lambda s: s["id"], reverse=True)
        return scans

    # ------------------------------------------------------------------
    # Login page
    # ------------------------------------------------------------------

    def _login_html(self, error: bool = False) -> str:
        """Render the standalone token-login page."""
        err_block = (
            '<p class="err">トークンが正しくありません。もう一度入力してください。</p>'
            if error else ""
        )
        return f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WScan — ログイン</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; min-height: 100vh; display: flex; align-items: center;
    justify-content: center; font-family: "Segoe UI", "Hiragino Sans", system-ui, sans-serif;
    background: radial-gradient(circle at 30% 20%, #1b2a4a 0%, #0b1220 60%, #070b14 100%);
    color: #e6edf6;
  }}
  .card {{
    width: min(380px, 92vw); padding: 36px 32px; border-radius: 16px;
    background: rgba(20, 30, 50, 0.85); border: 1px solid rgba(120, 160, 220, 0.25);
    box-shadow: 0 24px 60px rgba(0, 0, 0, 0.45); backdrop-filter: blur(6px);
  }}
  .brand {{ display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }}
  .brand .dot {{ width: 12px; height: 12px; border-radius: 50%;
    background: #4fd1c5; box-shadow: 0 0 12px #4fd1c5; }}
  h1 {{ font-size: 1.4rem; margin: 0; letter-spacing: 0.5px; }}
  p.sub {{ margin: 4px 0 24px; color: #93a4bd; font-size: 0.86rem; }}
  label {{ display: block; font-size: 0.8rem; color: #b9c6da; margin-bottom: 8px; }}
  input[type=password] {{
    width: 100%; padding: 12px 14px; border-radius: 10px; font-size: 1rem;
    border: 1px solid rgba(120, 160, 220, 0.3); background: #0d1626; color: #e6edf6;
    outline: none; transition: border-color 0.15s, box-shadow 0.15s;
  }}
  input[type=password]:focus {{ border-color: #4fd1c5; box-shadow: 0 0 0 3px rgba(79, 209, 197, 0.2); }}
  button {{
    margin-top: 20px; width: 100%; padding: 12px; border: 0; border-radius: 10px;
    font-size: 1rem; font-weight: 600; cursor: pointer; color: #052018;
    background: linear-gradient(135deg, #4fd1c5, #3aa6e0);
  }}
  button:hover {{ filter: brightness(1.08); }}
  .err {{ color: #ff9b9b; font-size: 0.84rem; margin: 14px 0 0; }}
  .foot {{ margin-top: 22px; font-size: 0.72rem; color: #6f7f97; text-align: center; }}
</style>
</head>
<body>
  <form class="card" method="post" action="/login">
    <div class="brand"><span class="dot"></span><h1>WScan</h1></div>
    <p class="sub">Web Security Scanner — イントラネット版</p>
    <label for="token">アクセストークン</label>
    <input id="token" name="token" type="password" autofocus autocomplete="current-password"
           placeholder="共有トークンを入力">
    {err_block}
    <button type="submit">ログイン</button>
    <div class="foot">権限のある担当者のみ利用してください。</div>
  </form>
</body>
</html>"""

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
            # Serve mode: dashboard submits full scan config. Ignore the request
            # if a scan is already running so it is not silently dropped when the
            # persistent loop next clears the event.
            if self.scan_in_progress or self.scan_request_event.is_set():
                # Notify the client without disturbing the in-progress scan's status.
                try:
                    asyncio.get_running_loop().create_task(
                        self.emit("scan_rejected", {
                            "message": "スキャンが既に実行中です。完了後に再試行してください。",
                        })
                    )
                except RuntimeError:
                    pass
                return
            self.scan_request_data = msg.get("config", {})
            self.api_scan_id = str(int(time.time()))
            self.api_scan_status = "scanning"
            self.api_findings = []
            self.api_report_path = None
            self.scan_request_event.set()

        elif action == "crawl_review":
            # User reviewed crawl results. command: continue|recrawl|cancel
            # Optional extra_urls (list[str]) and manual_crawl_file (str) are
            # consumed by the engine on resume.
            self.crawl_review_action = {
                "command": msg.get("command", "continue"),
                "extra_urls": msg.get("extra_urls", []) or [],
                "manual_crawl_file": msg.get("manual_crawl_file", "") or "",
                # Manual attack scenarios built in the dashboard scenario editor.
                "flows": msg.get("flows", []) or [],
            }
            self.crawl_review_event.set()

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
        dead = set()
        for client in list(self.clients):
            try:
                await client.send_text(json.dumps(event))
            except Exception:
                dead.add(client)
        self.clients -= dead

    async def emit_status(self, message: str, state: str = "running"):
        # D: CI/CD API — ステータス自動更新
        if state == "done":
            self.api_scan_status = "done"
        elif state == "error":
            self.api_scan_status = "error"
        elif state == "running" and self.api_scan_status == "idle":
            self.api_scan_status = "scanning"
        await self.emit("status", {"message": message, "state": state})

    async def emit_finding(self, finding: dict):
        # D: CI/CD API — findings を自動蓄積
        self.api_findings.append(finding)
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
        fast_mode: bool = False,
    ):
        """Send scan configuration to the dashboard so it can render dynamic badges."""
        await self.emit("scan_config", {
            "url": url,
            "checks": checks,
            "depth": depth,
            "concurrency": concurrency,
            "timeout": timeout,
            "fast_mode": fast_mode,
        })

    async def emit_awaiting_config(self):
        """Tell the dashboard to show the scan configuration form (serve mode)."""
        await self.emit("awaiting_config", {})

    async def emit_scan_started(self, config: dict):
        """Tell the dashboard the scan has started with the given config."""
        await self.emit("scan_started", config)

    async def emit_page_start(self, url: str):
        await self.emit("page_start", {"url": url})

    async def emit_page_graph_update(
        self,
        url: str,
        parent: str = "",
        depth: int = 0,
        forms: int = 0,
        inputs: int = 0,
        params: int = 0,
        status: str = "done",
        via: dict = None,
        screenshot_b64: str = "",
    ):
        """Emit a crawl graph node for the live screen-transition map.

        ``via`` describes the element on the parent page that led here
        ({text, selector, rect, viewport}); ``screenshot_b64`` is the page
        thumbnail. Both power the click-location / screenshot views.
        """
        await self.emit("page_graph_update", {
            "url": url,
            "parent": parent,
            "depth": depth,
            "forms": forms,
            "inputs": inputs,
            "params": params,
            "status": status,
            "via": via,
            "screenshot_b64": screenshot_b64,
        })

    async def emit_payload_test(self, field: str, payload: str, check_type: str, url: str = "") -> None:
        if self.request_logger is not None:
            self.request_logger.log_payload(field, payload, check_type, url)
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

    async def emit_scan_gap(
        self,
        url: str,
        field_name: str = "(page)",
        check: str = "access",
        location: str = "navigation",
        note: str = "",
    ) -> None:
        """Emit a target/input that could not be tested."""
        await self.emit("scan_gap", {
            "url": url,
            "field_name": field_name,
            "check": check,
            "location": location,
            "note": note,
        })

    async def emit_plan_review(self, plans_data: list):
        """
        Send plan data to the dashboard for operator review/edit.
        The dashboard will show the plan modal and wait for the operator
        to click 'Start Attack'.
        """
        self.plan_confirm_event.clear()
        await self.emit("plan_review", {"plans": plans_data})

    async def emit_crawl_review(self, pages_data: list):
        """
        Send the list of pages discovered by the crawl phase to the dashboard
        so the operator can confirm coverage, request a re-crawl, or merge a
        manual-crawl JSON before the attack phase begins.
        """
        self.crawl_review_event.clear()
        self.crawl_review_action = {}
        await self.emit("crawl_review", {"pages": pages_data})

    async def wait_for_crawl_review(self, timeout: float = 1800.0) -> dict:
        """Block until the operator clicks a button in the crawl review modal."""
        try:
            await asyncio.wait_for(self.crawl_review_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            await self.emit_status(
                f"[warn] Crawl review timed out after {timeout:.0f}s — "
                "continuing with current crawl results.",
                "warning",
            )
            return {"command": "continue"}
        return dict(self.crawl_review_action)

    async def emit_intervention_state(self, paused: bool):
        """Tell the dashboard whether the scan is paused."""
        await self.emit("intervention_state", {"paused": paused})

    # ------------------------------------------------------------------
    # Blocking wait helpers (called from engine coroutine)
    # ------------------------------------------------------------------

    async def wait_for_plan_confirm(self, timeout: float = 600.0) -> dict:
        """
        Block until the operator clicks 'Start Attack' in the web UI.
        If *timeout* elapses without confirmation, a warning is emitted and
        the method returns without auto-starting the scan (callers should
        treat an empty dict with plan_confirm_event not set as "not confirmed").
        Returns the edits dict (may be empty if no changes were made or
        if the operator did not confirm within the timeout).
        """
        try:
            await asyncio.wait_for(
                self.plan_confirm_event.wait(),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            await self.emit_status(
                f"[warn] Plan confirm timed out after {timeout:.0f}s — "
                "operator confirmation required to start the scan.",
                "warning",
            )
        return self.confirmed_plan_edits
