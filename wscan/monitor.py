"""
WScan Monitor Server
FastAPI + WebSocket server for real-time scan monitoring dashboard.
"""
import asyncio
import collections
import datetime
import hashlib
import json
import os
import secrets
import shutil
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Set, Any, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    FileResponse,
    RedirectResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from starlette.background import BackgroundTask


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


def select_scans_to_prune(
    scans: list,
    *,
    max_age_days: float = 0,
    max_scans: int = 0,
    now_epoch: Optional[float] = None,
    protected_ids: Optional[set] = None,
) -> list:
    """保持ポリシーに基づき「削除対象スキャンの id」を返す純粋関数。

    - ``max_age_days > 0`` … 経過日数がこれを超えるスキャンを削除対象にする。
    - ``max_scans   > 0`` … 新しい順に ``max_scans`` 件を残し、超過分を削除対象にする。
    - ``protected_ids``   … 実行中スキャン等、決して削除しない id の集合。
    値が 0/未設定のポリシーは無効（＝何も削除しない。後方互換のため既定で無効）。

    ``scans`` の各要素は ``{"id", "started_at"}`` を持つ想定。スキャン id が
    数値(エポック秒)ならそれを、そうでなければ ``started_at`` の ISO 文字列を
    時刻として用いる。FS/HTTP に依存しないためテスト容易。
    """
    if now_epoch is None:
        now_epoch = time.time()
    protected = {str(p) for p in (protected_ids or set())}

    def _epoch(s) -> Optional[float]:
        sid = str(s.get("id", ""))
        if sid.isdigit():
            return float(sid)
        ts = s.get("started_at") or ""
        try:
            return datetime.datetime.fromisoformat(ts).timestamp()
        except Exception:
            return None

    ordered = sorted(scans, key=lambda s: (_epoch(s) or 0.0), reverse=True)  # newest first
    doomed: set = set()

    if max_age_days and max_age_days > 0:
        cutoff = now_epoch - max_age_days * 86400
        for s in ordered:
            e = _epoch(s)
            if e is not None and e < cutoff:
                doomed.add(str(s.get("id", "")))

    if max_scans and max_scans > 0:
        for s in ordered[int(max_scans):]:
            doomed.add(str(s.get("id", "")))

    doomed -= protected
    doomed.discard("")
    return [str(s.get("id", "")) for s in ordered if str(s.get("id", "")) in doomed]


def _host_of(url: str) -> str:
    try:
        # DNS 末尾ドット（"example.com."）は "example.com" と同一ホストなので
        # 正規化しておく。これを残すと deny/allow 照合を末尾ドットで回避できる。
        return (urlparse(url).hostname or "").lower().rstrip(".")
    except Exception:
        return ""


def target_in_scope(url: str, allowed: list, denied: list) -> bool:
    """対象URLのホストがスキャン許可スコープ内かを判定する純粋関数。

    - denied に一致（完全一致 or サブドメイン）すれば常に拒否。
    - allowed が非空なら、そのいずれかに一致するホストのみ許可。
    - allowed が空なら（denied 以外は）許可。
    共有サーバーで範囲外/内部資産への誤爆・悪用を防ぐためのガード。
    """
    host = _host_of(url)
    if not host:
        return False
    for d in (denied or []):
        d = (d or "").lower().strip().strip(".")
        if d and (host == d or host.endswith("." + d)):
            return False
    allow = [(a or "").lower().strip().strip(".") for a in (allowed or []) if (a or "").strip()]
    if allow:
        return any(host == a or host.endswith("." + a) for a in allow)
    return True


def due_schedule_ids(schedules: list, now_epoch: Optional[float] = None) -> list:
    """実行すべき（有効かつ next_run <= 現在）スケジュール id を返す純粋関数。"""
    if now_epoch is None:
        now_epoch = time.time()
    out = []
    for s in schedules or []:
        if not s.get("enabled", True):
            continue
        try:
            nxt = float(s.get("next_run", 0) or 0)
        except (TypeError, ValueError):
            nxt = 0
        if nxt <= now_epoch:
            out.append(str(s.get("id", "")))
    return [i for i in out if i]


class MonitorServer:
    """Real-time monitoring server for scan progress."""

    # 履歴の素朴な再生からは除外する一過性モーダルイベント。これらは
    # 「今まさに操作待ちかどうか」が本質で、解決後に再生すると亡霊モーダルになる。
    # 未解決の1件だけ pending_interactive 経由で別途送る。
    _REPLAY_SUPPRESS_TYPES = frozenset({"crawl_review", "plan_review", "awaiting_config"})

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
        # 「操作待ち」の一過性モーダルイベント（crawl_review / plan_review /
        # awaiting_config）は解決済みでも event_history に残る。これをそのまま
        # 再接続/リロード時に再生すると、解決済みのレビュー画面や次スキャン準備中の
        # 旧レビューが亡霊のように再表示される。そこで「現在まだ未解決の1件」だけを
        # ここで保持し、再生時は履歴から一過性モーダルを除外して本フィールドを末尾に
        # 1件だけ送る。None なら未解決のモーダルは無い。
        self.pending_interactive: Optional[dict] = None

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
        # 進捗のスナップショット（ポータルが /api/v1/scan/status でモニターを
        # 開かずに確認できるようにする）。emit_phase/emit_progress が更新。
        self.api_target: str = ""
        self.api_phase: str = ""             # crawl / plan / attack / report
        self.api_progress: dict = {"current": 0, "total": 0, "percent": 0}
        self.manual_crawl_session = None
        # 出力(output/)の保持ポリシー。0 = 無制限(既定・後方互換)。
        #   retention_days       … 経過日数を超えたスキャンを自動削除
        #   retention_max_scans  … 直近この件数のみ残し超過分を自動削除
        # serve 起動時とスキャン完了毎に prune_old_scans() が適用する。
        self.retention_days: float = 0
        self.retention_max_scans: int = 0
        # スキャン対象スコープ（共有サーバーでの誤爆・悪用防止）。0件なら無制限。
        self.allowed_target_hosts: list = []
        self.denied_target_hosts: list = []
        # ログイン失敗のレート制限（IP単位の総当たり対策）。
        self._login_fail: dict = {}
        # リバースプロキシ配下で実クライアントIPを X-Forwarded-For から取るか。
        # 既定 False（XFF は偽装可能なため、信頼できるプロキシ配下のときだけ有効化）。
        self.trust_proxy: bool = False
        # 監査ログ書き込み失敗を一度だけ警告するためのフラグ。
        self._audit_warned: bool = False
        # スキャンのウォッチドッグ（ハング対策。0=無効）。
        self.scan_max_seconds: float = 0
        self._scan_started_at: float = 0.0
        self._watchdog_fired: bool = False
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

    # ── Login brute-force throttling ──────────────────────────────────
    _LOGIN_MAX_FAILS = 5      # この回数失敗すると
    _LOGIN_WINDOW = 300       # この秒数だけロックアウト

    def _client_ip(self, request: Request) -> str:
        # 信頼できるプロキシ配下では X-Forwarded-For の先頭(=実クライアント)を使う。
        # これによりプロキシ配下で全利用者が同一IP扱いになりロックアウトが
        # 巻き添えになる問題を避ける。trust_proxy=False のときは偽装防止のため
        # ソケットの接続元IPのみを用いる。
        if self.trust_proxy:
            xff = request.headers.get("x-forwarded-for", "")
            if xff:
                first = xff.split(",")[0].strip()
                if first:
                    return first
        return (request.client.host if request.client else "") or "unknown"

    def _login_locked(self, ip: str) -> bool:
        now = time.time()
        fails = [t for t in self._login_fail.get(ip, []) if now - t < self._LOGIN_WINDOW]
        self._login_fail[ip] = fails
        return len(fails) >= self._LOGIN_MAX_FAILS

    def _record_login_fail(self, ip: str) -> None:
        self._login_fail.setdefault(ip, []).append(time.time())

    def _clear_login_fail(self, ip: str) -> None:
        self._login_fail.pop(ip, None)

    # ── Target scope (allow/deny) ─────────────────────────────────────
    def _scope_error(self, url: str) -> Optional[str]:
        """対象URLが許可スコープ外なら理由文字列、許可内なら None。"""
        if target_in_scope(url, self.allowed_target_hosts, self.denied_target_hosts):
            return None
        return f"対象ホストがスキャン許可スコープ外です: {_host_of(url) or url}"

    def _config_scope_error(self, config: dict) -> Optional[str]:
        """スキャン設定に含まれる全ての対象URLをスコープ検査する。

        url だけでなく target_urls / access_urls / login_url も対象。これらは
        エンジンが実際にアクセス/攻撃するため、in-scope の url を指定しつつ
        ここに範囲外ホストを混ぜる回避を防ぐ。
        """
        if not (self.allowed_target_hosts or self.denied_target_hosts):
            return None
        config = config or {}
        urls: list = []
        if config.get("url"):
            urls.append(config["url"])
        for key in ("target_urls", "access_urls"):
            v = config.get(key)
            if isinstance(v, str):
                urls += [u.strip() for u in v.replace(",", "\n").splitlines() if u.strip()]
            elif isinstance(v, (list, tuple)):
                urls += [str(u).strip() for u in v if str(u).strip()]
        if config.get("login_url"):
            urls.append(config["login_url"])
        # 攻撃フロー/シナリオの navigate 先もブラウザが実際に開くため検査対象。
        # in-scope の url を指定しつつ、フローで範囲外へ navigate する回避を防ぐ。
        urls += self._flow_nav_urls(config.get("flows"))
        for u in urls:
            err = self._scope_error(u)
            if err:
                return err
        return None

    @staticmethod
    def _flow_nav_urls(flows) -> list:
        """フロー定義から navigate 系ステップの URL を抽出する。"""
        out: list = []
        for flow in (flows or []):
            if not isinstance(flow, dict):
                continue
            for step in (flow.get("steps") or []):
                if not isinstance(step, dict):
                    continue
                if step.get("action") in ("navigate", "goto") and step.get("url"):
                    out.append(str(step["url"]))
        return out

    # ── Scan watchdog (hang protection) ───────────────────────────────
    def mark_scan_started(self) -> None:
        """スキャン開始時刻を記録し watchdog をリセットする。"""
        self._scan_started_at = time.time()
        self._watchdog_fired = False

    def watchdog_check(self) -> bool:
        """実行中スキャンが上限時間を超えていたら一度だけ abort を要求する。

        ブラウザのハング等で完了しないスキャンを自動停止し、serve を次の
        スキャンへ進ませる。``scan_max_seconds`` が 0 のときは無効。
        """
        if not (self.scan_max_seconds and self.scan_in_progress and self._scan_started_at):
            return False
        if self._watchdog_fired:
            return False
        if time.time() - self._scan_started_at > self.scan_max_seconds:
            self._watchdog_fired = True
            try:
                self.command_queue.put_nowait("abort")
            except Exception:
                pass
            return True
        return False

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
            ip = self._client_ip(request)
            if self._login_locked(ip):
                return HTMLResponse(self._login_html(locked=True), status_code=429)
            form = await request.form()
            token = (form.get("token") or "").strip()
            if self._token_ok(token):
                self._clear_login_fail(ip)
                resp = RedirectResponse(url="/", status_code=303)
                resp.set_cookie(
                    SESSION_COOKIE,
                    self._session_value,
                    httponly=True,
                    samesite="lax",
                    max_age=60 * 60 * 12,  # 12 hours
                )
                return resp
            self._record_login_fail(ip)
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
            # Send event history to newly connected client.
            # 一過性モーダル(crawl_review/plan_review/awaiting_config)は素朴に
            # 再生せず除外し、未解決の1件だけを末尾に送る（亡霊モーダル防止）。
            try:
                for event in list(self.event_history)[-200:]:
                    if event.get("type") in self._REPLAY_SUPPRESS_TYPES:
                        continue
                    await ws.send_text(json.dumps(event))
                if self.pending_interactive is not None:
                    await ws.send_text(json.dumps(self.pending_interactive))
                # Keep connection alive and process incoming messages
                while True:
                    try:
                        raw = await asyncio.wait_for(ws.receive_text(), timeout=30)
                        ws_ip = (ws.client.host if ws.client else "") or "ws"
                        self._handle_client_message(raw, ws_ip)
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

        @app.get("/api/v1/settings")
        async def api_get_settings():
            """通知設定を返す（Webhook URL はマスクして返す）。"""
            n = self._notify_settings()
            return JSONResponse({
                "notifications": {
                    "enabled": n["enabled"],
                    "min_severity": n["min_severity"],
                    "notify_complete": n["notify_complete"],
                    "webhook_set": bool(n["webhook_url"]),
                    "webhook_hint": self._mask_secret(n["webhook_url"]),
                }
            })

        @app.post("/api/v1/settings")
        async def api_set_settings(request: Request):
            """通知設定を更新する。webhook_url 未指定なら既存値を保持。"""
            try:
                body = await request.json()
            except Exception:
                return JSONResponse({"error": "Invalid JSON"}, status_code=400)
            n = body.get("notifications") or {}
            cur = self._notify_settings()
            new_url = n.get("webhook_url", None)
            if new_url is None:
                new_url = cur["webhook_url"]  # 未指定 → 既存維持
            new_url = str(new_url).strip()
            min_sev = str(n.get("min_severity", cur["min_severity"]) or "high")
            if min_sev not in ("critical", "high", "medium", "low"):
                min_sev = "high"
            settings = self._load_settings()
            settings["notifications"] = {
                "webhook_url": new_url,
                "min_severity": min_sev,
                "notify_complete": bool(n.get("notify_complete", cur["notify_complete"])),
                "enabled": bool(n.get("enabled", cur["enabled"])),
            }
            try:
                self._save_settings(settings)
            except Exception as exc:
                return JSONResponse({"error": f"保存に失敗しました: {exc}"}, status_code=500)
            self._audit("settings_update", self._client_ip(request),
                        f"webhook_set={bool(new_url)} enabled={settings['notifications']['enabled']}")
            return JSONResponse({"status": "ok"})

        @app.post("/api/v1/settings/test")
        async def api_test_notification():
            """現在の通知設定でテスト通知を送信する。"""
            cfg = self._notify_settings()
            if not cfg["webhook_url"]:
                return JSONResponse({"error": "Webhook URL が未設定です。"}, status_code=400)
            try:
                from wscan.notification import NotificationManager
                mgr = NotificationManager(
                    webhook_url=cfg["webhook_url"],
                    min_severity=cfg["min_severity"],
                    notify_complete=True,
                )
                await mgr.notify_scan_complete(
                    {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
                    target_url="(WScan テスト通知)",
                )
                return JSONResponse({"status": "sent"})
            except Exception as exc:
                return JSONResponse({"error": str(exc)}, status_code=500)

        @app.get("/api/v1/schedules")
        async def api_get_schedules():
            """登録済みの定期スキャンを一覧で返す。"""
            return JSONResponse({"schedules": self.list_schedules()})

        @app.post("/api/v1/schedules")
        async def api_add_schedule(request: Request):
            """定期スキャンを登録する。Body: {url, checks?, depth?, interval_hours}"""
            try:
                body = await request.json()
            except Exception:
                return JSONResponse({"error": "Invalid JSON"}, status_code=400)
            url = (body.get("url") or "").strip()
            if not url:
                return JSONResponse({"error": "url is required"}, status_code=400)
            try:
                interval = float(body.get("interval_hours", 24) or 24)
            except (TypeError, ValueError):
                interval = 24
            if interval <= 0:
                return JSONResponse({"error": "interval_hours must be > 0"}, status_code=400)
            checks = body.get("checks") or []
            if isinstance(checks, str):
                checks = [c.strip() for c in checks.replace(",", " ").split() if c.strip()]
            sched = self.add_schedule(url, checks, int(body.get("depth", 2) or 2), interval)
            self._audit("schedule_add", self._client_ip(request), f"{url} ({interval}h)")
            return JSONResponse({"status": "ok", "schedule": sched})

        @app.post("/api/v1/schedules/{sched_id}/toggle")
        async def api_toggle_schedule(sched_id: str, request: Request):
            s = self.toggle_schedule(sched_id)
            if s is None:
                return JSONResponse({"error": "not found"}, status_code=404)
            self._audit("schedule_toggle", self._client_ip(request),
                        f"{s.get('url','')} enabled={s.get('enabled')}")
            return JSONResponse({"status": "ok", "schedule": s})

        @app.delete("/api/v1/schedules/{sched_id}")
        async def api_delete_schedule(sched_id: str, request: Request):
            if not self.delete_schedule(sched_id):
                return JSONResponse({"error": "not found"}, status_code=404)
            self._audit("schedule_delete", self._client_ip(request), sched_id)
            return JSONResponse({"status": "deleted", "id": sched_id})

        @app.get("/api/v1/audit")
        async def api_get_audit():
            """管理操作の監査ログ（末尾200件、新しい順）を返す。"""
            return JSONResponse({"audit": self.read_audit(200)})

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
                    openai_base_url=cfg.get("openai_base_url", "") or "",
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

            scope_err = self._config_scope_error(config)
            if scope_err:
                return JSONResponse({"error": scope_err}, status_code=403)

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
            self.api_target = config.get("url", "") or ""
            self.api_phase = ""
            self.api_progress = {"current": 0, "total": 0, "percent": 0}
            self._audit("scan_start", self._client_ip(request), config.get("url", ""))
            return JSONResponse({
                "status": "accepted",
                "scan_id": self.api_scan_id,
                "message": "スキャンを開始しました。/api/v1/scan/status でステータスを確認してください。",
            })

        @app.get("/api/v1/scan/status")
        async def api_scan_status():
            """スキャンステータスを返す（進捗・フェーズ・対象を含む）。"""
            return JSONResponse({
                "status": self.api_scan_status,
                "scan_id": self.api_scan_id,
                "findings_count": len(self.api_findings),
                "target": self.api_target,
                "phase": self.api_phase,
                "progress": self.api_progress,
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
            scope_err = self._scope_error(url)
            if scope_err:
                return JSONResponse({"error": scope_err}, status_code=403)
            output_path = (body.get("output_path") or "flows/manual_crawl.json").strip()
            headless = bool(body.get("headless", False))
            proxy = (body.get("proxy") or "").strip()
            # stream=True … サーバ上のヘッドレス Chromium を画面配信し、
            # ダッシュボードから座標入力で遠隔操作するモード。
            stream = bool(body.get("stream", False))

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
                    stream=stream,
                    frame_callback=self._emit_manual_crawl_frame if stream else None,
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

        @app.post("/api/v1/manual-crawl/import")
        async def api_manual_crawl_import(request: Request):
            """手入力の URL リストを巡回シード JSON として保存する。

            サーバ/ヘッドレス環境では可視ブラウザを利用者が操作できないため、
            手元で控えた URL を貼り付けてシード化する代替経路を提供する。
            """
            try:
                body = await request.json()
            except Exception:
                return JSONResponse({"error": "Invalid JSON"}, status_code=400)

            from wscan.manual_crawl import (
                parse_url_list,
                build_seed_payload,
                save_seed_payload,
            )

            start_url = (body.get("url") or body.get("start_url") or "").strip()
            urls = parse_url_list(body.get("urls") or body.get("text") or "")
            if not urls:
                return JSONResponse(
                    {"error": "http(s) で始まる URL を1件以上入力してください"},
                    status_code=400,
                )
            # スコープ外 URL は弾く（start_url 指定時はそれも検査）。
            for candidate in ([start_url] if start_url else []) + urls:
                scope_err = self._scope_error(candidate)
                if scope_err:
                    return JSONResponse({"error": scope_err}, status_code=403)

            output_path = (body.get("output_path") or "flows/manual_crawl.json").strip()
            # 取込 URL はすべて _scope_error で検証済み。seed 正規化が start_url の
            # 同一オリジンだけに絞って許可ホストの URL を落とさないよう、許可スコープ
            # （未設定時は取込 URL のホスト集合）を渡す。
            seed_scopes = self.allowed_target_hosts or list(
                {h for h in (_host_of(u) for u in urls) if h}
            )
            try:
                payload = build_seed_payload(
                    start_url or urls[0], urls, allowed_scopes=seed_scopes
                )
                saved = save_seed_payload(output_path, payload)
            except Exception as exc:
                return JSONResponse({"error": str(exc)}, status_code=500)

            status = {
                "running": False,
                "imported": True,
                "output_path": str(saved),
                "url_count": len(payload.get("seed_urls", [])),
                "step_count": 0,
                "urls": payload.get("seed_urls", [])[-20:],
            }
            await self.emit("manual_crawl_status", status)
            return JSONResponse(status)

        # ── Scan management portal: history, reports, downloads ───────────────

        @app.post("/api/v1/scan/abort")
        async def api_scan_abort(request: Request):
            """Request the running scan to stop (saves a partial report)."""
            if not self.scan_in_progress:
                return JSONResponse(
                    {"error": "実行中のスキャンはありません。"}, status_code=409
                )
            self.command_queue.put_nowait("abort")
            self._audit("scan_abort", self._client_ip(request), self.current_scan_id)
            return JSONResponse({"status": "aborting"})

        @app.get("/api/v1/scans")
        async def api_scans():
            """List all scans found under the output directory (history)."""
            scans = self._list_scans()
            return JSONResponse({
                "scans": scans,
                "storage": self.storage_summary(scans),
            })

        @app.post("/api/v1/scans/prune")
        async def api_scans_prune(request: Request):
            """保持ポリシーを今すぐ適用して古いスキャンを削除する（手動整理）。"""
            pruned = self.prune_old_scans()
            self._audit("scans_prune", self._client_ip(request), f"{len(pruned)} 件")
            return JSONResponse({
                "status": "ok",
                "pruned": pruned,
                "pruned_count": len(pruned),
                "storage": self.storage_summary(),
            })

        @app.get("/api/v1/scans/{scan_id}/download")
        async def api_scan_download(scan_id: str):
            """Download a scan's whole artifact folder as a zip archive.

            アーカイブはメモリ上ではなく一時ファイルに構築してからストリーミングし、
            送信後に削除する。スクリーンショット多数の大規模スキャンでも RAM を
            圧迫しない。zip 構築はスレッドへ逃がしてイベントループを塞がない。
            """
            d = self._scan_dir(scan_id)
            if d is None or not d.is_dir():
                return JSONResponse({"error": "not found"}, status_code=404)

            def _build_zip() -> str:
                fd, tmp_path = tempfile.mkstemp(prefix=f"wscan-{scan_id}-", suffix=".zip")
                os.close(fd)
                with zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as zf:
                    for path in sorted(d.rglob("*")):
                        if path.is_file():
                            zf.write(path, arcname=path.relative_to(d.parent))
                return tmp_path

            try:
                tmp_path = await asyncio.to_thread(_build_zip)
            except Exception as exc:
                return JSONResponse({"error": f"zip 生成に失敗しました: {exc}"}, status_code=500)

            def _cleanup() -> None:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

            return FileResponse(
                tmp_path,
                media_type="application/zip",
                filename=f"wscan-{scan_id}.zip",
                background=BackgroundTask(_cleanup),
            )

        @app.get("/api/v1/scans/{scan_id}/diff")
        async def api_scan_diff(scan_id: str):
            """同一対象の「前回スキャン」との差分（新規/修正済み/継続）を返す。"""
            d = self._scan_dir(scan_id)
            if d is None or not d.is_dir():
                return JSONResponse({"error": "not found"}, status_code=404)
            from wscan.diff_scan import load_previous, diff as _diff

            scans = self._list_scans()
            cur = next((s for s in scans if s["id"] == scan_id), None)
            target = (cur or {}).get("target", "")
            # 同一対象で、この scan より前(=id が小さい)・evidence ありの最新を探す。
            prev = None
            for s in sorted(scans, key=lambda x: x["id"], reverse=True):
                if s["id"] >= scan_id or not s.get("json_available"):
                    continue
                if target and s.get("target") != target:
                    continue
                prev = s
                break
            if prev is None:
                return JSONResponse(
                    {"error": "比較対象（同一対象の前回スキャン）が見つかりません。", "target": target},
                    status_code=404,
                )
            new = load_previous(str(d))
            prev_dir = self._scan_dir(prev["id"])
            old = load_previous(str(prev_dir)) if prev_dir else []
            result = _diff(old, new)
            return JSONResponse({
                "scan_id": scan_id,
                "previous_id": prev["id"],
                "target": target,
                **result.to_dict(),
            })

        @app.delete("/api/v1/scans/{scan_id}")
        async def api_scan_delete(scan_id: str, request: Request):
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
            self._audit("scan_delete", self._client_ip(request), scan_id)
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
                "sarif_available": (d / "report.sarif").is_file(),
                "json_available": (d / "evidence.json").is_file(),
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

    def storage_summary(self, scans: Optional[list] = None) -> dict:
        """output/ の合計サイズ・件数・保持ポリシーを返す（ポータル表示用）。"""
        if scans is None:
            scans = self._list_scans()
        total = sum(int(s.get("size_bytes") or 0) for s in scans)
        return {
            "total_bytes": total,
            "scan_count": len(scans),
            "retention_days": self.retention_days,
            "retention_max_scans": self.retention_max_scans,
        }

    def prune_old_scans(self) -> list:
        """保持ポリシーに従い古いスキャンの成果物フォルダを削除し、削除した id を返す。

        ポリシー未設定（いずれも 0）なら何もしない。実行中スキャンは保護する。
        """
        if not (self.retention_days or self.retention_max_scans):
            return []
        protected = set()
        if self.scan_in_progress and self.current_scan_id:
            protected.add(self.current_scan_id)
        ids = select_scans_to_prune(
            self._list_scans(),
            max_age_days=self.retention_days,
            max_scans=self.retention_max_scans,
            protected_ids=protected,
        )
        pruned: list = []
        for sid in ids:
            d = self._scan_dir(sid)
            if d is None or not d.is_dir():
                continue
            try:
                shutil.rmtree(d)
                pruned.append(sid)
            except Exception:
                pass
        return pruned

    # ------------------------------------------------------------------
    # Server settings (notifications) — persisted as a FILE under output/ so it
    # survives restarts (output is the mounted volume) and is never listed as a
    # scan (._list_scans only iterates directories).
    # ------------------------------------------------------------------

    def _settings_path(self) -> Path:
        return OUTPUT_BASE / "wscan_settings.json"

    # ------------------------------------------------------------------
    # Management audit log (who did what, from where) — JSONL file under
    # output/. 共有サーバーで start/abort/delete/設定変更 等の操作を追跡する。
    # ------------------------------------------------------------------

    def _audit_path(self) -> Path:
        return OUTPUT_BASE / "management_audit.jsonl"

    def _audit(self, action: str, ip: str = "", detail: str = "") -> None:
        """管理操作を 1 行 JSONL で追記する（失敗しても本処理は止めない）。"""
        try:
            OUTPUT_BASE.mkdir(parents=True, exist_ok=True)
            entry = {
                "ts": datetime.datetime.now().isoformat(timespec="seconds"),
                "ip": ip or "",
                "action": action,
                "detail": str(detail)[:300],
            }
            with open(self._audit_path(), "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as exc:
            # 監査はセキュリティ機能なので失敗を黙殺しない（最初の失敗を一度警告）。
            if not self._audit_warned:
                self._audit_warned = True
                print(f"[wscan] 監査ログの書き込みに失敗しています: {exc}")

    def read_audit(self, limit: int = 200) -> list:
        """監査ログの末尾 limit 件を新しい順で返す。"""
        p = self._audit_path()
        if not p.is_file():
            return []
        try:
            lines = p.read_text(encoding="utf-8").splitlines()
        except Exception:
            return []
        out = []
        for ln in lines[-limit:]:
            ln = ln.strip()
            if not ln:
                continue
            try:
                out.append(json.loads(ln))
            except Exception:
                continue
        out.reverse()
        return out

    def _load_settings(self) -> dict:
        p = self._settings_path()
        if not p.is_file():
            return {}
        try:
            return json.loads(p.read_text(encoding="utf-8")) or {}
        except Exception:
            # 破損していたら握り潰さず .corrupt へ退避してログする（次回は空で再生成）。
            try:
                backup = p.with_suffix(".json.corrupt")
                p.replace(backup)
                print(f"[wscan] 設定ファイルが壊れていたため {backup.name} へ退避しました。")
            except Exception:
                pass
            return {}

    def _save_settings(self, data: dict) -> None:
        """設定を atomic に書き出す（一時ファイル→fsync→os.replace）。

        直書きだと書き込み途中のクラッシュでファイルが壊れ、通知設定や
        スケジュールが丸ごと失われる。同一ディレクトリの一時ファイルへ書いて
        fsync 後に置換することで、常に「旧 or 新」のどちらか完全な状態を保つ。
        書き込みは serve の単一イベントループ内で同期実行されるため逐次化される。
        """
        OUTPUT_BASE.mkdir(parents=True, exist_ok=True)
        target = self._settings_path()
        tmp = target.with_suffix(".json.tmp")
        payload = json.dumps(data, ensure_ascii=False, indent=2)
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)

    def _notify_settings(self) -> dict:
        n = (self._load_settings().get("notifications") or {})
        return {
            "webhook_url": str(n.get("webhook_url", "") or ""),
            "min_severity": str(n.get("min_severity", "high") or "high"),
            "notify_complete": bool(n.get("notify_complete", True)),
            "enabled": bool(n.get("enabled", True)),
        }

    @staticmethod
    def _mask_secret(s: str) -> str:
        s = s or ""
        if len(s) <= 8:
            return "••••" if s else ""
        return s[:8] + "…" + s[-4:]

    async def send_scan_complete_notification(self) -> None:
        """ポータルで設定された Webhook へスキャン完了通知を送る（serve モード）。"""
        cfg = self._notify_settings()
        if not (cfg["enabled"] and cfg["webhook_url"]):
            return
        try:
            from wscan.notification import NotificationManager
            mgr = NotificationManager(
                webhook_url=cfg["webhook_url"],
                min_severity=cfg["min_severity"],
                notify_complete=cfg["notify_complete"],
            )
            sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in self.api_findings:
                s = (f.get("severity") or "").lower()
                if s in sev:
                    sev[s] += 1
            summary = {"total": len(self.api_findings), **sev}
            await mgr.notify_scan_complete(
                summary,
                target_url=self.api_target,
                report_path=self.api_report_path or "",
            )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Scheduled (recurring) scans
    # ------------------------------------------------------------------

    def request_scan(self, config: dict) -> bool:
        """スキャンを serve ループへ投入する。実行中/投入済みなら False。

        ダッシュボード/API の開始処理と同じ状態セットを行うため、スケジューラ
        からも一貫した形でスキャンを起動できる。
        """
        if self.scan_in_progress or self.scan_request_event.is_set():
            return False
        self.scan_request_data = dict(config or {})
        self.api_scan_id = str(int(time.time()))
        self.api_scan_status = "scanning"
        self.api_findings = []
        self.api_report_path = None
        self.api_target = (config or {}).get("url", "") or ""
        self.api_phase = ""
        self.api_progress = {"current": 0, "total": 0, "percent": 0}
        self.scan_request_event.set()
        return True

    def list_schedules(self) -> list:
        return list(self._load_settings().get("schedules") or [])

    def _write_schedules(self, schedules: list) -> None:
        settings = self._load_settings()
        settings["schedules"] = schedules
        self._save_settings(settings)

    def add_schedule(self, url: str, checks: list, depth: int, interval_hours: float) -> dict:
        now = time.time()
        sched = {
            "id": str(int(now * 1000)),  # ミリ秒で一意化
            "url": url,
            "checks": checks or [],
            "depth": int(depth or 2),
            "interval_hours": float(interval_hours or 24),
            "enabled": True,
            "created_at": now,
            "last_run": 0,
            "next_run": now,  # 次のスケジューラ tick で実行
        }
        schedules = self.list_schedules()
        schedules.append(sched)
        self._write_schedules(schedules)
        return sched

    def delete_schedule(self, sched_id: str) -> bool:
        schedules = self.list_schedules()
        kept = [s for s in schedules if str(s.get("id")) != str(sched_id)]
        if len(kept) == len(schedules):
            return False
        self._write_schedules(kept)
        return True

    def toggle_schedule(self, sched_id: str) -> Optional[dict]:
        schedules = self.list_schedules()
        found = None
        for s in schedules:
            if str(s.get("id")) == str(sched_id):
                s["enabled"] = not s.get("enabled", True)
                found = s
                break
        if found is None:
            return None
        self._write_schedules(schedules)
        return found

    def trigger_due_schedules(self) -> Optional[str]:
        """期限到来のスケジュールが1件あればスキャンを起動し、その id を返す。

        serve は同時1スキャンのため、起動するのは1件のみ（残りは次 tick）。
        起動できなければ（実行中/期限未到来）None。
        """
        if self.scan_in_progress or self.scan_request_event.is_set():
            return None
        schedules = self.list_schedules()
        now = time.time()
        due = due_schedule_ids(schedules, now)
        if not due:
            return None
        target_id = due[0]
        for s in schedules:
            if str(s.get("id")) == target_id:
                cfg = {
                    "url": s.get("url", ""),
                    "checks": s.get("checks") or [],
                    "depth": int(s.get("depth", 2)),
                }
                # スコープ外になった対象は起動せず、次回まで送る（無限ループ防止に
                # next_run は前進させる）。
                if self._config_scope_error(cfg):
                    s["last_run"] = now
                    s["next_run"] = now + float(s.get("interval_hours", 24) or 24) * 3600
                    self._write_schedules(schedules)
                    return None
                if not self.request_scan(cfg):
                    return None
                s["last_run"] = now
                s["next_run"] = now + float(s.get("interval_hours", 24) or 24) * 3600
                self._write_schedules(schedules)
                return target_id
        return None

    # ------------------------------------------------------------------
    # Login page
    # ------------------------------------------------------------------

    def _login_html(self, error: bool = False, locked: bool = False) -> str:
        """Render the standalone token-login page."""
        if locked:
            err_block = (
                '<p class="err">試行回数が多すぎます。しばらく待ってから'
                'もう一度お試しください。</p>'
            )
        elif error:
            err_block = (
                '<p class="err">トークンが正しくありません。もう一度入力してください。</p>'
            )
        else:
            err_block = ""
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

    def _handle_client_message(self, raw: str, client_ip: str = "ws") -> None:
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
            # 解決済み＝再接続時にプランモーダルを再表示しない。
            self._clear_pending_interactive("plan_review")
            self.plan_confirm_event.set()

        elif action == "manual_payload":
            # U-3: {"action": "manual_payload", "url": ..., "field": ..., "payload": ..., "check_type": ...}
            self.manual_payload_queue.put_nowait(msg)

        elif action == "manual_crawl_input":
            # 遠隔ブラウザ操作: {"action":"manual_crawl_input","event":{type,nx,ny,...}}
            # 入力の検証・正規化はセッション側（coerce_input_event）に委譲する。
            session = self.manual_crawl_session
            if session is not None and getattr(session, "streaming", False):
                ev = msg.get("event") or {}
                try:
                    asyncio.get_running_loop().create_task(session.input_event(ev))
                except RuntimeError:
                    pass

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
            cfg = msg.get("config", {}) or {}
            # HTTP API と同様に対象スコープを検査（WS 経由でのスコープ回避を防ぐ）。
            scope_err = self._config_scope_error(cfg)
            if scope_err:
                try:
                    asyncio.get_running_loop().create_task(
                        self.emit("scan_rejected", {"message": scope_err})
                    )
                except RuntimeError:
                    pass
                return
            self.scan_request_data = cfg
            self.api_scan_id = str(int(time.time()))
            self.api_scan_status = "scanning"
            self.api_findings = []
            self.api_report_path = None
            self.api_target = cfg.get("url", "") or ""
            self.api_phase = ""
            self.api_progress = {"current": 0, "total": 0, "percent": 0}
            self._audit("scan_start", client_ip, cfg.get("url", ""))
            self.scan_request_event.set()

        elif action == "crawl_review":
            # User reviewed crawl results. command: continue|recrawl|cancel
            # Optional extra_urls (list[str]) and manual_crawl_file (str) are
            # consumed by the engine on resume.
            extra_urls = msg.get("extra_urls", []) or []
            flows = msg.get("flows", []) or []
            # レビュー時に追加される URL / フローもスコープ検査し、範囲外は除外する
            # （スキャン本体と同じ allow/deny を後段の navigate にも効かせる）。
            if self.allowed_target_hosts or self.denied_target_hosts:
                extra_urls = [u for u in extra_urls if not self._scope_error(str(u))]
                flows = [
                    f for f in flows
                    if all(not self._scope_error(u) for u in self._flow_nav_urls([f]))
                ]
            self.crawl_review_action = {
                "command": msg.get("command", "continue"),
                "extra_urls": extra_urls,
                "manual_crawl_file": msg.get("manual_crawl_file", "") or "",
                # Manual attack scenarios built in the dashboard scenario editor.
                "flows": flows,
            }
            # 解決済み＝再接続時に巡回レビューを再表示しない。
            self._clear_pending_interactive("crawl_review")
            self.crawl_review_event.set()

    # ------------------------------------------------------------------
    # Pending interactive (operator-awaited modal) state
    # ------------------------------------------------------------------

    def _mark_pending_interactive(self, event_type: str, data: Any = None) -> None:
        """未解決の一過性モーダルを1件だけ記録（再接続時にこれだけ再送する）。"""
        self.pending_interactive = {
            "type": event_type,
            "timestamp": time.time(),
            "data": data or {},
        }

    def _clear_pending_interactive(self, *types: str) -> None:
        """未解決モーダルを解消。types 指定時はその型に一致する場合のみ消す。"""
        if self.pending_interactive is None:
            return
        if types and self.pending_interactive.get("type") not in types:
            return
        self.pending_interactive = None

    # ------------------------------------------------------------------
    # Broadcast helpers
    # ------------------------------------------------------------------

    async def emit(self, event_type: str, data: Any = None):
        """Send an event to all connected monitoring clients."""
        # スキャンが完了したら未解決のレビュー待ちは無効化する。
        # （非serve単発や異常終了で pending が残ったまま再接続→亡霊表示を防ぐ）
        if event_type == "scan_complete":
            self._clear_pending_interactive()
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

    async def broadcast_ephemeral(self, event_type: str, data: Any = None):
        """履歴に残さず接続中クライアントへ送る（高頻度・大容量イベント用）。

        スクリーンキャストのフレームのように毎秒大量に流れ、再生する意味のない
        イベントは ``event_history`` に積まない（メモリ肥大・再接続時の再生事故を防ぐ）。
        """
        event = {"type": event_type, "timestamp": time.time(), "data": data or {}}
        payload = json.dumps(event)
        dead = set()
        for client in list(self.clients):
            try:
                await client.send_text(payload)
            except Exception:
                dead.add(client)
        self.clients -= dead

    async def _emit_manual_crawl_frame(self, frame: dict):
        """遠隔操作セッションの画面フレームをダッシュボードへ配信する。"""
        await self.broadcast_ephemeral("manual_crawl_frame", frame)

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
        self.api_target = url or self.api_target
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
        # アイドル状態＝設定フォーム待ち。これを未解決モーダルとして記録し、
        # 再接続時に（過去スキャンの crawl_review ではなく）設定フォームを出す。
        self._mark_pending_interactive("awaiting_config", {})
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
        # NOTE: payload file-logging lives in BaseScanner.log_payload_test (so it
        # works without a monitor and is not duplicated here). This only pushes
        # the live dashboard event.
        await self.emit("payload_test", {
            "field": field,
            "payload": payload,
            "check_type": check_type,
            "url": url,
        })

    async def emit_progress(self, current: int, total: int, message: str = ""):
        self.api_progress = {
            "current": current,
            "total": total,
            "percent": int(current / total * 100) if total > 0 else 0,
        }
        await self.emit("progress", {**self.api_progress, "message": message})

    async def emit_phase(self, phase: str) -> None:
        """Emit current scan phase: 'crawl' | 'plan' | 'attack' | 'report'"""
        self.api_phase = phase
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
        self._mark_pending_interactive("plan_review", {"plans": plans_data})
        await self.emit("plan_review", {"plans": plans_data})

    async def emit_crawl_review(self, pages_data: list):
        """
        Send the list of pages discovered by the crawl phase to the dashboard
        so the operator can confirm coverage, request a re-crawl, or merge a
        manual-crawl JSON before the attack phase begins.
        """
        self.crawl_review_event.clear()
        self.crawl_review_action = {}
        self._mark_pending_interactive("crawl_review", {"pages": pages_data})
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
