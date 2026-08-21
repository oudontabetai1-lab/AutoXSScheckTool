"""
WScan Browser Manager
Playwright-based browser automation with evidence collection.
"""
import asyncio
import base64
import json
import re
import socket
import time
import urllib.request
from urllib.parse import urlparse as _urlparse
from typing import Optional, Callable, Any
from urllib.parse import urljoin, urlparse

from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Request, Response
from rich.console import Console

from .header_scope import headers_allowed_for_url
from .tls_config import TLSConfig
from .url_extraction import is_plausible_route_candidate, truncated_regex_literal


console = Console()


class _BrowserCDPConnection:
    """flatten CDP の子 session へ直接送信する最小限の接続。"""

    def __init__(self):
        self._websocket = None
        self._receive_task: Optional[asyncio.Task] = None
        self._next_id = 0
        self._pending: dict[int, asyncio.Future] = {}
        self._event_handler = None

    async def connect(self, websocket_url: str, event_handler) -> None:
        from websockets import connect

        self._event_handler = event_handler
        self._websocket = await connect(
            websocket_url,
            open_timeout=3,
            close_timeout=1,
            max_size=None,
        )
        self._receive_task = asyncio.create_task(self._receive())

    async def _receive(self) -> None:
        try:
            async for raw_message in self._websocket:
                message = json.loads(raw_message)
                command_id = message.get("id")
                if command_id is not None:
                    future = self._pending.pop(command_id, None)
                    if future is not None and not future.done():
                        future.set_result(message)
                    continue
                if self._event_handler is not None:
                    try:
                        self._event_handler(
                            message.get("method") or "",
                            message.get("params") or {},
                            message.get("sessionId") or "",
                        )
                    except Exception:
                        pass
        except Exception:
            pass
        finally:
            for future in self._pending.values():
                if not future.done():
                    future.set_exception(RuntimeError("CDP connection closed"))
            self._pending.clear()

    async def send(
        self,
        method: str,
        params: Optional[dict] = None,
        *,
        session_id: str = "",
    ) -> dict:
        if self._websocket is None:
            raise RuntimeError("CDP connection is unavailable")
        self._next_id += 1
        command_id = self._next_id
        future = asyncio.get_running_loop().create_future()
        self._pending[command_id] = future
        message = {
            "id": command_id,
            "method": method,
            "params": params or {},
        }
        if session_id:
            message["sessionId"] = session_id
        try:
            await self._websocket.send(json.dumps(message))
            response = await asyncio.wait_for(future, timeout=3.0)
        except Exception:
            self._pending.pop(command_id, None)
            raise
        if response.get("error"):
            # CDP のエラー本文にリクエスト情報が含まれる可能性があるため露出しない。
            raise RuntimeError("CDP command failed")
        return response.get("result") or {}

    async def close(self) -> None:
        websocket = self._websocket
        self._websocket = None
        if websocket is not None:
            try:
                await websocket.close()
            except Exception:
                pass
        if self._receive_task is not None:
            try:
                await self._receive_task
            except Exception:
                pass
            self._receive_task = None


class _RoutedCDPSession:
    """Browser CDP 接続上の子 session を通常の send API として扱う。"""

    def __init__(self, connection: _BrowserCDPConnection, session_id: str):
        self._connection = connection
        self._session_id = session_id

    async def send(self, method: str, params: Optional[dict] = None) -> dict:
        return await self._connection.send(
            method,
            params,
            session_id=self._session_id,
        )


class NetworkCapture:
    """Captures HTTP request/response pairs."""

    def __init__(self, logger=None):
        self.pairs: list[dict] = []
        # Use (url, id(request_object)) as key to avoid collisions when the same URL
        # is requested multiple times concurrently (race condition fix).
        self._pending: dict[tuple, dict] = {}
        # Optional RequestLogger: persists every request/response pair to a
        # JSONL audit log. clear() wipes the in-memory list per page, so the
        # log is the only place a complete request history survives.
        self.logger = logger

    def on_request(self, request: Request):
        key = (request.url, id(request))
        self._pending[key] = {
            "url": request.url,
            "method": request.method,
            "headers": dict(request.headers),
            "post_data": request.post_data,
            "timestamp": time.time(),
            "_req_id": id(request),
        }

    def on_response(self, response: Response):
        # Match by (url, id(response.request)) so concurrent requests to the same URL
        # are kept separate and don't overwrite each other.
        req_id = id(response.request) if response.request else None
        key = (response.url, req_id)
        req = self._pending.pop(key, None)
        if req is None:
            # Fallback: try matching by URL alone (older Playwright versions)
            for k in list(self._pending):
                if k[0] == response.url:
                    req = self._pending.pop(k)
                    break
        if req is None:
            req = {"url": response.url}
        pair = {
            "request": req,
            "response": {
                "url": response.url,
                "status": response.status,
                "headers": dict(response.headers),
                "timestamp": time.time(),
            },
        }
        self.pairs.append(pair)
        if self.logger is not None:
            self.logger.log_http(pair)

    async def enrich_response(self, response: Response):
        """Asynchronously get response body text.

        Playwright's ``response.text()`` does a strict UTF-8 decode of the raw
        body and raises ``UnicodeDecodeError`` on non-UTF-8 / binary content,
        which would silently drop the body. Fall back to a resilient decode of
        the raw bytes so we still capture (and can scan) such responses.
        """
        try:
            try:
                body = await response.text()
            except UnicodeDecodeError:
                from .textio import safe_decode
                # 本文は 50KB でキャップする。limit を渡すことで、gzip 応答でも
                # 展開量を 50KB に抑える（gzip bomb 対策）。
                body = safe_decode(await response.body(), limit=50000)
            for pair in reversed(self.pairs):
                if pair["response"]["url"] == response.url:
                    pair["response"]["body"] = body[:50000]  # cap at 50KB
                    break
        except Exception:
            pass

    def latest(self) -> Optional[dict]:
        return self.pairs[-1] if self.pairs else None

    def latest_for_url(self, url: str, *, match_query: bool = True) -> Optional[dict]:
        """Return the newest captured pair for a specific URL, ignoring assets loaded later."""
        target = (url or "").split("#", 1)[0]
        target_parsed = urlparse(target)
        for pair in reversed(self.pairs):
            req_url = (pair.get("request", {}).get("url") or "").split("#", 1)[0]
            resp_url = (pair.get("response", {}).get("url") or "").split("#", 1)[0]
            if match_query and (req_url == target or resp_url == target):
                return pair
            if not match_query:
                for candidate in (req_url, resp_url):
                    parsed = urlparse(candidate)
                    target_path = target_parsed.path or "/"
                    candidate_path = parsed.path or "/"
                    if (
                        parsed.scheme == target_parsed.scheme
                        and parsed.netloc == target_parsed.netloc
                        and candidate_path == target_path
                    ):
                        return pair
        return None

    def best_pair_for_page(self, url: str) -> Optional[dict]:
        """検査対象ページを最もよく表す request/response ペアを選ぶ。

        フォーム送信 / URL パラメータ注入の後、ページはアナリティクスや
        トラッキングのビーコン（多くは別オリジンの ``POST``）や、あとから
        読まれるサブリソース（css/js/画像）も送信しうる。そのため単純に
        ``latest()`` を採ると、レポートの「リクエスト/レスポンス」が検査対象
        ではない別 URL（例: analytics）になってしまう。

        優先順位: (1) 対象 URL の完全一致（パス一致・クエリ無視） →
        (2) 同一オリジンで ``Content-Type`` が HTML の最新レスポンス（＝文書本体）
        → (3) 同一オリジンの最新レスポンス。いずれも無ければ ``None``。
        呼び出し側で最後の手段として ``latest()`` にフォールバックできる。
        """
        exact = self.latest_for_url(url, match_query=False)
        if exact:
            return exact
        target = urlparse((url or "").split("#", 1)[0])
        same_origin: Optional[dict] = None
        same_origin_html: Optional[dict] = None
        for pair in reversed(self.pairs):
            resp = pair.get("response", {}) or {}
            req = pair.get("request", {}) or {}
            cand = urlparse((resp.get("url") or req.get("url") or "").split("#", 1)[0])
            if cand.scheme != target.scheme or cand.netloc != target.netloc:
                continue  # 別オリジン（アナリティクス等）は除外
            if same_origin is None:
                same_origin = pair  # reversed なので最新の同一オリジン
            ctype = ""
            for k, v in (resp.get("headers") or {}).items():
                if str(k).lower() == "content-type":
                    ctype = str(v).lower()
                    break
            if "html" in ctype:
                same_origin_html = pair  # 文書本体（最新）
                break
        return same_origin_html or same_origin

    def clear(self):
        self.pairs.clear()
        self._pending.clear()


class BrowserManager:
    """Manages Playwright browser and provides helper methods."""

    def __init__(
        self,
        headless: bool = False,
        timeout: int = 30,
        monitor=None,
        auth_user: str = "",
        auth_pass: str = "",
        proxy: str = "",
        sleep_factor: float = 1.0,
        extra_headers: Optional[dict] = None,
        tls_config: Optional[TLSConfig] = None,
        target_url: str = "",
        header_scope_origins: Optional[set] = None,
        header_scope_enforce: bool = True,
        expect_late_headers: bool = False,
        popup_header_intercept: bool = False,
        request_logger=None,
        mfa_solver=None,
    ):
        self.headless = headless
        self.timeout = timeout * 1000  # ms
        self.monitor = monitor
        self.auth_user = auth_user
        self.auth_pass = auth_pass
        # MFA（2FA）ソルバ。設定時はログイン後のワンタイムコード入力を自動化。
        # None なら従来どおり MFA 段は何もしない。
        self.mfa_solver = mfa_solver
        self.proxy = proxy  # e.g. "http://127.0.0.1:8080"
        self.sleep_factor = sleep_factor
        self.tls_config = tls_config or TLSConfig()
        self.target_url = target_url
        # Custom HTTP headers (Authorization, X-API-Key, …). When explicit
        # origins are known they are added per request; otherwise the legacy
        # context-wide behavior is preserved.
        self.extra_headers: dict[str, str] = dict(extra_headers or {})
        self.header_scope_enforce = bool(header_scope_enforce)
        self.expect_late_headers = bool(expect_late_headers)
        self.popup_header_intercept = bool(popup_header_intercept)
        self.header_scope_origins = (
            set(header_scope_origins or ())
            if self.header_scope_enforce
            else set()
        )
        self._header_intercept_mode: str = "none"
        self._header_route_active: bool = False
        self._header_cdp_fallback_warned: bool = False
        self._header_route_fallback_warned: bool = False
        self._header_request_fallback_warned: bool = False
        self._header_scope_disabled_warned: bool = False
        self._popup_header_intercept_warned: bool = False
        self._context_wide_headers_active: bool = False
        self._service_worker_block_fallback_warned: bool = False
        self._header_attached_page_ids: set[int] = set()
        self._header_explicit_target_ids: set[str] = set()
        self._header_attach_tasks: dict[int, asyncio.Task] = {}
        self._header_cdp_sessions: dict[int, Any] = {}
        self._header_browser_cdp: Optional[_BrowserCDPConnection] = None
        self._header_browser_session_id: str = ""
        self._header_auto_target_sessions: dict[str, str] = {}
        self._header_auto_attach_active: bool = False
        self._header_debug_port: Optional[int] = None
        self._header_target_tasks: set[asyncio.Task] = set()
        self._header_page_tasks: set[asyncio.Task] = set()
        self._header_pause_tasks: set[asyncio.Task] = set()
        self._header_interception_closing: bool = False
        self._playwright = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self.request_logger = request_logger
        self.network = NetworkCapture(logger=request_logger)
        self.dialog_fired: bool = False
        self.dialog_message: str = ""
        self.dialog_screenshot_b64: str = ""  # Screenshot taken right when alert fires
        self.last_login_url: str = ""
        self.last_login_success: bool = False
        self.last_navigation_error: str = ""
        self.last_navigation_status: Optional[int] = None

    async def init(self):
        """Launch browser and create page."""
        if self.extra_headers and not self.header_scope_enforce:
            await self._warn_header_scope_disabled()
        self._playwright = await async_playwright().start()
        use_scoped_headers = bool(self.extra_headers and self.header_scope_origins)
        scoped_headers_possible = bool(
            self.header_scope_enforce
            and self.header_scope_origins
            and (self.extra_headers or self.expect_late_headers)
        )
        block_service_workers = scoped_headers_possible
        launch_args = ["--disable-web-security", "--disable-features=IsolateOrigins"]
        if scoped_headers_possible and self.popup_header_intercept:
            # Playwright の CDPSession.send() は flatten された子 session_id を
            # 指定できない。loopback の一時 endpoint から browser CDP へ接続し、
            # popup target を停止中の同一 session で設定・再開できるようにする。
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                    probe.bind(("127.0.0.1", 0))
                    self._header_debug_port = probe.getsockname()[1]
                await self._warn_popup_header_intercept()
                launch_args.extend([
                    "--remote-debugging-address=127.0.0.1",
                    f"--remote-debugging-port={self._header_debug_port}",
                ])
            except Exception:
                self._header_debug_port = None
        launch_kwargs: dict = {"headless": self.headless, "args": launch_args}
        if self.proxy:
            launch_kwargs["proxy"] = {"server": self.proxy}
        self._browser = await self._playwright.chromium.launch(**launch_kwargs)
        ctx_kwargs: dict = {
            "viewport": {"width": 1280, "height": 800},
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        }
        ctx_kwargs.update(self.tls_config.playwright_context_options(self.target_url))
        if self.proxy:
            ctx_kwargs["proxy"] = {"server": self.proxy}
        if self.extra_headers and not use_scoped_headers:
            # Keep header names case-preserving but de-dupe case-insensitive collisions
            # so Playwright doesn't reject duplicates.
            seen: dict[str, str] = {}
            for k, v in self.extra_headers.items():
                seen[k.lower()] = v
                ctx_kwargs.setdefault("extra_http_headers", {})[k] = str(v)
        if block_service_workers:
            # Service Worker が処理するリクエストは CDP Fetch / context.route()
            # のどちらでも確実に傍受できないため、初期ヘッダがある場合に加え、
            # refresh で後から届き得る場合もコンテキスト生成時に無効化する。
            ctx_kwargs["service_workers"] = "block"
        try:
            self._context = await self._browser.new_context(**ctx_kwargs)
        except TypeError:
            if not block_service_workers or "service_workers" not in ctx_kwargs:
                raise
            # 古い Playwright は service_workers を受け付けない。この場合も scan を
            # 中断せず、該当オプションだけ外してリクエスト単位の傍受を試す。
            ctx_kwargs.pop("service_workers", None)
            await self._warn_service_worker_block_fallback()
            self._context = await self._browser.new_context(**ctx_kwargs)
        self._context_wide_headers_active = bool(
            self.extra_headers and not use_scoped_headers
        )
        self._header_intercept_mode = (
            "context" if self._context_wide_headers_active else "none"
        )
        if self.header_scope_origins:
            try:
                self._context.on("page", self._on_header_context_page)
            except Exception:
                # main/worker page は明示 attach するため、イベント購読に失敗しても
                # スキャンを止めない。popup はヘッダなしのフェイルクローズになる。
                pass
        self.page = await self._context.new_page()
        if use_scoped_headers:
            # 最初のナビゲーションより前に Fetch.enable の完了を保証する。
            await self._activate_scoped_header_interception(self.page)
            if self._header_intercept_mode == "cdp":
                # 失敗時は context の page イベントによる現行方式を維持する。
                await self._activate_header_target_auto_attach()
        self.page.set_default_timeout(self.timeout)

        # Set up network interception
        self.page.on("request", self.network.on_request)
        self.page.on("response", self._on_response)

        # Set up dialog handler (for XSS detection)
        self.page.on("dialog", self._on_dialog)

    async def _on_response(self, response: Response):
        self.network.on_response(response)
        await self.network.enrich_response(response)
        if self.monitor:
            req = self.network.latest()
            if req:
                await self.monitor.emit_request(req.get("request", {}))
                await self.monitor.emit_response(req.get("response", {}))

    async def _emit_header_notice(self, message: str) -> None:
        """ヘッダ関連の重要通知を monitor または CLI へ出す。"""
        if self.monitor:
            try:
                await self.monitor.emit_status(message, "running")
                return
            except Exception:
                # 通知障害でスキャンを中断せず、CLI へ表示して見落としを防ぐ。
                pass
        console.print(f"[yellow]{message}[/yellow]")

    async def _warn_header_cdp_fallback(self) -> None:
        """CDP から従来 route 方式への切替を、値を含めず一度だけ通知する。"""
        if self._header_cdp_fallback_warned:
            return
        self._header_cdp_fallback_warned = True
        await self._emit_header_notice(
            "CDP による傍受を有効化できないため従来方式で継続します。"
            "ストリーミング応答（SSE 等）が途中で切れる可能性があります"
        )

    async def _warn_header_route_fallback(self) -> None:
        """ルート登録失敗の通知を、ヘッダ値を含めず一度だけ出す。"""
        if self._header_route_fallback_warned:
            return
        self._header_route_fallback_warned = True
        await self._emit_header_notice(
            "リクエスト単位のヘッダ付与を有効化できず、"
            "コンテキスト全体へ適用します"
            "（第三者サブリソースにも送信され得ます）"
        )

    async def _warn_header_scope_disabled(self) -> None:
        """明示的なスコープ制御無効化を、ヘッダ値なしで一度だけ通知する。"""
        if self._header_scope_disabled_warned:
            return
        self._header_scope_disabled_warned = True
        await self._emit_header_notice(
            "認証ヘッダのスコープ制御が無効です。"
            "コンテキスト全体へ適用するため、第三者サブリソースにも"
            "認証ヘッダが送信されます"
        )

    async def _warn_popup_header_intercept(self) -> None:
        """DevTools ポートを開く明示 opt-in を、値なしで一度だけ通知する。"""
        if self._popup_header_intercept_warned:
            return
        self._popup_header_intercept_warned = True
        await self._emit_header_notice(
            "popup 傍受のためローカル DevTools ポートを開きます。"
            "同一ホストの他プロセスからブラウザを操作され得るため、"
            "共有ホストでは使用しないでください"
        )

    async def _warn_service_worker_block_fallback(self) -> None:
        """Service Worker 無効化不可の通知を、値を含めず一度だけ出す。"""
        if self._service_worker_block_fallback_warned:
            return
        self._service_worker_block_fallback_warned = True
        await self._emit_header_notice(
            "Service Worker を無効化できないため、一部のリクエストでは"
            "リクエスト単位のヘッダ付与が適用されない可能性があります"
        )

    async def _warn_header_request_fallback(self) -> None:
        """リクエスト単位の付与失敗を、ヘッダ値を含めず一度だけ通知する。"""
        if self._header_request_fallback_warned:
            return
        self._header_request_fallback_warned = True
        await self._emit_header_notice(
            "リクエスト単位のヘッダ付与に失敗したため、"
            "該当リクエストは認証ヘッダなしで実行しました"
        )

    async def _find_debugger_websocket_url(self) -> str:
        """loopback の DevTools endpoint が起動するまで短時間だけ待つ。"""
        if not self._header_debug_port:
            return ""
        endpoint = (
            f"http://127.0.0.1:{self._header_debug_port}/json/version"
        )
        deadline = asyncio.get_running_loop().time() + 0.5
        while asyncio.get_running_loop().time() < deadline:
            try:
                def _read_version():
                    with urllib.request.urlopen(endpoint, timeout=0.3) as response:
                        return json.loads(response.read())

                version = await asyncio.to_thread(_read_version)
                websocket_url = str(version.get("webSocketDebuggerUrl") or "")
                if websocket_url:
                    return websocket_url
            except Exception:
                await asyncio.sleep(0.05)
        return ""

    def _on_header_browser_cdp_event(
        self,
        method: str,
        params: dict,
        session_id: str,
    ) -> None:
        """browser CDP の同期通知を、停止を残さない非同期処理へ渡す。"""
        if self._header_interception_closing:
            return
        if method == "Target.attachedToTarget":
            if session_id != self._header_browser_session_id:
                return
            try:
                task = asyncio.create_task(
                    self._enable_fetch_for_attached_header_target(params)
                )
            except Exception:
                return
            self._header_target_tasks.add(task)
            task.add_done_callback(self._header_target_tasks.discard)
            return
        if method == "Target.detachedFromTarget":
            detached_session_id = str(params.get("sessionId") or "")
            for target_id, current_session_id in tuple(
                self._header_auto_target_sessions.items()
            ):
                if current_session_id == detached_session_id:
                    self._header_auto_target_sessions.pop(target_id, None)
            return
        if method == "Fetch.requestPaused" and session_id:
            cdp = self._header_browser_cdp
            if cdp is not None:
                self._dispatch_fetch_request_paused(
                    _RoutedCDPSession(cdp, session_id),
                    params,
                )

    async def _enable_fetch_for_attached_header_target(
        self,
        event: dict,
    ) -> None:
        """停止中の page target へ Fetch を設定し、必ず再開する。"""
        target_info = event.get("targetInfo") or {}
        target_id = str(target_info.get("targetId") or "")
        target_type = str(target_info.get("type") or "")
        cdp_session_id = str(event.get("sessionId") or "")
        cdp = self._header_browser_cdp
        try:
            if (
                cdp is not None
                and target_type in {"page", "tab"}
                and target_id
                and cdp_session_id
                and target_id not in self._header_explicit_target_ids
                and self._header_auto_target_sessions.get(target_id)
                != cdp_session_id
            ):
                # responseStage は指定せず、応答ストリームを止めない。
                await cdp.send(
                    "Fetch.enable",
                    {"patterns": [{"urlPattern": "*"}]},
                    session_id=cdp_session_id,
                )
                self._header_auto_target_sessions[target_id] = cdp_session_id
        except Exception:
            # この target はヘッダなしで継続し、他の page の傍受は維持する。
            try:
                await self._warn_header_request_fallback()
            except Exception:
                pass
        finally:
            if cdp is not None and cdp_session_id:
                try:
                    # waitForDebuggerOnStart で停止した target は、種別や Fetch の
                    # 成否にかかわらず同一 session で必ず再開する。
                    await cdp.send(
                        "Runtime.runIfWaitingForDebugger",
                        session_id=cdp_session_id,
                    )
                except Exception:
                    pass

    async def _activate_header_target_auto_attach(self) -> bool:
        """新 page を初回ナビゲーション前に停止して Fetch を有効化する。"""
        if self._header_auto_attach_active:
            return True
        websocket_url = await self._find_debugger_websocket_url()
        if not websocket_url:
            return False
        cdp = _BrowserCDPConnection()
        try:
            await cdp.connect(
                websocket_url,
                self._on_header_browser_cdp_event,
            )
            browser_session = await cdp.send("Target.attachToBrowserTarget")
            browser_session_id = str(browser_session.get("sessionId") or "")
            if not browser_session_id:
                raise RuntimeError("browser CDP session is unavailable")
            self._header_browser_cdp = cdp
            self._header_browser_session_id = browser_session_id
            await cdp.send(
                "Target.setAutoAttach",
                {
                    "autoAttach": True,
                    "waitForDebuggerOnStart": True,
                    "flatten": True,
                },
                session_id=browser_session_id,
            )
        except Exception:
            self._header_browser_cdp = None
            self._header_browser_session_id = ""
            try:
                await cdp.close()
            except Exception:
                pass
            return False
        self._header_auto_attach_active = True
        return True

    async def _deactivate_header_target_auto_attach(self) -> None:
        """auto-attach の購読と子 session を best-effort で解放する。"""
        cdp = self._header_browser_cdp
        browser_session_id = self._header_browser_session_id
        self._header_auto_attach_active = False
        if cdp is None:
            return
        if browser_session_id:
            try:
                await cdp.send(
                    "Target.setAutoAttach",
                    {
                        "autoAttach": False,
                        "waitForDebuggerOnStart": False,
                        "flatten": True,
                    },
                    session_id=browser_session_id,
                )
            except Exception:
                pass
        if self._header_target_tasks:
            await asyncio.gather(
                *list(self._header_target_tasks),
                return_exceptions=True,
            )
        for cdp_session_id in set(
            self._header_auto_target_sessions.values()
        ):
            try:
                await cdp.send(
                    "Fetch.disable",
                    session_id=cdp_session_id,
                )
            except Exception:
                pass
        if browser_session_id:
            try:
                await cdp.send(
                    "Target.detachFromTarget",
                    {"sessionId": browser_session_id},
                )
            except Exception:
                pass
        await cdp.close()
        self._header_browser_cdp = None
        self._header_browser_session_id = ""
        self._header_auto_target_sessions.clear()

    def _dispatch_fetch_request_paused(self, cdp, event: dict) -> None:
        """CDP の同期イベントから、必ず解放する非同期ハンドラを起動する。"""
        try:
            task = asyncio.create_task(
                self._on_fetch_request_paused(cdp, event)
            )
        except Exception:
            return
        self._header_pause_tasks.add(task)
        task.add_done_callback(self._header_pause_tasks.discard)

    async def _on_fetch_request_paused(self, cdp, event: dict) -> None:
        """許可オリジンだけヘッダを上書きし、停止中リクエストを解放する。"""
        try:
            request_id = event["requestId"]
        except Exception:
            # requestId が無ければ CDP へ返せる識別子がないため、何もしない。
            return

        params = {"requestId": request_id}
        try:
            request = event["request"]
            url = request["url"]
            if headers_allowed_for_url(url, self.header_scope_origins):
                headers = {
                    str(name): str(value)
                    for name, value in (request.get("headers") or {}).items()
                }
                for name, value in self.extra_headers.items():
                    lowered = str(name).lower()
                    headers = {
                        current_name: current_value
                        for current_name, current_value in headers.items()
                        if current_name.lower() != lowered
                    }
                    headers[str(name)] = str(value)
                params["headers"] = [
                    {"name": name, "value": value}
                    for name, value in headers.items()
                ]
        except Exception:
            # 判定やヘッダ合成に失敗した場合も、値を付けずに必ず解放する。
            try:
                await self._warn_header_request_fallback()
            except Exception:
                pass
            params = {"requestId": request_id}

        try:
            await cdp.send("Fetch.continueRequest", params)
        except Exception:
            # page/context 終了でセッションが消滅した場合はスキャンへ伝播させない。
            pass

    async def _attach_header_interception(self, page) -> None:
        """同じ page へ二重登録せず、request stage の CDP Fetch を有効化する。"""
        page_id = id(page)
        if page_id in self._header_attached_page_ids:
            return
        if self._header_auto_attach_active:
            # auto-attach が新 page の停止中に設定済み。別 session で重ねない。
            return
        existing = self._header_attach_tasks.get(page_id)
        if existing is not None:
            await existing
            return

        async def _attach() -> None:
            if self._context is None:
                raise RuntimeError("browser context is unavailable")
            cdp = None
            try:
                cdp = await self._context.new_cdp_session(page)
                cdp.on(
                    "Fetch.requestPaused",
                    lambda event: self._dispatch_fetch_request_paused(cdp, event),
                )
                # responseStage は指定しない。応答本文を待たずストリームを維持する。
                await cdp.send(
                    "Fetch.enable",
                    {"patterns": [{"urlPattern": "*"}]},
                )
                try:
                    target = await cdp.send("Target.getTargetInfo")
                    target_id = str(
                        (target or {}).get("targetInfo", {}).get("targetId") or ""
                    )
                    if target_id:
                        self._header_explicit_target_ids.add(target_id)
                except Exception:
                    # target ID の取得不可は Fetch 自体の成功を取り消さない。
                    pass
            except Exception:
                if cdp is not None:
                    try:
                        await cdp.send("Fetch.disable")
                    except Exception:
                        pass
                    try:
                        await cdp.detach()
                    except Exception:
                        pass
                raise
            self._header_cdp_sessions[page_id] = cdp
            self._header_attached_page_ids.add(page_id)

        task = asyncio.create_task(_attach())
        self._header_attach_tasks[page_id] = task
        try:
            await task
        except Exception:
            if self._header_attach_tasks.get(page_id) is task:
                self._header_attach_tasks.pop(page_id, None)
            self._header_attached_page_ids.discard(page_id)
            raise

    def _on_header_context_page(self, page) -> None:
        """popup 等の追加 page へ CDP Fetch を冪等に設定する。"""
        if (
            self._header_intercept_mode != "cdp"
            or self._header_interception_closing
        ):
            return
        try:
            task = asyncio.create_task(
                self._attach_additional_header_page(page)
            )
        except Exception:
            return
        self._header_page_tasks.add(task)
        task.add_done_callback(self._header_page_tasks.discard)

    async def _attach_additional_header_page(self, page) -> None:
        try:
            await self._attach_header_interception(page)
        except Exception:
            # 一部 page の attach 失敗後に route を併用すると CDP Fetch と競合する。
            # その page はヘッダなしで継続し、既存 session のスキャンを維持する。
            await self._warn_header_request_fallback()

    async def _activate_scoped_header_interception(self, page) -> None:
        """CDP -> route -> context の順でスコープ付きヘッダを有効化する。"""
        if self._context is None:
            return
        if self._header_intercept_mode in {"cdp", "route"}:
            return
        if self._header_route_active:
            self._header_intercept_mode = "route"
            return

        if self._context_wide_headers_active:
            try:
                await self._context.set_extra_http_headers({})
            except Exception:
                # context-wide 設定を解除できないまま CDP/route を重ねると、
                # スコープ外にもヘッダが残る。従来 mode のまま継続する。
                self._header_intercept_mode = "context"
                await self._warn_header_route_fallback()
                try:
                    await self._context.set_extra_http_headers(
                        {k: str(v) for k, v in self.extra_headers.items()}
                    )
                except Exception:
                    pass
                return
            self._context_wide_headers_active = False
            self._header_intercept_mode = "none"

        try:
            await self._attach_header_interception(page)
        except Exception:
            await self._warn_header_cdp_fallback()
        else:
            self._header_intercept_mode = "cdp"
            self._header_route_active = False
            return

        try:
            await self._context.route("**/*", self._auth_header_route)
        except Exception:
            self._header_route_active = False
            await self._warn_header_route_fallback()
        else:
            self._header_intercept_mode = "route"
            self._header_route_active = True
            return

        try:
            await self._context.set_extra_http_headers(
                {k: str(v) for k, v in self.extra_headers.items()}
            )
        except Exception:
            self._header_intercept_mode = "none"
        else:
            self._context_wide_headers_active = bool(self.extra_headers)
            self._header_intercept_mode = (
                "context" if self._context_wide_headers_active else "none"
            )

    async def _auth_header_route(self, route, request):
        """許可オリジンのリクエストにだけ認証ヘッダを付けて継続する。

        許可オリジンでは max_redirects=0 で自前取得し fulfill する。ブラウザに 30x を
        そのまま返すことで、リダイレクト先は新規リクエストとして再度この判定を通り、
        スコープ外オリジンへ認証ヘッダが引き継がれない（Chromium はリダイレクトを内部で
        追うため、continue_ で注入したヘッダがそのまま外部へ送られてしまう）。
        """
        headers = None
        attempted_fetch = False
        try:
            if not headers_allowed_for_url(request.url, self.header_scope_origins):
                await route.continue_()
                return

            headers = dict(request.headers)
            headers.update(
                {key.lower(): str(value) for key, value in self.extra_headers.items()}
            )
            attempted_fetch = True
            response = await route.fetch(headers=headers, max_redirects=0)
            await route.fulfill(response=response)
            return
        except Exception:
            await self._warn_header_request_fallback()

        if attempted_fetch:
            try:
                # fetch はリクエスト送信後にも失敗し得る。成功可否ではなく試行した
                # 事実で判定し、continue_ による再送を避けて abort で解放する。
                await route.abort()
            except Exception:
                # ページやコンテキストが既に閉じている場合は abort も失敗し得る。
                pass
            return

        try:
            # continue_ に headers を渡すと Chromium がリダイレクト先にも
            # 引き継ぎ、外部オリジンへ漏洩し得るため、失敗時は必ずヘッダ無しで
            # 継続する（認証よりフェイルクローズを優先）。
            await route.continue_()
        except Exception:
            try:
                # 継続自体の一時的な失敗でもハングさせないよう、素通しを再試行する。
                await route.continue_()
            except Exception:
                # A route that was already continued, closed, or failed again
                # still must not propagate an exception into Playwright.
                pass

    async def _on_dialog(self, dialog):
        """Capture alert dialogs (XSS indicator)."""
        self.dialog_fired = True
        self.dialog_message = dialog.message
        # Capture an evidence screenshot, but NEVER let it wedge the scan. While
        # a dialog is open Playwright blocks the page, and ``page.screenshot``
        # can in turn block until the dialog is handled — a deadlock if we
        # screenshot *before* dismissing. Bound it with Playwright's *native*
        # timeout (not ``asyncio.wait_for``): wait_for cancels our await at 3s
        # but the screenshot keeps the page's default timeout running underneath,
        # so when that later fires there is no awaiter left and asyncio logs
        # "Future exception was never retrieved". Letting Playwright own the one
        # timeout keeps a single timer and dismisses no matter what, so a flood
        # of alert()-firing payloads (e.g. a stored-XSS listing) can't freeze
        # every later navigation.
        try:
            shot = await self.page.screenshot(
                full_page=False, type="jpeg", quality=80, timeout=3000
            )
            self.dialog_screenshot_b64 = base64.b64encode(shot).decode()
        except Exception:
            self.dialog_screenshot_b64 = ""
        try:
            await dialog.dismiss()
        except Exception:
            # The page may already have navigated or been closed by a parallel
            # worker. The dialog signal is still useful evidence.
            pass

    async def update_extra_headers(self, headers: dict) -> None:
        """Replace extra HTTP headers used by the refresh task."""
        self.extra_headers = dict(headers or {})
        if self.extra_headers and not self.header_scope_enforce:
            await self._warn_header_scope_disabled()
        if self._context is None:
            return
        if self._header_route_active:
            self._header_intercept_mode = "route"
            return
        if self._header_intercept_mode in {"cdp", "route"}:
            return
        if self.extra_headers and self.header_scope_origins:
            # Service Worker の block はコンテキスト生成時にしか設定できない。
            # 遅延有効化でも CDP -> route -> context の順序は維持する。
            await self._activate_scoped_header_interception(self.page)
            return
        try:
            await self._context.set_extra_http_headers(self.extra_headers)
        except Exception:
            # Older Playwright builds or already-closed contexts — swallow so a
            # rotating-token failure never aborts an in-progress scan.
            pass
        else:
            self._context_wide_headers_active = bool(self.extra_headers)
            self._header_intercept_mode = (
                "context" if self._context_wide_headers_active else "none"
            )

    def reset_dialog(self):
        self.dialog_fired = False
        self.dialog_message = ""
        self.dialog_screenshot_b64 = ""

    _DIALOG_HANDLER_JS = r"""
        (() => {
            const DIALOG = /(?:alert|confirm|prompt)\s*\(/i;
            const out = [];
            for (const el of document.querySelectorAll('*')) {
                for (const attr of (el.attributes || [])) {
                    const n = attr.name.toLowerCase();
                    if (n.startsWith('on') && DIALOG.test(attr.value || '')) {
                        out.push(attr.value);
                    }
                }
                let urlAttr = '';
                try { urlAttr = el.getAttribute('href') || el.getAttribute('src') || ''; }
                catch (e) { urlAttr = ''; }
                if (/^\s*javascript:/i.test(urlAttr) && DIALOG.test(urlAttr)) {
                    out.push(urlAttr);
                }
            }
            return out;
        })()
    """

    async def snapshot_dialog_handlers(self) -> list:
        """現在の DOM に存在する「ダイアログを呼ぶハンドラ値／javascript: URL」を返す。

        ``trigger_injected_handlers`` の baseline 比較用。payload 投入前（clean な
        ページ）に撮っておき、投入後に **新規に増えた**ハンドラだけを発火対象にする
        ことで、ページ本来の ``onclick="alert(1)"`` 等を誤って撃たないようにする。
        失敗時は空 list（比較なし＝従来の payload 包含フィルタのみ）。
        """
        page = self.page
        if page is None:
            return []
        try:
            return await page.evaluate(self._DIALOG_HANDLER_JS)
        except Exception:
            return []

    async def trigger_injected_handlers(
        self, payload: str = "", baseline_handlers: list | None = None
    ) -> int:
        """注入した payload 由来のイベントハンドラ／``javascript:`` URL を発火させる。

        ``onmouseover`` / ``onclick`` / ``onfocus`` などインタラクション必須の
        ハンドラや ``<a href="javascript:...">`` は、反射しても自動では発火しない。
        そのため本物の XSS でも ``dialog`` が立たず ``confirmed`` に昇格できず、
        ``_reflection_executable`` の保守的判定で取りこぼす（false negative）。

        ここで DOM を走査し、その属性が待ち受けるイベントを dispatch する（focus 系は
        ``el.focus()`` も）。``javascript:`` URL は ``el.click()`` で既定遷移を起こす。
        捕捉は既存の dialog ハンドラに委ねる。

        **誤検知抑制のため対象を三重に絞る**:
        1. on* ハンドラは「属性の構造（``name=value``）」が ``payload`` に含まれること
           （値の一致だけでは、サニタイズ後の値エコーを自前 UI の正規ハンドラに埋めた
           ページで誤発火する）。``javascript:`` URL はスキーム込みの値が payload に含まれること。
        2. ``baseline_handlers``（payload 投入前 DOM のダイアログハンドラ）に対して
           **新規に増えた**ぶんだけ（多重集合の差分）。
        3. 呼び出し側で着地パス一致・一意トークンによるダイアログ帰属も併用する。

        これにより、入力を安全にエスケープしていても本来 ``onclick="alert(1)"`` 等の
        正規ハンドラを持つページで、通常の XSS payload（``alert(1)`` を含む）が
        既存 UI を誤発火させて ``xss_dialog`` の誤検知を出す事故を防ぐ。``payload`` が
        空なら何も撃たない。戻り値は発火を試みた要素数。失敗時は 0。
        """
        page = self.page
        if page is None or not payload:
            return 0
        try:
            return await page.evaluate(
                r"""
                ({payload, baseline}) => {
                    if (!payload) return 0;
                    const DIALOG = /(?:alert|confirm|prompt)\s*\(/i;
                    const MOUSE = new Set(['click','dblclick','mousedown','mouseup',
                        'mouseover','mouseout','mouseenter','mouseleave','mousemove',
                        'contextmenu']);
                    const MAX = 60;
                    // ハンドラ値が payload に由来するか（空白差を吸収して包含比較）。
                    const norm = (s) => (s || '').replace(/\s+/g, '');
                    const injected = norm(payload);
                    const fromPayload = (val) => {
                        const v = norm(val);
                        return v.length > 0 && injected.indexOf(v) !== -1;
                    };
                    // on* ハンドラは「属性の構造そのもの」が payload に含まれることを要求する
                    // （値の一致だけでは不十分）。例えば payload が
                    // `" onmouseover=alert(<token>) x="` のとき、`onmouseover=alert(<token>)`
                    // が payload に在ることを確認する。これにより、入力を数字だけに
                    // サニタイズして自前 UI の `onclick="alert(<token>)"` に埋め込むような
                    // ページで、トークン値のエコーを注入ハンドラと誤認して発火するのを防ぐ
                    // （属性名 onclick は payload に無い＝構造は注入されていない）。
                    const structurallyInjected = (name, val) => {
                        const v = norm(val);
                        if (!v.length) return false;
                        return injected.indexOf(norm(name) + '=' + v) !== -1
                            || injected.indexOf(norm(name) + "='" + v) !== -1
                            || injected.indexOf(norm(name) + '="' + v) !== -1;
                    };
                    // baseline に存在したハンドラ値の多重集合。同値のハンドラは baseline
                    // 個数ぶんを「既存」として消費し、それを超えた出現だけを新規と見なす。
                    const baseCount = {};
                    for (const b of (baseline || [])) {
                        const k = norm(b);
                        baseCount[k] = (baseCount[k] || 0) + 1;
                    }
                    const isNew = (val) => {
                        const k = norm(val);
                        if (baseCount[k] > 0) { baseCount[k]--; return false; }
                        return true;
                    };
                    let triggered = 0;
                    const nodes = document.querySelectorAll('*');
                    for (const el of nodes) {
                        if (triggered >= MAX) break;
                        const events = [];
                        for (const attr of (el.attributes || [])) {
                            const n = attr.name.toLowerCase();
                            if (n.startsWith('on') && DIALOG.test(attr.value || '')
                                    && structurallyInjected(n, attr.value)
                                    && isNew(attr.value)) {
                                events.push(n.slice(2));
                            }
                        }
                        let urlAttr = '';
                        try { urlAttr = el.getAttribute('href') || el.getAttribute('src') || ''; }
                        catch (e) { urlAttr = ''; }
                        const jsUrl = /^\s*javascript:/i.test(urlAttr)
                            && DIALOG.test(urlAttr) && fromPayload(urlAttr) && isNew(urlAttr);
                        if (!events.length && !jsUrl) continue;
                        triggered++;
                        for (const type of events) {
                            try {
                                if (type === 'focus' || type === 'focusin') {
                                    try { el.focus(); } catch (e) {}
                                }
                                let ev;
                                if (MOUSE.has(type)) {
                                    ev = new MouseEvent(type, {bubbles: true, cancelable: true});
                                } else if (type.startsWith('pointer') && window.PointerEvent) {
                                    ev = new PointerEvent(type, {bubbles: true, cancelable: true});
                                } else if (type.startsWith('key') && window.KeyboardEvent) {
                                    ev = new KeyboardEvent(type, {bubbles: true, cancelable: true});
                                } else {
                                    ev = new Event(type, {bubbles: true, cancelable: true});
                                }
                                el.dispatchEvent(ev);
                            } catch (e) {}
                        }
                        if (jsUrl) {
                            try { el.click(); } catch (e) {}
                        }
                    }
                    return triggered;
                }
                """,
                {"payload": payload, "baseline": list(baseline_handlers or [])},
            )
        except Exception:
            # ページ遷移・クローズ・evaluate 失敗。発火層は加算的なので黙って 0。
            return 0

    async def navigate(
        self,
        url: str,
        wait_until: str = "domcontentloaded",
        retries: int = 2,
        retry_delay: float = 0.75,
    ) -> bool:
        """Navigate to URL and return success."""
        self.last_navigation_error = ""
        self.last_navigation_status = None
        attempts = max(1, int(retries) + 1)
        try:
            self.network.clear()
        except Exception:
            pass
        for attempt in range(attempts):
            try:
                response = await self.page.goto(url, wait_until=wait_until, timeout=self.timeout)
                self.last_navigation_status = response.status if response else None
                if (
                    response is not None
                    and (response.status == 429 or response.status >= 500)
                    and attempt + 1 < attempts
                ):
                    self.last_navigation_error = f"HTTP {response.status}"
                    await asyncio.sleep(retry_delay * (attempt + 1))
                    continue
                if response is not None and response.status >= 400:
                    self.last_navigation_error = f"HTTP {response.status}"
                    return False
                self.last_navigation_error = ""
                # SPA モードでは navigate 成功後に描画確定を待つ。crawl だけでなく
                # attack フェーズ（_attack_one_page・各スキャナの fill_and_submit_form
                # 前 navigate）でも待つことで、非同期描画フォームが「発見済みだが未検査」に
                # ならないようにする。非SPA(spa_settle=False)では従来挙動のまま。
                if getattr(self, "spa_settle", False):
                    try:
                        await self.settle_spa()
                    except Exception:
                        pass
                return True
            except Exception as e:
                self.last_navigation_error = f"{type(e).__name__}: {e}"
                if attempt + 1 >= attempts:
                    return False
                await asyncio.sleep(retry_delay * (attempt + 1))
        return False

    async def settle_spa(self, *, timeout_ms: int = 8000) -> None:
        """SPA 描画の確定を待つ。失敗時は例外を外へ出さない。"""
        try:
            timeout = max(0, int(timeout_ms))
            try:
                await self.page.wait_for_load_state("networkidle", timeout=timeout)
            except Exception:
                pass
            try:
                await self.page.wait_for_function(
                    """
                    () => {
                        const root = document.querySelector('app-root, #root') || document.body;
                        if (!root) return false;
                        return root.childElementCount > 0
                            || (root.innerText || '').trim().length > 0;
                    }
                    """,
                    timeout=timeout,
                    polling=200,
                )
            except Exception:
                pass
        except Exception:
            pass

    async def screenshot_b64(self, label: str = "") -> str:
        """Take screenshot and return as base64 string."""
        try:
            data = await self.page.screenshot(full_page=False, type="jpeg", quality=80)
            b64 = base64.b64encode(data).decode()
            if self.monitor:
                await self.monitor.emit_screenshot(b64, label)
            return b64
        except Exception:
            return ""

    async def get_page_source(self) -> str:
        """Get current page HTML source."""
        try:
            return await self.page.content()
        except Exception:
            return ""

    async def find_forms(self) -> list[dict]:
        """Find all forms and their inputs on the current page."""
        try:
            forms = await self.page.evaluate("""
                () => {
                    const results = [];
                    document.querySelectorAll('form').forEach((form, fi) => {
                        const inputs = [];
                        const els = form.querySelectorAll(
                            'input:not([type=hidden]):not([type=submit]):not([type=button]):not([type=reset]):not([type=image]):not([type=checkbox]):not([type=radio]), textarea'
                        );
                        els.forEach((el, ii) => {
                            inputs.push({
                                index: ii,
                                name: el.name || el.id || `input_${ii}`,
                                type: el.type || 'text',
                                id: el.id,
                                placeholder: el.placeholder,
                                value: el.value,
                            });
                        });
                        if (inputs.length > 0) {
                            results.push({
                                index: fi,
                                action: form.action || window.location.href,
                                method: (form.method || 'GET').toUpperCase(),
                                inputs: inputs,
                            });
                        }
                    });
                    return results;
                }
            """)
            return forms
        except Exception:
            return []

    async def get_url_params(self) -> list[str]:
        """Get query parameter names from current URL."""
        try:
            params = await self.page.evaluate("""
                () => {
                    const params = new URLSearchParams(window.location.search);
                    return [...params.keys()];
                }
            """)
            return params
        except Exception:
            return []

    async def fill_and_submit_form(
        self,
        form_index: int,
        field_name: str,
        payload: str,
        safe_values: Optional[dict] = None,
    ) -> tuple[str, dict]:
        """Fill a form field with payload and submit. Returns (page_source, network_pair)."""
        self.reset_dialog()
        self.network.clear()
        try:
            result = await self.page.evaluate(
                """
                async ([formIndex, fieldName, payload, safeValues, authUser, authPass]) => {
                    const forms = document.querySelectorAll('form');
                    const form = forms[formIndex];
                    if (!form) return {success: false, error: 'form not found'};

                    // Infer a safe, type-valid value for a field so HTML5 validation passes.
                    function getSafeValue(el) {
                        const type = (el.type || 'text').toLowerCase();
                        const name = (el.name || el.id || '').toLowerCase();
                        const ph   = (el.placeholder || '').toLowerCase();
                        const hint = name + ' ' + ph;

                        // --- Auth fields (highest priority) ---
                        if (type === 'password') return authPass || 'Test1234!';
                        if (authUser && /user|email|login|account|mail/.test(hint)) return authUser;

                        // --- Input type ---
                        if (type === 'email')          return authUser && authUser.includes('@') ? authUser : 'tester@example.com';
                        if (type === 'url')            return 'https://example.com';
                        if (type === 'tel')            return '090-0000-0000';
                        if (type === 'color')          return '#000000';
                        if (type === 'date')           return '2000-01-01';
                        if (type === 'datetime-local') return '2000-01-01T00:00';
                        if (type === 'time')           return '12:00';
                        if (type === 'month')          return '2000-01';
                        if (type === 'week')           return '2000-W01';
                        if (type === 'range' || type === 'number') {
                            const min = parseFloat(el.min);
                            const max = parseFloat(el.max);
                            if (!isNaN(min) && min >= 0) return String(Math.ceil(min) || 1);
                            if (!isNaN(max) && max >= 1) return '1';
                            return '1';
                        }

                        // --- Hint-based (name / placeholder) ---
                        if (/email|mail/.test(hint))                      return 'tester@example.com';
                        if (/url|link|href|website|site/.test(hint))      return 'https://example.com';
                        if (/phone|tel|mobile|fax|cell/.test(hint))       return '090-0000-0000';
                        if (/zip|postal|post.code|postcode/.test(hint))   return '100-0001';
                        if (/age|year|num|qty|quantity|amount|price|cost|score|count|total|size|limit|page/.test(hint)) return '1';
                        if (/date/.test(hint))                            return '2000-01-01';
                        if (/address|addr/.test(hint))                    return '1-1 Test Street';
                        if (/city|town|prefecture|state|region/.test(hint)) return 'Tokyo';
                        if (/country/.test(hint))                         return 'Japan';
                        if (/comment|message|description|body|content|text|memo|note/.test(hint)) return 'test message';
                        if (/pass|password|passwd|pwd/.test(hint))        return 'Test1234!';
                        if (/first.?name|given.?name/.test(hint))         return 'Taro';
                        if (/last.?name|family.?name|surname/.test(hint)) return 'Yamada';
                        if (/name/.test(hint))                            return authUser || 'TaroYamada';
                        if (/title|subject/.test(hint))                   return 'Test Title';

                        return safeValues && safeValues[el.name || el.id] ? safeValues[el.name || el.id] : 'test';
                    }

                    function dispatchEvents(el) {
                        ['input', 'change', 'blur'].forEach(evt =>
                            el.dispatchEvent(new Event(evt, {bubbles: true}))
                        );
                    }

                    const allInputs = form.querySelectorAll(
                        'input:not([type=submit]):not([type=button]):not([type=reset]):not([type=image]):not([type=file]), textarea, select'
                    );

                    // Fill all inputs with safe / auth values first
                    allInputs.forEach(el => {
                        if (el.type === 'checkbox' || el.type === 'radio' || el.type === 'hidden') return;
                        if (el.tagName === 'SELECT') {
                            // Pick first non-empty option (value="" is empty; "0" is valid)
                            const opts = Array.from(el.options).filter(o => o.value !== '');
                            if (opts.length) { el.value = opts[0].value; dispatchEvents(el); }
                            return;
                        }
                        el.value = getSafeValue(el);
                        dispatchEvents(el);
                    });

                    // Fill target field with payload (overrides safe fill)
                    const target = Array.from(allInputs).find(
                        el => (el.name || el.id) === fieldName
                    );
                    if (target) {
                        target.value = payload;
                        dispatchEvents(target);
                    }

                    return {
                        success: true,
                        action: form.action || window.location.href,
                        method: (form.method || 'GET').toUpperCase()
                    };
                }
                """,
                [form_index, field_name, payload, safe_values or {}, self.auth_user, self.auth_pass],
            )

            # Check whether the form was found before attempting submit
            if not result or not result.get("success"):
                source = await self.get_page_source()
                return source, {}

            # Submit the form
            submit_btn = await self.page.query_selector(
                f"form:nth-of-type({form_index + 1}) [type=submit], "
                f"form:nth-of-type({form_index + 1}) button"
            )
            if submit_btn:
                await submit_btn.click()
            else:
                await self.page.evaluate(
                    f"document.querySelectorAll('form')[{form_index}].submit()"
                )

            await self.page.wait_for_load_state("domcontentloaded", timeout=self.timeout)
            _js_wait = 0.2 * self.sleep_factor
            if _js_wait > 0:
                await asyncio.sleep(_js_wait)

            source = await self.get_page_source()
            action_url = result.get("action") or self.page.url
            # アナリティクス等の別 URL ビーコンを掴まないよう、対象ページを最も
            # よく表すペアを選ぶ（同一オリジンの文書本体を優先）。
            pair = self.network.best_pair_for_page(action_url) or self.network.latest() or {}
            return source, pair
        except Exception as e:
            source = await self.get_page_source()
            return source, {}

    async def fill_and_submit_form_multi(
        self,
        form_index: int,
        field_payloads: dict,
    ) -> tuple[str, dict]:
        """
        Fill *multiple* form fields with their respective payloads and submit.

        field_payloads: {field_name: payload_string, ...}
        All non-specified fields receive safe/auth values (same as fill_and_submit_form).
        Returns (page_source, network_pair).
        """
        self.reset_dialog()
        self.network.clear()
        try:
            result = await self.page.evaluate(
                """
                async ([formIndex, fieldPayloads, authUser, authPass]) => {
                    const forms = document.querySelectorAll('form');
                    const form = forms[formIndex];
                    if (!form) return {success: false, error: 'form not found'};

                    function getSafeValue(el) {
                        const type = (el.type || 'text').toLowerCase();
                        const name = (el.name || el.id || '').toLowerCase();
                        const ph   = (el.placeholder || '').toLowerCase();
                        const hint = name + ' ' + ph;
                        if (type === 'password') return authPass || 'Test1234!';
                        if (authUser && /user|email|login|account|mail/.test(hint)) return authUser;
                        if (type === 'email')          return authUser && authUser.includes('@') ? authUser : 'tester@example.com';
                        if (type === 'url')            return 'https://example.com';
                        if (type === 'tel')            return '090-0000-0000';
                        if (type === 'color')          return '#000000';
                        if (type === 'date')           return '2000-01-01';
                        if (type === 'datetime-local') return '2000-01-01T00:00';
                        if (type === 'time')           return '12:00';
                        if (type === 'month')          return '2000-01';
                        if (type === 'week')           return '2000-W01';
                        if (type === 'range' || type === 'number') {
                            const min = parseFloat(el.min);
                            if (!isNaN(min) && min >= 0) return String(Math.ceil(min) || 1);
                            return '1';
                        }
                        if (/email|mail/.test(hint))      return 'tester@example.com';
                        if (/url|link|href|website/.test(hint)) return 'https://example.com';
                        if (/phone|tel|mobile|fax/.test(hint))  return '090-0000-0000';
                        if (/zip|postal|postcode/.test(hint))   return '100-0001';
                        if (/age|year|num|qty|quantity|amount|price|count|score/.test(hint)) return '1';
                        if (/date/.test(hint))                  return '2000-01-01';
                        if (/comment|message|description|body|content|text/.test(hint)) return 'test message';
                        if (/pass|password|passwd|pwd/.test(hint)) return 'Test1234!';
                        if (/name/.test(hint))                  return authUser || 'TaroYamada';
                        if (/title|subject/.test(hint))         return 'Test Title';
                        return 'test';
                    }

                    function dispatchEvents(el) {
                        ['input', 'change', 'blur'].forEach(evt =>
                            el.dispatchEvent(new Event(evt, {bubbles: true}))
                        );
                    }

                    const allInputs = form.querySelectorAll(
                        'input:not([type=submit]):not([type=button]):not([type=reset]):not([type=image]):not([type=file]), textarea, select'
                    );

                    // Fill non-targeted fields with safe / auth values first
                    allInputs.forEach(el => {
                        if (el.type === 'checkbox' || el.type === 'radio' || el.type === 'hidden') return;
                        if (el.tagName === 'SELECT') {
                            const opts = Array.from(el.options).filter(o => o.value !== '');
                            if (opts.length) { el.value = opts[0].value; dispatchEvents(el); }
                            return;
                        }
                        el.value = getSafeValue(el);
                        dispatchEvents(el);
                    });

                    // Override targeted fields with their attack payloads
                    for (const [fieldName, payload] of Object.entries(fieldPayloads)) {
                        const target = Array.from(allInputs).find(
                            el => (el.name || el.id) === fieldName
                        );
                        if (target) { target.value = payload; dispatchEvents(target); }
                    }
                    return {
                        success: true,
                        action: form.action || window.location.href,
                        method: (form.method || 'GET').toUpperCase()
                    };
                }
                """,
                [form_index, field_payloads, self.auth_user, self.auth_pass],
            )

            if not result or not result.get("success"):
                source = await self.get_page_source()
                return source, {}

            submit_btn = await self.page.query_selector(
                f"form:nth-of-type({form_index + 1}) [type=submit], "
                f"form:nth-of-type({form_index + 1}) button"
            )
            if submit_btn:
                await submit_btn.click()
            else:
                await self.page.evaluate(
                    f"document.querySelectorAll('form')[{form_index}].submit()"
                )

            await self.page.wait_for_load_state("domcontentloaded", timeout=self.timeout)
            _js_wait = 0.2 * self.sleep_factor
            if _js_wait > 0:
                await asyncio.sleep(_js_wait)

            source = await self.get_page_source()
            action_url = result.get("action") or self.page.url
            # アナリティクス等の別 URL ビーコンを掴まないよう、対象ページを最も
            # よく表すペアを選ぶ（同一オリジンの文書本体を優先）。
            pair = self.network.best_pair_for_page(action_url) or self.network.latest() or {}
            return source, pair
        except Exception:
            source = await self.get_page_source()
            return source, {}

    async def test_url_param(self, base_url: str, param: str, payload: str) -> tuple[str, dict]:
        """Test a URL parameter with a payload."""
        self.reset_dialog()
        self.network.clear()
        from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

        parsed = urlparse(base_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        test_url = urlunparse(parsed._replace(query=new_query))

        await self.navigate(test_url)
        _nav_wait = 0.1 * self.sleep_factor
        if _nav_wait > 0:
            await asyncio.sleep(_nav_wait)
        source = await self.get_page_source()
        # 完全一致（クエリ込み）を最優先し、無ければ同一オリジンの文書本体を選ぶ。
        # 別オリジンのアナリティクス POST を誤って掴まないため。
        pair = (
            self.network.latest_for_url(test_url)
            or self.network.best_pair_for_page(test_url)
            or self.network.latest()
            or {}
        )
        return source, pair

    async def collect_links(self, base_url: str, same_domain: bool = True) -> list[str]:
        """Collect navigable URLs from links, forms, data attributes, and inline JS."""
        try:
            links = await self.page.evaluate("""
                (baseUrl) => {
                    const parsed = new URL(baseUrl);
                    const links = new Set();
                    const ignoredExt = /\\.(?:png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|map|pdf|zip)(?:[?#].*)?$/i;

                    function addCandidate(raw) {
                        if (!raw || typeof raw !== 'string') return;
                        let candidate = raw.trim();
                        if (!candidate || candidate === '#' || candidate.startsWith('javascript:') || candidate.startsWith('mailto:') || candidate.startsWith('tel:')) return;
                        candidate = candidate.replace(/[\\s"'`<>)}\\],;]+$/g, '');
                        try {
                            const url = new URL(candidate, baseUrl);
                            if (url.protocol === 'http:' || url.protocol === 'https:') {
                                if (ignoredExt.test(url.pathname)) return;
                                links.add(url.href.split('#')[0]);
                            }
                        } catch(e) {}
                    }

                    document.querySelectorAll('a[href], area[href], form[action], iframe[src], frame[src]').forEach(el => {
                        addCandidate(el.getAttribute('href') || el.getAttribute('action') || el.getAttribute('src') || '');
                    });

                    document.querySelectorAll('[data-href], [data-url], [data-route], [data-path], [data-api], [data-endpoint]').forEach(el => {
                        ['data-href', 'data-url', 'data-route', 'data-path', 'data-api', 'data-endpoint'].forEach(attr => {
                            addCandidate(el.getAttribute(attr) || '');
                        });
                    });

                    const urlRe = /(?:https?:\\/\\/[^\\s"'`<>\\)\\]}]+|(?:\\.\\.\\/|\\.\\/|\\/)[A-Za-z0-9_~!$&()*+,;=:@.%\\/?-]+)/g;
                    document.querySelectorAll('script:not([src])').forEach(script => {
                        const text = script.textContent || '';
                        for (const match of text.matchAll(urlRe)) {
                            addCandidate(match[0]);
                        }
                    });

                    return [...links];
                }
            """, base_url)
            links.extend(self._collect_urls_from_loaded_assets(base_url))
            if same_domain:
                base = urlparse(base_url)
                links = [l for l in links if urlparse(l).netloc == base.netloc]
            return list(dict.fromkeys(links))
        except Exception:
            return []

    async def collect_links_rich(self, base_url: str, same_domain: bool = True) -> list[dict]:
        """Collect navigable links together with the element that produces them.

        Returns a list of ``{url, text, selector, rect, viewport}`` entries so the
        transition diagram can show *which* link/button leads to each page and
        *where* on the page it sits. ``rect`` is in viewport pixels (matching the
        viewport-only screenshot), ``viewport`` is the page viewport size.
        """
        try:
            entries = await self.page.evaluate("""
                (baseUrl) => {
                    const parsed = new URL(baseUrl);
                    const ignoredExt = /\\.(?:png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|map|pdf|zip)(?:[?#].*)?$/i;
                    const out = [];
                    const seen = new Set();

                    function selectorFor(el) {
                        if (el.id) return '#' + el.id;
                        const tag = el.tagName.toLowerCase();
                        const name = el.getAttribute('name');
                        if (name) return tag + '[name="' + name + '"]';
                        const cls = (el.className && typeof el.className === 'string')
                            ? '.' + el.className.trim().split(/\\s+/).slice(0, 2).join('.') : '';
                        return tag + cls;
                    }

                    function consider(el, raw) {
                        if (!raw || typeof raw !== 'string') return;
                        let candidate = raw.trim();
                        if (!candidate || candidate === '#' || candidate.startsWith('javascript:')
                            || candidate.startsWith('mailto:') || candidate.startsWith('tel:')) return;
                        candidate = candidate.replace(/[\\s"'`<>)}\\],;]+$/g, '');
                        let url;
                        try {
                            url = new URL(candidate, baseUrl);
                        } catch (e) { return; }
                        if (url.protocol !== 'http:' && url.protocol !== 'https:') return;
                        if (ignoredExt.test(url.pathname)) return;
                        const clean = url.href.split('#')[0];
                        if (seen.has(clean)) return;   // first element wins
                        seen.add(clean);
                        const r = el.getBoundingClientRect();
                        const text = (el.innerText || el.textContent || el.value
                            || el.getAttribute('aria-label') || el.getAttribute('title') || '').trim();
                        out.push({
                            url: clean,
                            text: text.slice(0, 120),
                            selector: selectorFor(el),
                            rect: { x: Math.round(r.left), y: Math.round(r.top),
                                    w: Math.round(r.width), h: Math.round(r.height) },
                            viewport: { w: window.innerWidth, h: window.innerHeight }
                        });
                    }

                    document.querySelectorAll('a[href], area[href], form[action], iframe[src], frame[src]').forEach(el => {
                        consider(el, el.getAttribute('href') || el.getAttribute('action') || el.getAttribute('src') || '');
                    });
                    document.querySelectorAll('[data-href], [data-url], [data-route], [data-path]').forEach(el => {
                        ['data-href', 'data-url', 'data-route', 'data-path'].forEach(attr => {
                            consider(el, el.getAttribute(attr) || '');
                        });
                    });
                    return out;
                }
            """, base_url)
            if same_domain:
                base = urlparse(base_url)
                entries = [e for e in entries if urlparse(e["url"]).netloc == base.netloc]
            # Preserve the full discovery surface of collect_links() (inline-script URLs,
            # data-api/data-endpoint, loaded JS/JSON assets). Any URL without an associated
            # DOM element is added with a null ``via`` so crawl coverage is not reduced.
            seen = {e["url"] for e in entries}
            try:
                for url in await self.collect_links(base_url, same_domain=same_domain):
                    if url not in seen:
                        seen.add(url)
                        entries.append({"url": url, "text": "", "selector": "",
                                        "rect": None, "viewport": None})
            except Exception:
                pass
            return entries
        except Exception:
            return []

    def _collect_urls_from_loaded_assets(self, base_url: str) -> list[str]:
        """Extract same-site route/API candidates from loaded JS/JSON assets."""
        discovered: list[str] = []
        ignored_ext = re.compile(
            r"\.(?:png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|map|pdf|zip)(?:[?#].*)?$",
            re.IGNORECASE,
        )
        url_re = re.compile(
            r"(?:https?://[^\s\"'`<>\)\]\}]+|(?:\.\./|\./|/)[A-Za-z0-9_~!$&()*+,;=:@.%/?-]+)"
        )
        for pair in list(self.network.pairs):
            resp = pair.get("response", {}) if isinstance(pair, dict) else {}
            req = pair.get("request", {}) if isinstance(pair, dict) else {}
            source_url = resp.get("url") or req.get("url") or ""
            headers = resp.get("headers", {}) or {}
            content_type = str(headers.get("content-type", "")).lower()
            body = resp.get("body") or ""
            if not body:
                continue
            is_text_asset = (
                "javascript" in content_type
                or "json" in content_type
                or source_url.split("?", 1)[0].endswith((".js", ".mjs", ".json"))
            )
            if not is_text_asset:
                continue
            scan_body = body[:200000]
            for m in url_re.finditer(scan_body):
                # 0009 C1: url_re は regex メタ文字（| [ ] \ ^ { }）の手前で match を
                # 打ち切るため、`/foo|bar/`→`/foo` のように切り詰めた regex 片が一見正常な
                # path に見えて通過する。match 直後の1文字が regex 継続文字なら、regex
                # リテラルの切り詰めとして抽出時に弾く（切り詰め前の証拠を見る）。
                if truncated_regex_literal(scan_body[m.end():m.end() + 1]):
                    continue
                candidate = m.group(0).rstrip(" \t\r\n\"'`<>)}],;")
                try:
                    resolved = urljoin(base_url, candidate)
                    parsed = urlparse(resolved)
                    if parsed.scheme not in {"http", "https"}:
                        continue
                    if ignored_ext.search(parsed.path):
                        continue
                    cleaned = resolved.split("#")[0]
                    # 切り詰め後の候補も、regex リテラル/式片の誤抽出を純粋関数で除去する
                    # （無駄クロール＋planner LLM 浪費＋実ルート到達阻害を防ぐ）。判定は
                    # 保守的で実ルートは落とさない。
                    if not is_plausible_route_candidate(cleaned):
                        continue
                    discovered.append(cleaned)
                except Exception:
                    continue
        return discovered

    async def set_cookies(self, cookies_str: str, url: str):
        """Set cookies from a 'name=value; name2=value2' string."""
        if not cookies_str or not self._context:
            return
        domain = _urlparse(url).hostname or ""
        cookies = []
        for part in cookies_str.split(";"):
            part = part.strip()
            if "=" in part:
                name, _, value = part.partition("=")
                cookies.append({
                    "name": name.strip(),
                    "value": value.strip(),
                    "domain": domain,
                    "path": "/",
                })
        if cookies:
            await self._context.add_cookies(cookies)

    async def set_cookies_from_list(self, cookie_list: list, url: str):
        """Set cookies from a list of dicts (browser JSON export format).

        Each dict should have at least 'name' and 'value'.  Optional keys:
        'domain', 'path', 'secure', 'httpOnly', 'sameSite'.
        """
        if not cookie_list or not self._context:
            return
        default_domain = _urlparse(url).hostname or ""
        normalized = []
        for c in cookie_list:
            if not c.get("name") or c.get("value") is None:
                continue
            normalized.append({
                "name": c["name"],
                "value": str(c["value"]),
                "domain": c.get("domain") or default_domain,
                "path": c.get("path") or "/",
            })
        if normalized:
            await self._context.add_cookies(normalized)

    async def auto_login(
        self,
        login_url: str,
        user_field: str = "username",
        pass_field: str = "password",
        success_indicator: str = "",
    ) -> bool:
        """
        Navigate to *login_url*, fill *user_field* / *pass_field* with
        self.auth_user / self.auth_pass, submit the form, and return True
        if login appears successful.

        *success_indicator*: substring expected in the post-login URL or
        page body to confirm success (e.g. '/dashboard').  If empty, the
        method returns True as long as the URL changed after submission.
        """
        if not self.auth_user or not self.auth_pass:
            return False
        try:
            self.last_login_url = ""
            self.last_login_success = False
            await self.navigate(login_url)

            # Use Playwright's native fill() where possible so JS framework
            # handlers receive realistic input events; fall back to JS assignment
            # for unusual fields.
            async def _fill_field(selector: str, value: str) -> bool:
                try:
                    await self.page.fill(selector, value, timeout=5000)
                    return True
                except Exception:
                    return bool(await self.page.evaluate(
                        """([sel, val]) => {
                            const el = document.querySelector(sel);
                            if (!el) return false;
                            el.focus();
                            el.value = val;
                            ['input','change','blur'].forEach(e =>
                                el.dispatchEvent(new Event(e, {bubbles:true}))
                            );
                            return true;
                        }""",
                        [selector, value],
                    ))

            user_selector = f'[name="{user_field}"],[id="{user_field}"]'
            pass_selector = f'[name="{pass_field}"],[id="{pass_field}"]'
            if not await _fill_field(user_selector, self.auth_user):
                return False
            if not await _fill_field(pass_selector, self.auth_pass):
                return False

            # MFA（メール）の baseline をパスワード送信前に確保する。送信で OTP メールが
            # 飛ぶため、ここで「送信前から受信箱にある古いメール」を記録しておくと、
            # 送信後に届く新着のみを solve() で対象にできる（古いコードの誤投入防止）。
            mfa_solver = getattr(self, "mfa_solver", None)
            if mfa_solver is not None and mfa_solver.enabled:
                try:
                    await mfa_solver.prime()
                except Exception:
                    pass

            submitted = False
            try:
                submit_btn = self.page.locator(user_selector).locator("xpath=ancestor::form").locator(
                    'button[type="submit"],input[type="submit"],[type="submit"],button:not([type="button"])'
                ).first
                await submit_btn.click(timeout=5000, no_wait_after=True)
                submitted = True
            except Exception:
                pass

            if not submitted:
                submit_script = """([userField]) => {
                    function _find(sel) {
                        try {
                            const direct = document.querySelector(sel);
                            if (direct) return direct;
                        } catch (e) {}
                        return document.querySelector(
                            `[name="${CSS.escape(sel)}"],[id="${CSS.escape(sel)}"]`
                        );
                    }
                    const el = _find(userField);
                    if (!el) return;
                    const form = el.closest('form');
                    if (!form) return;
                    const btn = form.querySelector(
                        'button[type="submit"],input[type="submit"],[type="submit"]'
                    ) || form.querySelector('button:not([type="button"])');
                    if (btn) { btn.click(); }
                    else { form.submit(); }
                }"""
                try:
                    async with self.page.expect_navigation(wait_until="domcontentloaded", timeout=15000):
                        await self.page.evaluate(submit_script, [user_field])
                except Exception:
                    # AJAX logins or same-document updates may not navigate. The
                    # polling loop below still evaluates the resulting body and URL.
                    pass

            # MFA（2FA）チャレンジ: パスワード送信後にワンタイムコード入力が
            # 要求される場合、外部 MCP 経由でコードを取得して投入する。未設定・
            # 非該当時は何もしない（従来挙動を維持）。
            mfa_field = ""
            mfa_solver = getattr(self, "mfa_solver", None)
            if mfa_solver is not None and mfa_solver.enabled:
                from . import mfa as _mfa
                mfa_field = mfa_solver.field or "otp"
                mfa_status = await self._handle_mfa_challenge(success_indicator)
                if mfa_status == "failed":
                    # MFA 画面を検出したがコード取得/投入に失敗。未認証のまま
                    # 「login_url から移動した」だけで成功と誤判定しないよう、
                    # ここで失敗を確定する。
                    self.last_login_url = self.page.url
                    self.last_login_success = False
                    return False

            from . import auth_detect as _auth
            deadline = time.monotonic() + 15.0
            post_url = self.page.url
            post_body = ""
            while time.monotonic() < deadline:
                try:
                    await self.page.wait_for_load_state("domcontentloaded", timeout=1000)
                except Exception:
                    pass
                post_url = self.page.url
                post_body = await self.get_page_source()
                # MFA 画面に留まっている間は成功と判定しない（/mfa への遷移を誤認しない）。
                on_mfa = bool(mfa_field) and _mfa.mfa_challenge_present(post_body, mfa_field)
                # 判定は純粋関数へ集約。URL の変化だけでなく「ログインフォームが
                # 残っていないか」「失敗文言が無いか」「ログインページから離脱したか」
                # を併せて評価し、/login?error= のような「移動はしたが失敗」を弾く。
                if _auth.login_succeeded(
                    post_url=post_url,
                    login_url=login_url,
                    body=post_body,
                    mfa_present=on_mfa,
                    success_indicator=success_indicator,
                ):
                    self.last_login_url = post_url
                    self.last_login_success = True
                    return True
                await asyncio.sleep(0.25)
            self.last_login_url = post_url
            return False
        except Exception:
            return False

    async def _handle_mfa_challenge(self, success_indicator: str = "") -> str:
        """パスワード送信後に MFA コード入力画面が出たら自動で突破する。

        最大 10 秒 MFA 画面の出現を待ち（強いシグナル or 設定されたコード入力欄の
        存在で検出）、出たら外部 MCP からコードを取得して入力欄へ投入・送信する。

        戻り値:
        - ``"not_present"`` … MFA 画面は現れなかった／既にログイン済み（従来挙動）。
        - ``"solved"``      … コードを取得し入力欄へ投入・送信した。
        - ``"failed"``      … MFA 画面は検出したが、コード取得や投入に失敗した。
        """
        from . import mfa as _mfa

        field = self.mfa_solver.field or "otp"

        # 検出フェーズ: ここでの例外は「MFA 無し」とみなし従来挙動へ委ねる。
        try:
            deadline = time.monotonic() + 10.0
            detected = False
            while time.monotonic() < deadline:
                try:
                    await self.page.wait_for_load_state("domcontentloaded", timeout=1000)
                except Exception:
                    pass
                body = await self.get_page_source()
                # 既に成功条件を満たしていれば MFA 不要。
                if success_indicator and (
                    success_indicator in self.page.url or success_indicator in body
                ):
                    return "not_present"
                if _mfa.mfa_challenge_present(body, field):
                    detected = True
                    break
                await asyncio.sleep(0.3)
            if not detected:
                return "not_present"
        except Exception:
            return "not_present"

        # 解決フェーズ: 検出後の失敗は "failed"（未認証のまま成功扱いにしない）。
        try:
            code = await self.mfa_solver.solve()
            if not code:
                return "failed"

            # コード入力欄を埋める。設定欄 → 一般的な OTP 入力欄の順に試す。
            candidates = [
                f'[name="{field}"],[id="{field}"]',
                'input[autocomplete="one-time-code"]',
                'input[name*="otp" i],input[id*="otp" i]',
                'input[name*="code" i],input[id*="code" i]',
                'input[name*="token" i],input[id*="token" i]',
            ]
            used = ""
            for sel in candidates:
                try:
                    await self.page.fill(sel, code, timeout=3000)
                    used = sel
                    break
                except Exception:
                    continue
            if not used:
                return "failed"

            # 送信（同フォームの submit ボタン → 失敗時は Enter）。
            try:
                submit_btn = self.page.locator(used).locator(
                    "xpath=ancestor::form"
                ).locator(
                    'button[type="submit"],input[type="submit"],[type="submit"],'
                    'button:not([type="button"])'
                ).first
                await submit_btn.click(timeout=5000, no_wait_after=True)
            except Exception:
                try:
                    await self.page.keyboard.press("Enter")
                except Exception:
                    pass
            return "solved"
        except Exception:
            return "failed"

    def is_on_login_page(self, login_url: str) -> bool:
        """
        Return True when the browser appears to have been redirected back to the
        login page (session expired or unauthenticated access).

        Checks:
        1. Current URL matches the configured login URL.
        2. Current URL contains common login path segments when login_url is empty.
        """
        if not self.page:
            return False
        current = self.page.url.rstrip("/").lower()
        if login_url:
            if current == login_url.rstrip("/").lower():
                return True
            # Also catch redirects like /login?next=... or /login#...
            from urllib.parse import urlparse
            cur_path = urlparse(current).path
            login_path = urlparse(login_url.lower()).path
            if login_path and cur_path == login_path:
                return True
        else:
            # Heuristic: URL contains login/signin/auth keywords
            for kw in ("/login", "/signin", "/sign-in", "/auth/login", "/account/login"):
                if current.endswith(kw) or (kw + "?") in current or (kw + "#") in current:
                    return True
        return False

    async def create_worker(self) -> "WorkerBrowser":
        """
        Create an additional browser page for concurrent scanning.
        The worker shares the same browser context (cookies) as the main page
        but has its own Playwright page, network capture, and dialog state.
        """
        page = await self._context.new_page()
        if self._header_intercept_mode == "cdp":
            # context の page イベントと競合しても attach 側の task ガードで
            # Fetch.enable は一度だけになる。worker の初回遷移前を明示保証する。
            await self._attach_header_interception(page)
        page.set_default_timeout(self.timeout)
        worker = WorkerBrowser(self, page)
        page.on("request", worker.network.on_request)
        page.on("response", worker._on_response)
        page.on("dialog", worker._on_dialog)
        return worker

    # ------------------------------------------------------------------
    # ① SPA/Dynamic content crawl exploration
    # ------------------------------------------------------------------

    async def explore_spa_interactions(
        self,
        page,
        base_url: str,
        max_clicks: int = 30,
    ) -> list[str]:
        """
        Explore client-side navigation by:
          1. Hooking history.pushState / history.replaceState to record URL changes.
          2. Clicking interactive elements (buttons, role=tab, role=link, nav links).
          3. Returning the list of newly discovered virtual routes.

        Returns a de-duplicated list of URLs discovered via SPA routing.
        """
        discovered: list[str] = []

        # Inject pushState hook before interacting
        hook_script = """
        (() => {
            if (window.__wscan_spa_hooked) return;
            window.__wscan_spa_hooked = true;
            window.__wscan_spa_urls = [];
            const _push = history.pushState.bind(history);
            const _replace = history.replaceState.bind(history);
            history.pushState = function(state, title, url) {
                if (url) window.__wscan_spa_urls.push(String(url));
                return _push(state, title, url);
            };
            history.replaceState = function(state, title, url) {
                if (url) window.__wscan_spa_urls.push(String(url));
                return _replace(state, title, url);
            };
            window.addEventListener('popstate', () => {
                window.__wscan_spa_urls.push(window.location.href);
            });
        })();
        """
        try:
            await page.evaluate(hook_script)
        except Exception:
            pass

        # Collect interactive elements to click
        selectors = [
            "a[data-href]",
            "[role='tab']",
            "[role='link']",
            "nav a",
            "header a",
            ".menu a",
            ".nav a",
            ".sidebar a",
            "button[data-route]",
            "button[data-path]",
            "[data-page]",
        ]

        clicked = 0
        seen_urls: set[str] = set()
        current_url_before = page.url

        for sel in selectors:
            if clicked >= max_clicks:
                break
            try:
                elements = await page.query_selector_all(sel)
            except Exception:
                continue

            for el in elements[:10]:  # Cap per selector
                if clicked >= max_clicks:
                    break
                try:
                    # Don't click external links
                    href = await el.get_attribute("href") or ""
                    if href.startswith("http") and not href.startswith(
                        urlparse(base_url).scheme + "://" + urlparse(base_url).netloc
                    ):
                        continue

                    await el.click(timeout=3000)
                    await page.wait_for_load_state("domcontentloaded", timeout=5000)
                    clicked += 1

                    new_url = page.url
                    if new_url not in seen_urls and new_url != current_url_before:
                        seen_urls.add(new_url)
                        discovered.append(new_url)

                    # Collect any pushState URLs
                    spa_urls = await page.evaluate("window.__wscan_spa_urls || []")
                    for su in spa_urls:
                        if su not in seen_urls:
                            seen_urls.add(su)
                            # Resolve relative URLs
                            full = urljoin(base_url, su)
                            discovered.append(full)

                    # Navigate back to not get lost
                    if page.url != current_url_before:
                        try:
                            await page.go_back(timeout=5000)
                            await page.wait_for_load_state("domcontentloaded", timeout=5000)
                            # Re-inject hook after navigation
                            await page.evaluate(hook_script)
                        except Exception:
                            pass

                except Exception:
                    continue

        # Final flush of pushState-captured URLs
        try:
            spa_urls = await page.evaluate("window.__wscan_spa_urls || []")
            for su in spa_urls:
                full = urljoin(base_url, su)
                if full not in seen_urls:
                    seen_urls.add(full)
                    discovered.append(full)
        except Exception:
            pass

        return list(dict.fromkeys(discovered))  # preserve order, deduplicate

    # ------------------------------------------------------------------
    # A — Multi-account session management
    # ------------------------------------------------------------------

    async def create_session_for_account(
        self,
        username: str,
        password: str,
        login_url: str,
        user_field: str = "username",
        pass_field: str = "password",
        success_indicator: str = "",
    ) -> Optional[str]:
        """
        Open an isolated browser context, log in with the given credentials,
        capture the resulting cookies, close the context, and return a
        cookie string ("name=value; name2=value2") or None on failure.
        """
        if not self._browser:
            return None

        ctx = await self._browser.new_context(
            ignore_https_errors=True,
            proxy={"server": self.proxy} if self.proxy else None,
        )
        try:
            page = await ctx.new_page()
            page.set_default_timeout(self.timeout)

            # Navigate to login page
            await page.goto(login_url, wait_until="domcontentloaded")

            # Fill credentials
            await page.evaluate(
                """([userField, passField, user, pw]) => {
                    function _fill(sel, val) {
                        const el = document.querySelector(
                            `[name="${sel}"],[id="${sel}"]`
                        );
                        if (!el) return;
                        el.value = val;
                        ['input','change','blur'].forEach(e =>
                            el.dispatchEvent(new Event(e, {bubbles:true}))
                        );
                    }
                    _fill(userField, user);
                    _fill(passField, pw);
                }""",
                [user_field, pass_field, username, password],
            )

            # Submit the form
            await page.evaluate(
                """([userField]) => {
                    const el = document.querySelector(`[name="${userField}"],[id="${userField}"]`);
                    if (!el) return;
                    const form = el.closest('form');
                    if (!form) return;
                    const btn = form.querySelector(
                        'button[type="submit"],input[type="submit"],[type="submit"]'
                    ) || form.querySelector('button:not([type="button"])');
                    if (btn) btn.click(); else form.submit();
                }""",
                [user_field],
            )

            await page.wait_for_load_state("domcontentloaded", timeout=15000)

            post_url = page.url
            post_body = ""
            try:
                post_body = await page.content()
            except Exception:
                pass

            # Check success
            if success_indicator:
                if success_indicator not in post_url and success_indicator not in post_body:
                    return None
            else:
                if post_url.rstrip("/") == login_url.rstrip("/"):
                    return None

            # Extract cookies
            cookies = await ctx.cookies()
            cookie_str = "; ".join(
                f"{c['name']}={c['value']}"
                for c in cookies
                if c.get("name") and c.get("value") is not None
            )
            return cookie_str if cookie_str else None

        except Exception:
            return None
        finally:
            try:
                await ctx.close()
            except Exception:
                pass

    async def close(self):
        """Close browser and playwright."""
        try:
            await self._deactivate_header_target_auto_attach()
            self._header_interception_closing = True
            if self._context:
                try:
                    self._context.remove_listener(
                        "page",
                        self._on_header_context_page,
                    )
                except Exception:
                    pass
            if self._header_page_tasks:
                await asyncio.gather(
                    *list(self._header_page_tasks),
                    return_exceptions=True,
                )
            for cdp in list(self._header_cdp_sessions.values()):
                try:
                    await cdp.send("Fetch.disable")
                except Exception:
                    pass
                try:
                    await cdp.detach()
                except Exception:
                    pass
            if self._header_pause_tasks:
                await asyncio.gather(
                    *list(self._header_pause_tasks),
                    return_exceptions=True,
                )
            self._header_cdp_sessions.clear()
            self._header_attached_page_ids.clear()
            self._header_explicit_target_ids.clear()
            self._header_attach_tasks.clear()
            self._header_intercept_mode = "none"
            self._header_route_active = False
            self._header_debug_port = None
            if self._context:
                await self._context.close()
            if self._browser:
                await self._browser.close()
            if self._playwright:
                await self._playwright.stop()
        except Exception:
            pass


class WorkerBrowser(BrowserManager):
    """
    A BrowserManager slice for one concurrent page worker.

    Inherits ALL methods from BrowserManager so scanners don't need any changes.
    The key difference: ``self.page`` points to this worker's dedicated Playwright
    page instead of the main page, so all navigation / form-filling / screenshot
    operations are fully isolated.  The shared browser context (cookies, auth)
    comes from the real BrowserManager.
    """

    def __init__(self, real_browser: "BrowserManager", page):
        # Bypass BrowserManager.__init__ — we just copy the fields we need.
        self.headless = real_browser.headless
        self.timeout = real_browser.timeout
        self.monitor = real_browser.monitor
        self.auth_user = real_browser.auth_user
        self.auth_pass = real_browser.auth_pass
        # MFA ソルバも引き継ぐ（worker のセッション切れ再ログインでも MFA を解ける）。
        self.mfa_solver = getattr(real_browser, "mfa_solver", None)
        self.proxy = real_browser.proxy
        self.sleep_factor = real_browser.sleep_factor
        # SPA 描画確定待ちフラグを引き継ぐ（worker の attack navigate でも settle する）。
        self.spa_settle = getattr(real_browser, "spa_settle", False)
        self._playwright = real_browser._playwright
        self._browser = real_browser._browser
        self._context = real_browser._context      # Shared — cookies are inherited
        self._real = real_browser

        # Worker-private state
        self.page = page
        # Inherit the audit logger so concurrent workers also persist traffic.
        self.request_logger = getattr(real_browser, "request_logger", None)
        self.network = NetworkCapture(logger=self.request_logger)
        self.dialog_fired: bool = False
        self.dialog_message: str = ""
        self.dialog_screenshot_b64: str = ""

    async def close(self):
        """Close only this worker's page (not the whole browser)."""
        try:
            await self.page.close()
        except Exception:
            pass
