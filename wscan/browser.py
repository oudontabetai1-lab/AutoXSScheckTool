"""
WScan Browser Manager
Playwright-based browser automation with evidence collection.
"""
import asyncio
import base64
import re
import time
from urllib.parse import urlparse as _urlparse
from typing import Optional, Callable, Any
from urllib.parse import urljoin, urlparse

from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Request, Response
from .tls_config import TLSConfig


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
        # Custom HTTP headers (Authorization, X-API-Key, …) applied to every
        # request through the Playwright context. Updated live by HeaderManager
        # when ``--header-refresh-cmd`` rotates the token.
        self.extra_headers: dict[str, str] = dict(extra_headers or {})
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
        self._playwright = await async_playwright().start()
        launch_args = ["--disable-web-security", "--disable-features=IsolateOrigins"]
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
        if self.extra_headers:
            # Keep header names case-preserving but de-dupe case-insensitive collisions
            # so Playwright doesn't reject duplicates.
            seen: dict[str, str] = {}
            for k, v in self.extra_headers.items():
                seen[k.lower()] = v
                ctx_kwargs.setdefault("extra_http_headers", {})[k] = str(v)
        self._context = await self._browser.new_context(**ctx_kwargs)
        self.page = await self._context.new_page()
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
        """Replace the context-wide extra HTTP headers (used by the refresh task)."""
        self.extra_headers = dict(headers or {})
        if self._context is None:
            return
        try:
            await self._context.set_extra_http_headers(self.extra_headers)
        except Exception:
            # Older Playwright builds or already-closed contexts — swallow so a
            # rotating-token failure never aborts an in-progress scan.
            pass

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

        **誤検知抑制のため対象を二重に絞る**:
        1. ハンドラ値が今回投入した ``payload`` に含まれること（空白正規化して包含比較）、
        2. ``baseline_handlers``（payload 投入前 DOM のダイアログハンドラ）に対して
           **新規に増えた**ぶんだけ（多重集合の差分）。

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
                                    && fromPayload(attr.value) && isNew(attr.value)) {
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
                return True
            except Exception as e:
                self.last_navigation_error = f"{type(e).__name__}: {e}"
                if attempt + 1 >= attempts:
                    return False
                await asyncio.sleep(retry_delay * (attempt + 1))
        return False

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
            for match in url_re.findall(body[:200000]):
                candidate = match.rstrip(" \t\r\n\"'`<>)}],;")
                try:
                    resolved = urljoin(base_url, candidate)
                    parsed = urlparse(resolved)
                    if parsed.scheme not in {"http", "https"}:
                        continue
                    if ignored_ext.search(parsed.path):
                        continue
                    discovered.append(resolved.split("#")[0])
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
