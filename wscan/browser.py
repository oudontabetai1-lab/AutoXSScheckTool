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

    def __init__(self):
        self.pairs: list[dict] = []
        # Use (url, id(request_object)) as key to avoid collisions when the same URL
        # is requested multiple times concurrently (race condition fix).
        self._pending: dict[tuple, dict] = {}

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
                body = safe_decode(await response.body())
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
    ):
        self.headless = headless
        self.timeout = timeout * 1000  # ms
        self.monitor = monitor
        self.auth_user = auth_user
        self.auth_pass = auth_pass
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
        self.network = NetworkCapture()
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
        # screenshot *before* dismissing. Bound it with a short timeout and
        # dismiss no matter what, so a flood of alert()-firing payloads (e.g. a
        # stored-XSS listing) can't freeze every later navigation.
        try:
            shot = await asyncio.wait_for(
                self.page.screenshot(full_page=False, type="jpeg", quality=80),
                timeout=3.0,
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
            pair = self.network.latest_for_url(action_url, match_query=False) or self.network.latest() or {}
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
            pair = self.network.latest_for_url(action_url, match_query=False) or self.network.latest() or {}
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
        pair = self.network.latest_for_url(test_url) or self.network.latest() or {}
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

            login_url_norm = login_url.rstrip("/")
            failure_markers = (
                "invalid login",
                "login failed",
                "incorrect password",
                "invalid password",
                "invalid credentials",
                "authentication failed",
            )
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
                body_lower = post_body.lower()
                if success_indicator:
                    if success_indicator in post_url or success_indicator in post_body:
                        self.last_login_url = post_url
                        self.last_login_success = True
                        return True
                else:
                    failed = any(marker in body_lower for marker in failure_markers)
                    moved = post_url.rstrip("/") != login_url_norm
                    if moved and not failed:
                        self.last_login_url = post_url
                        self.last_login_success = True
                        return True
                    if not self.is_on_login_page(login_url) and not failed:
                        self.last_login_url = post_url
                        self.last_login_success = True
                        return True
                await asyncio.sleep(0.25)
            self.last_login_url = post_url
            return False
        except Exception:
            return False

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
        self.proxy = real_browser.proxy
        self.sleep_factor = real_browser.sleep_factor
        self._playwright = real_browser._playwright
        self._browser = real_browser._browser
        self._context = real_browser._context      # Shared — cookies are inherited
        self._real = real_browser

        # Worker-private state
        self.page = page
        self.network = NetworkCapture()
        self.dialog_fired: bool = False
        self.dialog_message: str = ""
        self.dialog_screenshot_b64: str = ""

    async def close(self):
        """Close only this worker's page (not the whole browser)."""
        try:
            await self.page.close()
        except Exception:
            pass
