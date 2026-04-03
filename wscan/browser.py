"""
WScan Browser Manager
Playwright-based browser automation with evidence collection.
"""
import asyncio
import base64
import time
from urllib.parse import urlparse as _urlparse
from typing import Optional, Callable, Any
from urllib.parse import urljoin, urlparse

from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Request, Response


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
        """Asynchronously get response body text."""
        try:
            body = await response.text()
            for pair in reversed(self.pairs):
                if pair["response"]["url"] == response.url:
                    pair["response"]["body"] = body[:50000]  # cap at 50KB
                    break
        except Exception:
            pass

    def latest(self) -> Optional[dict]:
        return self.pairs[-1] if self.pairs else None

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
    ):
        self.headless = headless
        self.timeout = timeout * 1000  # ms
        self.monitor = monitor
        self.auth_user = auth_user
        self.auth_pass = auth_pass
        self.proxy = proxy  # e.g. "http://127.0.0.1:8080"
        self._playwright = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self.network = NetworkCapture()
        self.dialog_fired: bool = False
        self.dialog_message: str = ""
        self.dialog_screenshot_b64: str = ""  # Screenshot taken right when alert fires

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
            "ignore_https_errors": True,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        }
        if self.proxy:
            ctx_kwargs["proxy"] = {"server": self.proxy}
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
        await dialog.dismiss()

    def reset_dialog(self):
        self.dialog_fired = False
        self.dialog_message = ""
        self.dialog_screenshot_b64 = ""

    async def navigate(self, url: str, wait_until: str = "domcontentloaded") -> bool:
        """Navigate to URL and return success."""
        try:
            self.network.clear()
            await self.page.goto(url, wait_until=wait_until, timeout=self.timeout)
            return True
        except Exception as e:
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
                            'input:not([type=hidden]):not([type=submit]):not([type=button]):not([type=reset]):not([type=image]):not([type=file]):not([type=checkbox]):not([type=radio]), textarea'
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

                    return {success: true};
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

            await self.page.wait_for_load_state("domcontentloaded", timeout=10000)
            await asyncio.sleep(0.5)  # short wait for any JS to run

            source = await self.get_page_source()
            pair = self.network.latest() or {}
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
            await self.page.evaluate(
                """
                async ([formIndex, fieldPayloads, authUser, authPass]) => {
                    const forms = document.querySelectorAll('form');
                    const form = forms[formIndex];
                    if (!form) return;

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
                }
                """,
                [form_index, field_payloads, self.auth_user, self.auth_pass],
            )

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

            await self.page.wait_for_load_state("domcontentloaded", timeout=10000)
            await asyncio.sleep(0.5)

            source = await self.get_page_source()
            pair = self.network.latest() or {}
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
        await asyncio.sleep(0.3)
        source = await self.get_page_source()
        pair = self.network.latest() or {}
        return source, pair

    async def collect_links(self, base_url: str, same_domain: bool = True) -> list[str]:
        """Collect all links on the current page."""
        try:
            links = await self.page.evaluate("""
                (baseUrl) => {
                    const parsed = new URL(baseUrl);
                    const links = new Set();
                    document.querySelectorAll('a[href]').forEach(a => {
                        try {
                            const url = new URL(a.href, baseUrl);
                            if (url.protocol === 'http:' || url.protocol === 'https:') {
                                links.add(url.href.split('#')[0]);
                            }
                        } catch(e) {}
                    });
                    return [...links];
                }
            """, base_url)
            if same_domain:
                base = urlparse(base_url)
                links = [l for l in links if urlparse(l).netloc == base.netloc]
            return links
        except Exception:
            return []

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
            await self.navigate(login_url)
            await self.page.evaluate(
                """([userField, passField, user, pw]) => {
                    function _fill(sel, val) {
                        const el = document.querySelector(
                            `[name="${sel}"],[id="${sel}"]`
                        );
                        if (!el) return false;
                        el.value = val;
                        ['input','change','blur'].forEach(e =>
                            el.dispatchEvent(new Event(e, {bubbles:true}))
                        );
                        return true;
                    }
                    _fill(userField, user);
                    _fill(passField, pw);
                }""",
                [user_field, pass_field, self.auth_user, self.auth_pass],
            )
            # Submit — prefer clicking the button so JS frameworks receive the event
            await self.page.evaluate(
                """([userField]) => {
                    const el = document.querySelector(`[name="${userField}"],[id="${userField}"]`);
                    if (!el) return;
                    const form = el.closest('form');
                    if (!form) return;
                    // Try submit button first (handles React/Vue event handlers)
                    const btn = form.querySelector(
                        'button[type="submit"],input[type="submit"],[type="submit"]'
                    ) || form.querySelector('button:not([type="button"])');
                    if (btn) { btn.click(); }
                    else { form.submit(); }
                }""",
                [user_field],
            )
            await self.page.wait_for_load_state("domcontentloaded", timeout=15000)
            post_url = self.page.url
            post_body = await self.get_page_source()
            if success_indicator:
                return success_indicator in post_url or success_indicator in post_body
            # Heuristic: no longer on the login URL → success
            return post_url.rstrip("/") != login_url.rstrip("/")
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
