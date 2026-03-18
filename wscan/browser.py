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
    ):
        self.headless = headless
        self.timeout = timeout * 1000  # ms
        self.monitor = monitor
        self.auth_user = auth_user
        self.auth_pass = auth_pass
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
        self._browser = await self._playwright.chromium.launch(
            headless=self.headless,
            args=["--disable-web-security", "--disable-features=IsolateOrigins"],
        )
        self._context = await self._browser.new_context(
            viewport={"width": 1280, "height": 800},
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        )
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

                    const allInputs = form.querySelectorAll(
                        'input:not([type=submit]):not([type=button]):not([type=reset]):not([type=image]):not([type=file]), textarea'
                    );

                    // Fill all inputs with safe/auth values first
                    allInputs.forEach(el => {
                        const name = (el.name || el.id || '').toLowerCase();
                        if (el.type === 'checkbox' || el.type === 'radio') return;
                        if (el.type === 'hidden') return;
                        if (el.type === 'password' && authPass) {
                            el.value = authPass;
                        } else if (authUser && (name.includes('user') || name.includes('email') ||
                                   name.includes('login') || name.includes('account') ||
                                   name.includes('mail') || name.includes('name'))) {
                            el.value = authUser;
                        } else {
                            const key = el.name || el.id || '';
                            el.value = (safeValues && safeValues[key]) ? safeValues[key] : 'test';
                        }
                    });

                    // Fill target field with payload (overrides auth fill)
                    const target = Array.from(allInputs).find(
                        el => (el.name || el.id) === fieldName
                    );
                    if (target) {
                        target.value = payload;
                    }

                    return {success: true};
                }
                """,
                [form_index, field_name, payload, safe_values or {}, self.auth_user, self.auth_pass],
            )

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

                    const allInputs = form.querySelectorAll(
                        'input:not([type=submit]):not([type=button]):not([type=reset]):not([type=image]):not([type=file]), textarea'
                    );

                    // Fill non-targeted fields with safe / auth values first
                    allInputs.forEach(el => {
                        if (el.type === 'checkbox' || el.type === 'radio' || el.type === 'hidden') return;
                        const name = (el.name || el.id || '').toLowerCase();
                        if (el.type === 'password' && authPass) {
                            el.value = authPass;
                        } else if (authUser && (name.includes('user') || name.includes('email') ||
                                   name.includes('login') || name.includes('account') ||
                                   name.includes('mail') || name.includes('name'))) {
                            el.value = authUser;
                        } else {
                            el.value = 'test';
                        }
                    });

                    // Override targeted fields with their attack payloads
                    for (const [fieldName, payload] of Object.entries(fieldPayloads)) {
                        const target = Array.from(allInputs).find(
                            el => (el.name || el.id) === fieldName
                        );
                        if (target) target.value = payload;
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
