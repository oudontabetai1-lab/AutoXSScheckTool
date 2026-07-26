"""通常スキャンのリクエスト単位ヘッダ付与と共有オリジン判定のテスト。"""
import tempfile
import unittest
import warnings
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from wscan.browser import BrowserManager
from wscan.header_scope import (
    _url_origin,
    allowed_header_origins,
    effective_origin_url,
    headers_allowed_for_url,
)
from wscan.llm_agent_browser import (
    allowed_header_origins as agent_allowed_header_origins,
)


class _Request:
    def __init__(self, url, headers=None):
        self.url = url
        self.headers = dict(headers or {})


class _Route:
    def __init__(self, failures=0):
        self.calls = []
        self.failures = failures

    async def continue_(self, **kwargs):
        self.calls.append(kwargs)
        if self.failures:
            self.failures -= 1
            raise RuntimeError("continue failed")


class BrowserHeaderRouteTests(unittest.IsolatedAsyncioTestCase):
    def _browser(self):
        return BrowserManager(
            extra_headers={
                "Authorization": "Bearer secret",
                "X-Tenant": 42,
            },
            header_scope_origins={"https://app.example"},
        )

    async def test_allowed_origin_continues_with_normalized_auth_headers(self):
        browser = self._browser()
        route = _Route()
        request = _Request(
            "https://app.example/assets/app.js",
            {
                "authorization": "Bearer stale",
                "accept": "application/javascript",
            },
        )

        await browser._auth_header_route(route, request)

        self.assertEqual(
            route.calls,
            [{
                "headers": {
                    "authorization": "Bearer secret",
                    "accept": "application/javascript",
                    "x-tenant": "42",
                }
            }],
        )

    async def test_disallowed_origin_continues_without_extra_headers(self):
        browser = self._browser()
        route = _Route()
        request = _Request(
            "https://third-party.example/tracker.js",
            {"accept": "*/*"},
        )

        await browser._auth_header_route(route, request)

        self.assertEqual(route.calls, [{}])

    async def test_continue_failure_does_not_escape_and_retries_continue(self):
        browser = self._browser()
        route = _Route(failures=2)

        await browser._auth_header_route(
            route,
            _Request("https://app.example/private"),
        )

        self.assertEqual(len(route.calls), 2)

    async def test_origin_check_failure_still_attempts_continue(self):
        browser = self._browser()
        route = _Route()

        with patch(
            "wscan.browser.headers_allowed_for_url",
            side_effect=RuntimeError("origin check failed"),
        ):
            await browser._auth_header_route(
                route,
                _Request("https://app.example/private"),
            )

        self.assertEqual(route.calls, [{}])

    async def test_header_refresh_only_replaces_route_handler_state(self):
        browser = self._browser()
        browser._header_route_active = True
        browser._context = SimpleNamespace(
            set_extra_http_headers=AsyncMock()
        )

        await browser.update_extra_headers({"Authorization": "Bearer fresh"})

        self.assertEqual(
            browser.extra_headers,
            {"Authorization": "Bearer fresh"},
        )
        browser._context.set_extra_http_headers.assert_not_awaited()


class BrowserHeaderModeTests(unittest.IsolatedAsyncioTestCase):
    def _playwright_fakes(self, *, route_error=None):
        page = SimpleNamespace(
            set_default_timeout=MagicMock(),
            on=MagicMock(),
        )
        context = SimpleNamespace(
            route=AsyncMock(side_effect=route_error),
            set_extra_http_headers=AsyncMock(),
            new_page=AsyncMock(return_value=page),
        )
        browser = SimpleNamespace(new_context=AsyncMock(return_value=context))
        playwright = SimpleNamespace(
            chromium=SimpleNamespace(
                launch=AsyncMock(return_value=browser),
            )
        )
        starter = SimpleNamespace(start=AsyncMock(return_value=playwright))
        return starter, browser, context

    async def test_scoped_headers_enable_route_without_context_headers(self):
        starter, fake_browser, context = self._playwright_fakes()
        browser = BrowserManager(
            extra_headers={"Authorization": "Bearer secret"},
            header_scope_origins={"https://app.example"},
        )

        with patch("wscan.browser.async_playwright", return_value=starter):
            await browser.init()

        kwargs = fake_browser.new_context.await_args.kwargs
        self.assertNotIn("extra_http_headers", kwargs)
        context.route.assert_awaited_once_with(
            "**/*",
            browser._auth_header_route,
        )
        context.set_extra_http_headers.assert_not_awaited()
        self.assertTrue(browser._header_route_active)

    async def test_route_registration_failure_uses_context_wide_fallback(self):
        starter, fake_browser, context = self._playwright_fakes(
            route_error=RuntimeError("route unavailable"),
        )
        browser = BrowserManager(
            extra_headers={"Authorization": "Bearer secret"},
            header_scope_origins={"https://app.example"},
        )

        with patch("wscan.browser.async_playwright", return_value=starter):
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                await browser.init()

        self.assertNotIn(
            "extra_http_headers",
            fake_browser.new_context.await_args.kwargs,
        )
        context.set_extra_http_headers.assert_awaited_once_with(
            {"Authorization": "Bearer secret"}
        )
        self.assertFalse(browser._header_route_active)
        self.assertEqual(len(caught), 1)
        self.assertNotIn("secret", str(caught[0].message))

    async def test_unknown_scope_preserves_context_wide_behavior(self):
        starter, fake_browser, context = self._playwright_fakes()
        browser = BrowserManager(
            extra_headers={"Authorization": "Bearer secret"},
        )

        with patch("wscan.browser.async_playwright", return_value=starter):
            await browser.init()

        self.assertEqual(
            fake_browser.new_context.await_args.kwargs["extra_http_headers"],
            {"Authorization": "Bearer secret"},
        )
        context.route.assert_not_awaited()
        self.assertFalse(browser._header_route_active)

    async def test_empty_headers_do_not_enable_either_header_mode(self):
        starter, fake_browser, context = self._playwright_fakes()
        browser = BrowserManager(
            header_scope_origins={"https://app.example"},
        )

        with patch("wscan.browser.async_playwright", return_value=starter):
            await browser.init()

        self.assertNotIn(
            "extra_http_headers",
            fake_browser.new_context.await_args.kwargs,
        )
        context.route.assert_not_awaited()
        self.assertFalse(browser._header_route_active)


class HeaderScopeSharedHelperTests(unittest.TestCase):
    def test_agent_module_reexports_shared_origin_helper(self):
        self.assertIs(agent_allowed_header_origins, allowed_header_origins)

    def test_shared_helpers_normalize_ipv6_and_blank_pages(self):
        self.assertEqual(
            _url_origin("HTTPS://[2001:DB8::1]:443/path"),
            "https://[2001:db8::1]",
        )
        intended = "https://app.example/start"
        self.assertEqual(
            effective_origin_url("about:blank", intended),
            intended,
        )
        self.assertTrue(
            headers_allowed_for_url(
                "https://app.example/resource",
                allowed_header_origins(
                    intended,
                    [],
                    [],
                ),
            )
        )

    def test_engine_passes_all_normalized_scopes_to_browser(self):
        from wscan.engine import ScanEngine

        with tempfile.TemporaryDirectory() as output_dir:
            engine = ScanEngine(
                url="https://app.example/start",
                target_urls=["https://api.example/v1"],
                access_urls=["https://cdn.example/bootstrap"],
                login_url="https://identity.example/login",
                headers={"Authorization": "Bearer secret"},
                output_dir=output_dir,
            )

        self.assertEqual(
            engine._browser.header_scope_origins,
            {
                "https://app.example",
                "https://api.example",
                "https://cdn.example",
                "https://identity.example",
            },
        )


if __name__ == "__main__":
    unittest.main()
