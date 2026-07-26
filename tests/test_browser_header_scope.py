"""通常スキャンのリクエスト単位ヘッダ付与と共有オリジン判定のテスト。"""
import tempfile
import unittest
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
    def __init__(
        self,
        *,
        fetch_failure=None,
        fulfill_failure=None,
        continue_failures=0,
    ):
        self.response = object()
        self.fetch_failure = fetch_failure
        self.fulfill_failure = fulfill_failure
        self.continue_failures = continue_failures
        self.fetch_calls = []
        self.fulfill_calls = []
        self.continue_calls = []

    async def fetch(self, **kwargs):
        self.fetch_calls.append(kwargs)
        if self.fetch_failure is not None:
            raise self.fetch_failure
        return self.response

    async def fulfill(self, **kwargs):
        self.fulfill_calls.append(kwargs)
        if self.fulfill_failure is not None:
            raise self.fulfill_failure

    async def continue_(self, **kwargs):
        self.continue_calls.append(kwargs)
        if self.continue_failures:
            self.continue_failures -= 1
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

    async def test_allowed_origin_fetches_without_following_redirects_and_fulfills(self):
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
            route.fetch_calls,
            [{
                "headers": {
                    "authorization": "Bearer secret",
                    "accept": "application/javascript",
                    "x-tenant": "42",
                },
                "max_redirects": 0,
            }],
        )
        self.assertEqual(route.fulfill_calls, [{"response": route.response}])
        self.assertEqual(route.continue_calls, [])

    async def test_disallowed_origin_continues_without_headers_or_fetch(self):
        browser = self._browser()
        route = _Route()
        request = _Request(
            "https://third-party.example/tracker.js",
            {"accept": "*/*"},
        )

        await browser._auth_header_route(route, request)

        self.assertEqual(route.continue_calls, [{}])
        self.assertEqual(route.fetch_calls, [])
        self.assertEqual(route.fulfill_calls, [])

    async def test_fetch_failure_falls_back_to_continue_without_headers(self):
        browser = self._browser()
        route = _Route(fetch_failure=TypeError("max_redirects unsupported"))

        with patch("wscan.browser.console") as mock_console:
            await browser._auth_header_route(
                route,
                _Request("https://app.example/private"),
            )

        self.assertEqual(
            route.fetch_calls,
            [{
                "headers": {
                    "authorization": "Bearer secret",
                    "x-tenant": "42",
                },
                "max_redirects": 0,
            }],
        )
        self.assertEqual(route.fulfill_calls, [])
        self.assertEqual(route.continue_calls, [{}])
        mock_console.print.assert_called_once()
        notice = mock_console.print.call_args.args[0]
        self.assertIn("認証ヘッダなし", notice)
        self.assertNotIn("Authorization", notice)
        self.assertNotIn("secret", notice)

    async def test_fulfill_failure_falls_back_to_continue_without_headers(self):
        browser = self._browser()
        route = _Route(fulfill_failure=RuntimeError("fulfill failed"))

        await browser._auth_header_route(
            route,
            _Request("https://app.example/private"),
        )

        self.assertEqual(len(route.fetch_calls), 1)
        self.assertEqual(route.fulfill_calls, [{"response": route.response}])
        self.assertEqual(route.continue_calls, [{}])

    async def test_headerless_fallback_failure_retries_without_headers(self):
        browser = self._browser()
        route = _Route(
            fetch_failure=AttributeError("route.fetch unavailable"),
            continue_failures=1,
        )

        await browser._auth_header_route(
            route,
            _Request("https://app.example/private"),
        )

        self.assertEqual(
            route.continue_calls,
            [{}, {}],
        )

    async def test_request_fallback_notice_is_emitted_only_once(self):
        browser = self._browser()
        browser.monitor = SimpleNamespace(emit_status=AsyncMock())

        for _ in range(2):
            await browser._auth_header_route(
                _Route(fetch_failure=RuntimeError("fetch failed")),
                _Request("https://app.example/private"),
            )

        browser.monitor.emit_status.assert_awaited_once_with(
            "リクエスト単位のヘッダ付与に失敗したため、"
            "該当リクエストは認証ヘッダなしで実行しました",
            "running",
        )

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

        self.assertEqual(route.continue_calls, [{}])
        self.assertEqual(route.fetch_calls, [])
        self.assertEqual(route.fulfill_calls, [])

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

    async def test_header_refresh_enables_route_when_scoped_headers_appear(self):
        browser = BrowserManager(
            header_scope_origins={"https://app.example"},
        )
        browser._context = SimpleNamespace(
            route=AsyncMock(),
            set_extra_http_headers=AsyncMock(),
        )

        await browser.update_extra_headers(
            {"Authorization": "Bearer fresh"}
        )

        browser._context.route.assert_awaited_once_with(
            "**/*",
            browser._auth_header_route,
        )
        browser._context.set_extra_http_headers.assert_not_awaited()
        self.assertTrue(browser._header_route_active)

    async def test_header_refresh_unknown_scope_remains_context_wide(self):
        browser = BrowserManager()
        browser._context = SimpleNamespace(
            route=AsyncMock(),
            set_extra_http_headers=AsyncMock(),
        )

        await browser.update_extra_headers(
            {"Authorization": "Bearer fresh"}
        )

        browser._context.route.assert_not_awaited()
        browser._context.set_extra_http_headers.assert_awaited_once_with(
            {"Authorization": "Bearer fresh"}
        )
        self.assertFalse(browser._header_route_active)

    async def test_header_refresh_route_failure_uses_context_wide_fallback(self):
        browser = BrowserManager(
            header_scope_origins={"https://app.example"},
        )
        browser._context = SimpleNamespace(
            route=AsyncMock(side_effect=RuntimeError("route unavailable")),
            set_extra_http_headers=AsyncMock(),
        )
        browser.monitor = SimpleNamespace(emit_status=AsyncMock())

        await browser.update_extra_headers(
            {"Authorization": "Bearer fresh"}
        )

        browser._context.route.assert_awaited_once()
        browser._context.set_extra_http_headers.assert_awaited_once_with(
            {"Authorization": "Bearer fresh"}
        )
        self.assertFalse(browser._header_route_active)
        browser.monitor.emit_status.assert_awaited_once_with(
            "リクエスト単位のヘッダ付与を有効化できず、"
            "コンテキスト全体へ適用します"
            "（第三者サブリソースにも送信され得ます）",
            "running",
        )


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
        self.assertEqual(kwargs["service_workers"], "block")
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
        browser.monitor = SimpleNamespace(emit_status=AsyncMock())

        with patch("wscan.browser.async_playwright", return_value=starter):
            await browser.init()

        self.assertNotIn(
            "extra_http_headers",
            fake_browser.new_context.await_args.kwargs,
        )
        context.set_extra_http_headers.assert_awaited_once_with(
            {"Authorization": "Bearer secret"}
        )
        self.assertFalse(browser._header_route_active)
        browser.monitor.emit_status.assert_awaited_once_with(
            "リクエスト単位のヘッダ付与を有効化できず、"
            "コンテキスト全体へ適用します"
            "（第三者サブリソースにも送信され得ます）",
            "running",
        )

    async def test_unsupported_service_worker_option_retries_without_it(self):
        starter, fake_browser, context = self._playwright_fakes()
        fake_browser.new_context.side_effect = [
            TypeError("unsupported service_workers option"),
            context,
        ]
        browser = BrowserManager(
            extra_headers={"Authorization": "Bearer secret"},
            header_scope_origins={"https://app.example"},
        )

        with patch("wscan.browser.async_playwright", return_value=starter):
            with patch("wscan.browser.console") as mock_console:
                await browser.init()

        first_kwargs = fake_browser.new_context.await_args_list[0].kwargs
        second_kwargs = fake_browser.new_context.await_args_list[1].kwargs
        self.assertEqual(first_kwargs["service_workers"], "block")
        self.assertNotIn("service_workers", second_kwargs)
        context.route.assert_awaited_once()
        mock_console.print.assert_called_once()
        notice = mock_console.print.call_args.args[0]
        self.assertIn("Service Worker", notice)
        self.assertNotIn("Authorization", notice)
        self.assertNotIn("secret", notice)

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
        self.assertNotIn(
            "service_workers",
            fake_browser.new_context.await_args.kwargs,
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
        self.assertNotIn(
            "service_workers",
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

    def test_unicode_and_punycode_hosts_have_the_same_origin(self):
        self.assertEqual(
            _url_origin("https://例え.test/path"),
            _url_origin("https://xn--r8jz45g.test/other"),
        )

    def test_ascii_host_origin_is_unchanged(self):
        self.assertEqual(
            _url_origin("HTTPS://APP.Example:443/path"),
            "https://app.example",
        )

    def test_invalid_idna_host_does_not_raise(self):
        self.assertEqual(
            _url_origin("https://\udcff.test/path"),
            "https://\udcff.test",
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
