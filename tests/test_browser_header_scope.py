"""通常スキャンのリクエスト単位ヘッダ付与と共有オリジン判定のテスト。"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
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


class _FailingHeaders:
    def keys(self):
        raise RuntimeError("request headers unavailable")


class _Route:
    def __init__(
        self,
        *,
        fetch_failure=None,
        fulfill_failure=None,
        abort_failure=None,
        continue_failures=0,
    ):
        self.response = object()
        self.fetch_failure = fetch_failure
        self.fulfill_failure = fulfill_failure
        self.abort_failure = abort_failure
        self.continue_failures = continue_failures
        self.fetch_calls = []
        self.fulfill_calls = []
        self.abort_calls = []
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

    async def abort(self, **kwargs):
        self.abort_calls.append(kwargs)
        if self.abort_failure is not None:
            raise self.abort_failure

    async def continue_(self, **kwargs):
        self.continue_calls.append(kwargs)
        if self.continue_failures:
            self.continue_failures -= 1
            raise RuntimeError("continue failed")


class _CDPSession:
    def __init__(self, *, send_failure=None):
        self.send_failure = send_failure
        self.handlers = {}
        self.send_calls = []
        self.detach_calls = 0

    def on(self, event, handler):
        self.handlers[event] = handler

    async def send(self, method, params=None):
        self.send_calls.append((method, params))
        if self.send_failure is not None:
            raise self.send_failure

    async def detach(self):
        self.detach_calls += 1


class _BrowserCDP:
    def __init__(self, *, fail_methods=None):
        self.fail_methods = set(fail_methods or ())
        self.send_calls = []
        self.close_calls = 0

    async def send(self, method, params=None, *, session_id=""):
        self.send_calls.append((method, params, session_id))
        if method in self.fail_methods:
            raise RuntimeError("CDP command failed")
        if method == "Target.attachToBrowserTarget":
            return {"sessionId": "browser-session"}
        return {}

    async def close(self):
        self.close_calls += 1


class BrowserHeaderCDPTests(unittest.IsolatedAsyncioTestCase):
    def _browser(self):
        return BrowserManager(
            extra_headers={
                "Authorization": "Bearer secret",
                "X-Tenant": 42,
            },
            header_scope_origins={"https://app.example"},
        )

    async def test_allowed_origin_continues_with_case_insensitive_overrides(self):
        browser = self._browser()
        cdp = _CDPSession()

        await browser._on_fetch_request_paused(
            cdp,
            {
                "requestId": "request-1",
                "request": {
                    "url": "https://app.example/private",
                    "headers": {
                        "authorization": "Bearer stale",
                        "Accept": "application/json",
                    },
                },
            },
        )

        self.assertEqual(len(cdp.send_calls), 1)
        method, params = cdp.send_calls[0]
        self.assertEqual(method, "Fetch.continueRequest")
        self.assertEqual(params["requestId"], "request-1")
        self.assertEqual(
            params["headers"],
            [
                {"name": "Accept", "value": "application/json"},
                {"name": "Authorization", "value": "Bearer secret"},
                {"name": "X-Tenant", "value": "42"},
            ],
        )

    async def test_disallowed_origin_continues_without_headers_parameter(self):
        browser = self._browser()
        cdp = _CDPSession()

        await browser._on_fetch_request_paused(
            cdp,
            {
                "requestId": "request-2",
                "request": {
                    "url": "https://third-party.example/script.js",
                    "headers": {"Accept": "*/*"},
                },
            },
        )

        self.assertEqual(
            cdp.send_calls,
            [("Fetch.continueRequest", {"requestId": "request-2"})],
        )

    async def test_origin_check_failure_still_continues_exactly_once(self):
        browser = self._browser()
        cdp = _CDPSession()
        browser.monitor = SimpleNamespace(emit_status=AsyncMock())

        with patch(
            "wscan.browser.headers_allowed_for_url",
            side_effect=RuntimeError("origin check failed"),
        ):
            await browser._on_fetch_request_paused(
                cdp,
                {
                    "requestId": "request-3",
                    "request": {
                        "url": "https://app.example/private",
                        "headers": {},
                    },
                },
            )

        self.assertEqual(
            cdp.send_calls,
            [("Fetch.continueRequest", {"requestId": "request-3"})],
        )
        browser.monitor.emit_status.assert_awaited_once_with(
            "リクエスト単位のヘッダ付与に失敗したため、"
            "該当リクエストは認証ヘッダなしで実行しました",
            "running",
        )

    async def test_same_page_is_attached_only_once(self):
        browser = self._browser()
        cdp = _CDPSession()
        page = object()
        browser._context = SimpleNamespace(
            new_cdp_session=AsyncMock(return_value=cdp),
        )

        await browser._attach_header_interception(page)
        await browser._attach_header_interception(page)

        browser._context.new_cdp_session.assert_awaited_once_with(page)
        self.assertEqual(
            cdp.send_calls,
            [
                (
                    "Fetch.enable",
                    {"patterns": [{"urlPattern": "*"}]},
                ),
                ("Target.getTargetInfo", None),
            ],
        )
        self.assertIn("Fetch.requestPaused", cdp.handlers)

    async def test_auto_attached_popup_enables_fetch_only_once_and_resumes(self):
        browser = self._browser()
        cdp = _BrowserCDP()
        browser._header_browser_cdp = cdp
        event = {
            "sessionId": "popup-session",
            "waitingForDebugger": True,
            "targetInfo": {
                "targetId": "popup-target",
                "type": "page",
            },
        }

        await browser._enable_fetch_for_attached_header_target(event)
        await browser._enable_fetch_for_attached_header_target(event)

        self.assertEqual(
            [
                call
                for call in cdp.send_calls
                if call[0] == "Fetch.enable"
            ],
            [(
                "Fetch.enable",
                {"patterns": [{"urlPattern": "*"}]},
                "popup-session",
            )],
        )
        self.assertEqual(
            [
                call
                for call in cdp.send_calls
                if call[0] == "Runtime.runIfWaitingForDebugger"
            ],
            [
                ("Runtime.runIfWaitingForDebugger", None, "popup-session"),
                ("Runtime.runIfWaitingForDebugger", None, "popup-session"),
            ],
        )

    async def test_auto_attach_prevents_explicit_page_fetch_enable(self):
        browser = self._browser()
        browser._header_auto_attach_active = True
        page = object()
        browser._context = SimpleNamespace(
            new_cdp_session=AsyncMock(),
        )

        await browser._attach_header_interception(page)

        browser._context.new_cdp_session.assert_not_awaited()

    async def test_auto_attached_popup_resumes_when_fetch_enable_fails(self):
        browser = self._browser()
        cdp = _BrowserCDP(fail_methods={"Fetch.enable"})
        browser._header_browser_cdp = cdp
        browser.monitor = SimpleNamespace(emit_status=AsyncMock())

        await browser._enable_fetch_for_attached_header_target({
            "sessionId": "popup-session",
            "targetInfo": {
                "targetId": "popup-target",
                "type": "page",
            },
        })

        self.assertEqual(
            cdp.send_calls[-1],
            ("Runtime.runIfWaitingForDebugger", None, "popup-session"),
        )
        self.assertNotIn(
            "popup-target",
            browser._header_auto_target_sessions,
        )

    async def test_auto_attach_uses_waiting_flattened_browser_session(self):
        browser = self._browser()
        cdp = _BrowserCDP()

        with (
            patch.object(
                browser,
                "_find_debugger_websocket_url",
                AsyncMock(return_value="ws://fixture.test/devtools/browser/test"),
            ),
            patch(
                "wscan.browser._BrowserCDPConnection",
                return_value=cdp,
            ),
        ):
            cdp.connect = AsyncMock()
            enabled = await browser._activate_header_target_auto_attach()

        self.assertTrue(enabled)
        cdp.connect.assert_awaited_once()
        self.assertIn(
            (
                "Target.setAutoAttach",
                {
                    "autoAttach": True,
                    "waitForDebuggerOnStart": True,
                    "flatten": True,
                },
                "browser-session",
            ),
            cdp.send_calls,
        )

    async def test_auto_attach_failure_keeps_context_page_fallback(self):
        browser = self._browser()
        cdp = _BrowserCDP(fail_methods={"Target.setAutoAttach"})
        cdp.connect = AsyncMock()
        cdp.close = AsyncMock()

        with (
            patch.object(
                browser,
                "_find_debugger_websocket_url",
                AsyncMock(return_value="ws://fixture.test/devtools/browser/test"),
            ),
            patch(
                "wscan.browser._BrowserCDPConnection",
                return_value=cdp,
            ),
        ):
            enabled = await browser._activate_header_target_auto_attach()

        self.assertFalse(enabled)
        self.assertFalse(browser._header_auto_attach_active)
        self.assertIsNone(browser._header_browser_cdp)
        cdp.close.assert_awaited_once()

    async def test_close_disables_auto_fetch_and_detaches_browser_session(self):
        browser = self._browser()
        cdp = _BrowserCDP()
        browser._header_browser_cdp = cdp
        browser._header_browser_session_id = "browser-session"
        browser._header_auto_attach_active = True
        browser._header_auto_target_sessions = {
            "popup-target": "popup-session",
        }

        await browser._deactivate_header_target_auto_attach()

        self.assertIn(
            (
                "Target.setAutoAttach",
                {
                    "autoAttach": False,
                    "waitForDebuggerOnStart": False,
                    "flatten": True,
                },
                "browser-session",
            ),
            cdp.send_calls,
        )
        self.assertIn(
            ("Fetch.disable", None, "popup-session"),
            cdp.send_calls,
        )
        self.assertIn(
            (
                "Target.detachFromTarget",
                {"sessionId": "browser-session"},
                "",
            ),
            cdp.send_calls,
        )
        self.assertEqual(cdp.close_calls, 1)
        self.assertIsNone(browser._header_browser_cdp)
        self.assertFalse(browser._header_auto_attach_active)

    async def test_close_disables_and_detaches_cdp_session(self):
        browser = self._browser()
        cdp = _CDPSession()
        browser._header_cdp_sessions[id(object())] = cdp
        browser._header_intercept_mode = "cdp"
        browser._context = SimpleNamespace(close=AsyncMock())

        await browser.close()

        self.assertEqual(cdp.send_calls, [("Fetch.disable", None)])
        self.assertEqual(cdp.detach_calls, 1)
        browser._context.close.assert_awaited_once()
        self.assertEqual(browser._header_intercept_mode, "none")


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
        self.assertEqual(route.abort_calls, [])
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
        self.assertEqual(route.abort_calls, [])

    async def test_fetch_failure_aborts_without_resending(self):
        browser = self._browser()
        route = _Route(fetch_failure=TimeoutError("response timed out"))

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
        self.assertEqual(route.abort_calls, [{}])
        self.assertEqual(route.continue_calls, [])
        mock_console.print.assert_called_once()
        notice = mock_console.print.call_args.args[0]
        self.assertIn("認証ヘッダなし", notice)
        self.assertNotIn("Authorization", notice)
        self.assertNotIn("secret", notice)

    async def test_fulfill_failure_aborts_without_resending(self):
        browser = self._browser()
        route = _Route(fulfill_failure=RuntimeError("fulfill failed"))

        await browser._auth_header_route(
            route,
            _Request("https://app.example/private"),
        )

        self.assertEqual(len(route.fetch_calls), 1)
        self.assertEqual(route.fulfill_calls, [{"response": route.response}])
        self.assertEqual(route.abort_calls, [{}])
        self.assertEqual(route.continue_calls, [])

    async def test_fulfill_and_abort_failure_does_not_escape_handler(self):
        browser = self._browser()
        route = _Route(
            fulfill_failure=RuntimeError("fulfill failed"),
            abort_failure=RuntimeError("abort failed"),
        )

        await browser._auth_header_route(
            route,
            _Request("https://app.example/private"),
        )

        self.assertEqual(len(route.fetch_calls), 1)
        self.assertEqual(route.fulfill_calls, [{"response": route.response}])
        self.assertEqual(route.abort_calls, [{}])
        self.assertEqual(route.continue_calls, [])

    async def test_headerless_fallback_failure_retries_without_headers(self):
        browser = self._browser()
        route = _Route(
            continue_failures=1,
        )
        request = _Request("https://app.example/private")
        request.headers = _FailingHeaders()

        await browser._auth_header_route(
            route,
            request,
        )

        self.assertEqual(route.fetch_calls, [])
        self.assertEqual(route.abort_calls, [])
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
        browser._header_intercept_mode = "route"
        browser._context = SimpleNamespace(
            set_extra_http_headers=AsyncMock()
        )

        await browser.update_extra_headers({"Authorization": "Bearer fresh"})

        self.assertEqual(
            browser.extra_headers,
            {"Authorization": "Bearer fresh"},
        )
        browser._context.set_extra_http_headers.assert_not_awaited()

    async def test_header_refresh_enables_cdp_when_scoped_headers_appear(self):
        browser = BrowserManager(
            header_scope_origins={"https://app.example"},
        )
        page = object()
        cdp = _CDPSession()
        browser.page = page
        browser._context = SimpleNamespace(
            new_cdp_session=AsyncMock(return_value=cdp),
            route=AsyncMock(),
            set_extra_http_headers=AsyncMock(),
        )

        await browser.update_extra_headers(
            {"Authorization": "Bearer fresh"}
        )

        browser._context.new_cdp_session.assert_awaited_once_with(page)
        browser._context.route.assert_not_awaited()
        browser._context.set_extra_http_headers.assert_not_awaited()
        self.assertEqual(browser._header_intercept_mode, "cdp")
        self.assertFalse(browser._header_route_active)

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
        self.assertEqual(browser._header_intercept_mode, "context")

    async def test_header_refresh_cdp_and_route_failure_uses_context_fallback(self):
        browser = BrowserManager(
            header_scope_origins={"https://app.example"},
        )
        browser.page = object()
        browser._context = SimpleNamespace(
            new_cdp_session=AsyncMock(
                side_effect=RuntimeError("cdp unavailable")
            ),
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
        self.assertEqual(browser._header_intercept_mode, "context")
        self.assertEqual(
            browser.monitor.emit_status.await_args_list,
            [
                unittest.mock.call(
                    "CDP による傍受を有効化できないため従来方式で継続します。"
                    "ストリーミング応答（SSE 等）が途中で切れる可能性があります",
                    "running",
                ),
                unittest.mock.call(
                    "リクエスト単位のヘッダ付与を有効化できず、"
                    "コンテキスト全体へ適用します"
                    "（第三者サブリソースにも送信され得ます）",
                    "running",
                ),
            ],
        )

    async def test_header_refresh_does_not_overlap_unclearable_context_headers(self):
        browser = BrowserManager(
            header_scope_origins={"https://app.example"},
        )
        browser.page = object()
        browser._header_intercept_mode = "context"
        browser._context_wide_headers_active = True
        browser._context = SimpleNamespace(
            new_cdp_session=AsyncMock(),
            route=AsyncMock(),
            set_extra_http_headers=AsyncMock(
                side_effect=[RuntimeError("clear failed"), None]
            ),
        )
        browser.monitor = SimpleNamespace(emit_status=AsyncMock())

        await browser.update_extra_headers(
            {"Authorization": "Bearer fresh"}
        )

        browser._context.new_cdp_session.assert_not_awaited()
        browser._context.route.assert_not_awaited()
        self.assertEqual(
            browser._context.set_extra_http_headers.await_args_list,
            [
                unittest.mock.call({}),
                unittest.mock.call({"Authorization": "Bearer fresh"}),
            ],
        )
        self.assertEqual(browser._header_intercept_mode, "context")
        self.assertTrue(browser._context_wide_headers_active)


class BrowserHeaderModeTests(unittest.IsolatedAsyncioTestCase):
    def _playwright_fakes(self, *, cdp_error=None, route_error=None):
        page = SimpleNamespace(
            set_default_timeout=MagicMock(),
            on=MagicMock(),
        )
        cdp = _CDPSession()
        context = SimpleNamespace(
            on=MagicMock(),
            new_cdp_session=AsyncMock(
                return_value=cdp,
                side_effect=cdp_error,
            ),
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
        return starter, browser, context, cdp

    async def test_scoped_headers_enable_cdp_without_route_or_context_headers(self):
        starter, fake_browser, context, cdp = self._playwright_fakes()
        browser = BrowserManager(
            extra_headers={"Authorization": "Bearer secret"},
            header_scope_origins={"https://app.example"},
        )

        with patch("wscan.browser.async_playwright", return_value=starter):
            await browser.init()

        kwargs = fake_browser.new_context.await_args.kwargs
        self.assertNotIn("extra_http_headers", kwargs)
        self.assertEqual(kwargs["service_workers"], "block")
        context.on.assert_called_once_with(
            "page",
            browser._on_header_context_page,
        )
        context.new_cdp_session.assert_awaited_once_with(browser.page)
        self.assertEqual(
            cdp.send_calls,
            [
                (
                    "Fetch.enable",
                    {"patterns": [{"urlPattern": "*"}]},
                ),
                ("Target.getTargetInfo", None),
            ],
        )
        context.route.assert_not_awaited()
        context.set_extra_http_headers.assert_not_awaited()
        self.assertEqual(browser._header_intercept_mode, "cdp")
        self.assertFalse(browser._header_route_active)
        launch_args = browser._playwright.chromium.launch.await_args.kwargs["args"]
        self.assertFalse(
            any(arg.startswith("--remote-debugging-port=") for arg in launch_args)
        )
        self.assertNotIn(
            "--remote-debugging-address=127.0.0.1",
            launch_args,
        )
        self.assertIsNone(browser._header_debug_port)
        self.assertFalse(browser._header_auto_attach_active)

    async def test_popup_opt_in_adds_loopback_devtools_args_and_warns_once(self):
        starter, _fake_browser, _context, _cdp = self._playwright_fakes()
        browser = BrowserManager(
            extra_headers={"Authorization": "Bearer secret"},
            header_scope_origins={"https://app.example"},
            popup_header_intercept=True,
        )
        browser.monitor = SimpleNamespace(emit_status=AsyncMock())

        with (
            patch("wscan.browser.async_playwright", return_value=starter),
            patch.object(
                browser,
                "_activate_header_target_auto_attach",
                AsyncMock(return_value=True),
            ),
        ):
            await browser.init()
            await browser._warn_popup_header_intercept()

        launch_args = browser._playwright.chromium.launch.await_args.kwargs["args"]
        self.assertIn(
            "--remote-debugging-address=127.0.0.1",
            launch_args,
        )
        debug_args = [
            arg
            for arg in launch_args
            if arg.startswith("--remote-debugging-port=")
        ]
        self.assertEqual(len(debug_args), 1)
        self.assertTrue(debug_args[0].removeprefix(
            "--remote-debugging-port="
        ).isdigit())
        browser.monitor.emit_status.assert_awaited_once_with(
            "popup 傍受のためローカル DevTools ポートを開きます。"
            "同一ホストの他プロセスからブラウザを操作され得るため、"
            "共有ホストでは使用しないでください",
            "running",
        )
        notice = browser.monitor.emit_status.await_args.args[0]
        self.assertNotIn("Authorization", notice)
        self.assertNotIn("secret", notice)

    async def test_popup_opt_in_port_allocation_failure_keeps_page_fallback(self):
        starter, _fake_browser, context, _cdp = self._playwright_fakes()
        browser = BrowserManager(
            extra_headers={"Authorization": "Bearer secret"},
            header_scope_origins={"https://app.example"},
            popup_header_intercept=True,
        )
        browser.monitor = SimpleNamespace(emit_status=AsyncMock())

        with (
            patch("wscan.browser.async_playwright", return_value=starter),
            patch(
                "wscan.browser.socket.socket",
                side_effect=OSError("port unavailable"),
            ),
        ):
            await browser.init()

        launch_args = browser._playwright.chromium.launch.await_args.kwargs["args"]
        self.assertNotIn(
            "--remote-debugging-address=127.0.0.1",
            launch_args,
        )
        self.assertFalse(
            any(arg.startswith("--remote-debugging-port=") for arg in launch_args)
        )
        self.assertIsNone(browser._header_debug_port)
        self.assertFalse(browser._header_auto_attach_active)
        context.on.assert_called_once_with(
            "page",
            browser._on_header_context_page,
        )
        browser.monitor.emit_status.assert_not_awaited()

    async def test_disabled_scope_uses_context_wide_headers_and_warns_once(self):
        starter, fake_browser, context, _cdp = self._playwright_fakes()
        browser = BrowserManager(
            extra_headers={"Authorization": "Bearer secret"},
            header_scope_origins={"https://app.example"},
            header_scope_enforce=False,
        )
        browser.monitor = SimpleNamespace(emit_status=AsyncMock())

        with patch("wscan.browser.async_playwright", return_value=starter):
            await browser.init()
            await browser.update_extra_headers(
                {"Authorization": "Bearer fresh"}
            )

        self.assertEqual(browser.header_scope_origins, set())
        self.assertEqual(
            fake_browser.new_context.await_args.kwargs["extra_http_headers"],
            {"Authorization": "Bearer secret"},
        )
        self.assertNotIn(
            "service_workers",
            fake_browser.new_context.await_args.kwargs,
        )
        context.route.assert_not_awaited()
        context.set_extra_http_headers.assert_awaited_once_with(
            {"Authorization": "Bearer fresh"}
        )
        browser.monitor.emit_status.assert_awaited_once_with(
            "認証ヘッダのスコープ制御が無効です。"
            "コンテキスト全体へ適用するため、第三者サブリソースにも"
            "認証ヘッダが送信されます",
            "running",
        )

    async def test_cdp_failure_uses_route_and_warns_about_streaming(self):
        starter, fake_browser, context, _cdp = self._playwright_fakes(
            cdp_error=RuntimeError("cdp unavailable"),
        )
        browser = BrowserManager(
            extra_headers={"Authorization": "Bearer secret"},
            header_scope_origins={"https://app.example"},
        )
        browser.monitor = SimpleNamespace(emit_status=AsyncMock())

        with patch("wscan.browser.async_playwright", return_value=starter):
            await browser.init()

        context.route.assert_awaited_once_with(
            "**/*",
            browser._auth_header_route,
        )
        context.set_extra_http_headers.assert_not_awaited()
        self.assertEqual(browser._header_intercept_mode, "route")
        self.assertTrue(browser._header_route_active)
        browser.monitor.emit_status.assert_awaited_once_with(
            "CDP による傍受を有効化できないため従来方式で継続します。"
            "ストリーミング応答（SSE 等）が途中で切れる可能性があります",
            "running",
        )

    async def test_cdp_and_route_failure_uses_context_wide_fallback(self):
        starter, fake_browser, context, _cdp = self._playwright_fakes(
            cdp_error=RuntimeError("cdp unavailable"),
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
        self.assertEqual(browser._header_intercept_mode, "context")
        self.assertEqual(
            browser.monitor.emit_status.await_args_list,
            [
                unittest.mock.call(
                    "CDP による傍受を有効化できないため従来方式で継続します。"
                    "ストリーミング応答（SSE 等）が途中で切れる可能性があります",
                    "running",
                ),
                unittest.mock.call(
                    "リクエスト単位のヘッダ付与を有効化できず、"
                    "コンテキスト全体へ適用します"
                    "（第三者サブリソースにも送信され得ます）",
                    "running",
                ),
            ],
        )

    async def test_unsupported_service_worker_option_retries_without_it(self):
        starter, fake_browser, context, _cdp = self._playwright_fakes()
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
        context.new_cdp_session.assert_awaited_once()
        context.route.assert_not_awaited()
        mock_console.print.assert_called_once()
        notice = mock_console.print.call_args.args[0]
        self.assertIn("Service Worker", notice)
        self.assertNotIn("Authorization", notice)
        self.assertNotIn("secret", notice)

    async def test_unknown_scope_preserves_context_wide_behavior(self):
        starter, fake_browser, context, _cdp = self._playwright_fakes()
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
        self.assertEqual(browser._header_intercept_mode, "context")

    async def test_empty_headers_do_not_enable_either_header_mode(self):
        starter, fake_browser, context, _cdp = self._playwright_fakes()
        browser = BrowserManager(
            header_scope_origins={"https://app.example"},
            expect_late_headers=False,
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
        self.assertEqual(browser._header_intercept_mode, "none")

    async def test_expected_late_headers_only_block_service_workers(self):
        starter, fake_browser, context, _cdp = self._playwright_fakes()
        browser = BrowserManager(
            header_scope_origins={"https://app.example"},
            expect_late_headers=True,
        )

        with patch("wscan.browser.async_playwright", return_value=starter):
            await browser.init()

        kwargs = fake_browser.new_context.await_args.kwargs
        self.assertEqual(kwargs["service_workers"], "block")
        self.assertNotIn("extra_http_headers", kwargs)
        context.new_cdp_session.assert_not_awaited()
        context.route.assert_not_awaited()
        context.set_extra_http_headers.assert_not_awaited()
        self.assertFalse(browser._context_wide_headers_active)
        self.assertFalse(browser._header_route_active)
        self.assertEqual(browser._header_intercept_mode, "none")

    async def test_expected_late_headers_retry_without_unsupported_sw_option(self):
        starter, fake_browser, context, _cdp = self._playwright_fakes()
        fake_browser.new_context.side_effect = [
            TypeError("unsupported service_workers option"),
            context,
        ]
        browser = BrowserManager(
            header_scope_origins={"https://app.example"},
            expect_late_headers=True,
        )

        with patch("wscan.browser.async_playwright", return_value=starter):
            await browser.init()

        first_kwargs = fake_browser.new_context.await_args_list[0].kwargs
        second_kwargs = fake_browser.new_context.await_args_list[1].kwargs
        self.assertEqual(first_kwargs["service_workers"], "block")
        self.assertNotIn("service_workers", second_kwargs)
        context.new_cdp_session.assert_not_awaited()
        context.route.assert_not_awaited()
        self.assertEqual(browser._header_intercept_mode, "none")


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
        self.assertEqual(
            engine._header_scope_origins,
            engine._browser.header_scope_origins,
        )
        self.assertFalse(engine.popup_header_intercept)
        self.assertFalse(engine._browser.popup_header_intercept)

    def test_engine_marks_refresh_command_as_expected_late_headers(self):
        from wscan.engine import ScanEngine

        with tempfile.TemporaryDirectory() as output_dir:
            engine = ScanEngine(
                url="https://app.example/start",
                header_refresh_cmd="refresh-auth-headers",
                output_dir=output_dir,
            )

        self.assertTrue(engine._browser.expect_late_headers)

    def test_engine_env_enables_popup_header_intercept_when_unspecified(self):
        from wscan.engine import ScanEngine

        for env_value in ("1", "true"):
            with self.subTest(env_value=env_value):
                with tempfile.TemporaryDirectory() as output_dir:
                    with patch.dict(
                        os.environ,
                        {"WSCAN_POPUP_HEADER_INTERCEPT": env_value},
                    ):
                        engine = ScanEngine(
                            url="https://app.example/start",
                            output_dir=output_dir,
                        )

                self.assertTrue(engine.popup_header_intercept)
                self.assertTrue(engine._browser.popup_header_intercept)

    def test_explicit_popup_header_setting_overrides_engine_env(self):
        from wscan.engine import ScanEngine

        with tempfile.TemporaryDirectory() as output_dir:
            with patch.dict(
                os.environ,
                {"WSCAN_POPUP_HEADER_INTERCEPT": "true"},
            ):
                engine = ScanEngine(
                    url="https://app.example/start",
                    popup_header_intercept=False,
                    output_dir=output_dir,
                )

        self.assertFalse(engine.popup_header_intercept)
        self.assertFalse(engine._browser.popup_header_intercept)

    def test_engine_env_disables_header_scope(self):
        from wscan.engine import ScanEngine

        with tempfile.TemporaryDirectory() as output_dir:
            with patch.dict(
                os.environ,
                {"WSCAN_HEADER_SCOPE_ENFORCE": "0"},
            ):
                engine = ScanEngine(
                    url="https://app.example/start",
                    headers={"Authorization": "Bearer secret"},
                    output_dir=output_dir,
                )

        self.assertFalse(engine.header_scope_enforce)
        self.assertFalse(engine._browser.header_scope_enforce)
        self.assertEqual(engine._browser.header_scope_origins, set())

    def test_config_can_disable_header_scope(self):
        from main import _load_config

        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "wscan.yaml"
            with open(config_path, "w", encoding="utf-8") as config_file:
                config_file.write(
                    "browser:\n"
                    "  header_scope_enforce: false\n"
                )
            config = _load_config(config_path)

        self.assertFalse(config["header_scope_enforce"])

    def test_config_can_enable_popup_header_intercept(self):
        from main import _load_config

        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "wscan.yaml"
            with open(config_path, "w", encoding="utf-8") as config_file:
                config_file.write(
                    "browser:\n"
                    "  popup_header_intercept: true\n"
                )
            config = _load_config(config_path)

        self.assertTrue(config["popup_header_intercept"])


class PopupHeaderInterceptCliTests(unittest.TestCase):
    def _parse(self, *, config_value=False, env_value=None, cli=False):
        import main

        argv = ["main.py", "scan", "https://app.example"]
        if cli:
            argv.append("--popup-header-intercept")
        with patch.object(
            main,
            "_CFG",
            {"popup_header_intercept": config_value},
        ):
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("WSCAN_POPUP_HEADER_INTERCEPT", None)
                if env_value is not None:
                    os.environ["WSCAN_POPUP_HEADER_INTERCEPT"] = env_value
                with patch.object(sys, "argv", argv):
                    return main.parse_args()

    def test_default_is_off(self):
        self.assertFalse(self._parse().popup_header_intercept)

    def test_cli_can_opt_in(self):
        self.assertTrue(self._parse(cli=True).popup_header_intercept)

    def test_env_can_opt_in(self):
        for env_value in ("1", "true"):
            with self.subTest(env_value=env_value):
                self.assertTrue(
                    self._parse(env_value=env_value).popup_header_intercept
                )

    def test_config_can_opt_in(self):
        self.assertTrue(
            self._parse(config_value=True).popup_header_intercept
        )

    def test_env_false_overrides_config_true(self):
        self.assertFalse(
            self._parse(
                config_value=True,
                env_value="false",
            ).popup_header_intercept
        )

    def test_cli_true_overrides_env_false(self):
        self.assertTrue(
            self._parse(
                config_value=True,
                env_value="false",
                cli=True,
            ).popup_header_intercept
        )


class EngineDirectHeaderScopeTests(unittest.TestCase):
    def _engine(self, output_dir: str, **overrides):
        from wscan.engine import ScanEngine

        options = {
            "url": "https://app.example/start",
            "headers": {
                "Authorization": "Bearer secret",
                "X-API-Key": "api-secret",
            },
            "output_dir": output_dir,
        }
        options.update(overrides)
        with patch.dict(
            os.environ,
            {"WSCAN_HEADER_SCOPE_ENFORCE": ""},
        ):
            return ScanEngine(**options)

    def test_headers_for_url_includes_custom_headers_for_allowed_origin(self):
        with tempfile.TemporaryDirectory() as output_dir:
            engine = self._engine(output_dir)

        self.assertEqual(
            engine.headers_for_url("https://app.example/private"),
            {
                "Authorization": "Bearer secret",
                "X-API-Key": "api-secret",
            },
        )

    def test_headers_for_url_omits_custom_headers_for_external_origin(self):
        with tempfile.TemporaryDirectory() as output_dir:
            engine = self._engine(output_dir)

        self.assertEqual(
            engine.headers_for_url("https://external.example/private"),
            {},
        )

    def test_external_origin_keeps_scanner_default_headers(self):
        with tempfile.TemporaryDirectory() as output_dir:
            engine = self._engine(output_dir)

        headers = engine.auth_headers(
            {"User-Agent": "wscan-test", "Accept": "application/json"},
            url="https://external.example/private",
        )

        self.assertNotIn("Authorization", headers)
        self.assertNotIn("X-API-Key", headers)
        self.assertEqual(headers["User-Agent"], "wscan-test")
        self.assertEqual(headers["Accept"], "application/json")

    def test_disabled_enforcement_always_returns_custom_headers(self):
        with tempfile.TemporaryDirectory() as output_dir:
            engine = self._engine(
                output_dir,
                header_scope_enforce=False,
            )

        self.assertEqual(
            engine.headers_for_url("https://external.example/private"),
            {
                "Authorization": "Bearer secret",
                "X-API-Key": "api-secret",
            },
        )

    def test_unknown_scope_preserves_legacy_custom_headers(self):
        with tempfile.TemporaryDirectory() as output_dir:
            engine = self._engine(
                output_dir,
                url="not-a-url",
            )

        self.assertEqual(
            engine.headers_for_url("https://external.example/private"),
            {
                "Authorization": "Bearer secret",
                "X-API-Key": "api-secret",
            },
        )


if __name__ == "__main__":
    unittest.main()
