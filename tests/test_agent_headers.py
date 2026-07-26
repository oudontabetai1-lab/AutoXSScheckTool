"""Agent/Hybrid 偵察へ渡すカスタムヘッダの合成・配線テスト。

browser-use は optional 依存のため、実ブラウザや browser_use 自体は起動しない。
"""
import tempfile
import unittest
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from unittest.mock import AsyncMock, patch

import main
from wscan.agent_engine import AgentEngine
from wscan.header_manager import apply_bearer, parse_header_args
from wscan.llm_agent_browser import (
    AgentBrowserScanner,
    allowed_header_origins,
    effective_origin_url,
    headers_allowed_for_url,
)


class _RecordingHeaderSession:
    def __init__(self, current_url="http://fixture.test"):
        self.calls = []
        self.current_url = current_url

    async def get_current_page_url(self):
        return self.current_url

    async def set_extra_headers(self, headers):
        self.calls.append(headers)


class _FailingHeaderSession:
    async def get_current_page_url(self):
        return "http://fixture.test"

    async def set_extra_headers(self, _headers):
        raise RuntimeError("header application failed")


class _RecordingInitialHeaderSession:
    def __init__(self, current_url="http://fixture.test"):
        self.calls = []
        self.current_url = current_url

    async def start(self):
        self.calls.append("start")

    async def get_current_page(self):
        self.calls.append("get_current_page")
        return object()

    async def get_current_page_url(self):
        return self.current_url

    async def set_extra_headers(self, headers):
        self.calls.append(("set_extra_headers", headers))


class _SessionWithoutCurrentPage:
    def __init__(self):
        self.calls = []

    async def start(self):
        self.calls.append("start")

    async def set_extra_headers(self, headers):
        self.calls.append(("set_extra_headers", headers))


class _FetchCommands:
    def __init__(self, fail_enable=False, fail_header_continue=False):
        self.calls = []
        self.fail_enable = fail_enable
        self.fail_header_continue = fail_header_continue

    async def enable(self, params=None, session_id=None):
        self.calls.append(("enable", params, session_id))
        if self.fail_enable:
            raise RuntimeError("Fetch enable failed")

    async def disable(self, params=None, session_id=None):
        self.calls.append(("disable", params, session_id))

    async def continueRequest(self, params, session_id=None):
        self.calls.append(("continueRequest", params, session_id))
        if self.fail_header_continue and "headers" in params:
            raise RuntimeError("Fetch continue failed")


class _FetchRegistration:
    def __init__(self, fail_registration=False):
        self.callback = None
        self.fail_registration = fail_registration

    def requestPaused(self, callback):
        if self.fail_registration:
            raise RuntimeError("Fetch handler registration failed")
        self.callback = callback


class _RequestScopedHeaderSession:
    def __init__(
        self,
        *,
        fail_enable=False,
        fail_registration=False,
        fail_header_continue=False,
    ):
        self.calls = []
        self.agent_focus_target_id = "target-1"
        self.fetch_commands = _FetchCommands(
            fail_enable=fail_enable,
            fail_header_continue=fail_header_continue,
        )
        self.fetch_registration = _FetchRegistration(
            fail_registration=fail_registration
        )
        cdp_client = SimpleNamespace(
            send=SimpleNamespace(Fetch=self.fetch_commands),
            register=SimpleNamespace(Fetch=self.fetch_registration),
        )
        self.cdp_session = SimpleNamespace(
            cdp_client=cdp_client,
            session_id="target-session",
        )

    async def start(self):
        self.calls.append("start")

    async def get_current_page(self):
        self.calls.append("get_current_page")
        return object()

    async def get_or_create_cdp_session(self, target_id, focus=False):
        self.calls.append(("get_or_create_cdp_session", target_id, focus))
        return self.cdp_session


class AgentHeaderCompositionTests(unittest.TestCase):
    def test_cli_headers_and_bearer_are_combined(self):
        headers = apply_bearer(
            parse_header_args(["X-Tenant: example", "X-Trace: enabled"]),
            "agent-token",
        )

        self.assertEqual(
            headers,
            {
                "X-Tenant": "example",
                "X-Trace": "enabled",
                "Authorization": "Bearer agent-token",
            },
        )

    def test_explicit_authorization_wins_over_bearer(self):
        headers = apply_bearer(
            parse_header_args(
                ["authorization: Custom agent-credential", "X-Tenant: example"]
            ),
            "ignored-token",
        )

        self.assertEqual(
            headers,
            {
                "authorization": "Custom agent-credential",
                "X-Tenant": "example",
            },
        )

    def test_config_headers_and_bearer_are_copied_and_combined(self):
        config_headers = {"X-Tenant": "example"}

        headers = apply_bearer(dict(config_headers), "config-token")

        self.assertEqual(
            headers,
            {
                "X-Tenant": "example",
                "Authorization": "Bearer config-token",
            },
        )
        self.assertEqual(config_headers, {"X-Tenant": "example"})

    def test_agent_cli_accepts_bearer_header_and_header_file(self):
        argv = [
            "main.py",
            "agent",
            "http://fixture.test",
            "--bearer",
            "agent-token",
            "-H",
            "X-Tenant: example",
            "--header-file",
            "headers.yaml",
        ]

        with mock.patch.object(sys, "argv", argv):
            args = main.parse_args()

        self.assertEqual(args.bearer, "agent-token")
        self.assertEqual(args.header, ["X-Tenant: example"])
        self.assertEqual(args.header_file, "headers.yaml")


class AgentHeaderOriginTests(unittest.TestCase):
    def test_effective_origin_url_uses_intended_url_for_blank_pages(self):
        intended_url = "https://fixture.test/start"

        for current_url in (
            "",
            "about:blank",
            "chrome://newtab/",
            "about:newtab",
        ):
            with self.subTest(current_url=current_url):
                self.assertEqual(
                    effective_origin_url(current_url, intended_url),
                    intended_url,
                )

    def test_effective_origin_url_keeps_current_real_url(self):
        current_url = "https://fixture.test/current"

        self.assertEqual(
            effective_origin_url(
                current_url,
                "https://fixture.test/intended",
            ),
            current_url,
        )

    def test_allowed_header_origins_collects_all_explicit_scopes(self):
        origins = allowed_header_origins(
            "https://primary.example/start",
            [
                "https://primary.example/app",
                "https://api.example:8443/v1",
            ],
            ["https://login.example/session"],
            "https://identity.example/sign-in",
        )

        self.assertEqual(
            origins,
            {
                "https://primary.example",
                "https://api.example:8443",
                "https://login.example",
                "https://identity.example",
            },
        )

    def test_allowed_header_origins_ignores_empty_and_invalid_urls(self):
        origins = allowed_header_origins(
            "",
            ["not-a-url", "http://[invalid"],
            ["/relative-only", "://missing-scheme"],
        )

        self.assertEqual(origins, set())

    def test_allowed_header_origins_treats_ports_as_distinct_origins(self):
        origins = allowed_header_origins(
            "https://api.example/resource",
            ["https://api.example:8443/resource"],
            [],
        )

        self.assertEqual(
            origins,
            {"https://api.example", "https://api.example:8443"},
        )

    def test_headers_allowed_for_url_matches_only_allowed_origin(self):
        allowed = {"https://api.example:8443"}

        self.assertTrue(
            headers_allowed_for_url("https://api.example:8443/v1", allowed)
        )
        self.assertFalse(
            headers_allowed_for_url("https://api.example/v1", allowed)
        )
        self.assertFalse(
            headers_allowed_for_url("https://evil.example/v1", allowed)
        )
        self.assertFalse(headers_allowed_for_url("", allowed))
        self.assertFalse(headers_allowed_for_url("not-a-url", allowed))
        self.assertFalse(headers_allowed_for_url("http://[invalid", allowed))

    def test_headers_allowed_for_url_normalizes_default_ports(self):
        https_allowed = allowed_header_origins(
            "https://host.example:443/start",
            [],
            [],
        )
        http_allowed = allowed_header_origins(
            "http://host.example:80/start",
            [],
            [],
        )

        self.assertEqual(https_allowed, {"https://host.example"})
        self.assertTrue(
            headers_allowed_for_url(
                "https://host.example/current",
                https_allowed,
            )
        )
        self.assertEqual(http_allowed, {"http://host.example"})
        self.assertTrue(
            headers_allowed_for_url(
                "http://host.example/current",
                http_allowed,
            )
        )
        self.assertFalse(
            headers_allowed_for_url(
                "https://host.example:8443/current",
                https_allowed,
            )
        )


class AgentHeaderWiringTests(unittest.IsolatedAsyncioTestCase):
    async def test_run_passes_a_copied_header_dict_to_scanner(self):
        supplied_headers = {"Authorization": "Bearer agent-token"}
        result = SimpleNamespace(
            findings=[],
            steps_taken=0,
            success=True,
            error="",
            final_summary="",
        )

        with tempfile.TemporaryDirectory() as output_dir, patch(
            "wscan.llm_agent_browser.AgentBrowserScanner"
        ) as scanner_cls, patch(
            "wscan.report.ReportGenerator.generate",
            return_value=Path(output_dir) / "report.html",
        ):
            scanner_cls.return_value.run = AsyncMock(return_value=result)
            engine = AgentEngine(
                url="http://fixture.test",
                extra_headers=supplied_headers,
                output_dir=output_dir,
                open_report=False,
            )
            supplied_headers["X-Late"] = "not-forwarded"

            await engine.run()

        self.assertEqual(
            engine.extra_headers,
            {"Authorization": "Bearer agent-token"},
        )
        self.assertEqual(
            scanner_cls.call_args.kwargs["extra_headers"],
            {"Authorization": "Bearer agent-token"},
        )

    async def test_run_recon_passes_headers_to_scanner(self):
        result = SimpleNamespace(
            findings=[],
            memory=SimpleNamespace(visited_urls=[]),
            final_summary="",
        )

        with tempfile.TemporaryDirectory() as output_dir, patch(
            "wscan.llm_agent_browser.AgentBrowserScanner"
        ) as scanner_cls:
            scanner_cls.return_value.run = AsyncMock(return_value=result)
            engine = AgentEngine(
                url="http://fixture.test",
                extra_headers={"X-Tenant": "example"},
                output_dir=output_dir,
                open_report=False,
            )

            await engine.run_recon()

        self.assertEqual(
            scanner_cls.call_args.kwargs["extra_headers"],
            {"X-Tenant": "example"},
        )


class AgentBrowserHeaderApplicationTests(unittest.IsolatedAsyncioTestCase):
    async def test_request_scoped_headers_adds_headers_for_allowed_origin(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
        )
        session = _RequestScopedHeaderSession()

        enabled = await scanner._enable_request_scoped_headers(session)
        await session.fetch_registration.callback(
            {
                "requestId": "allowed-request",
                "request": {
                    "url": "http://fixture.test/page",
                    "headers": {
                        "Accept": "text/html",
                        "authorization": "stale-value",
                    },
                },
            },
            "event-session",
        )

        self.assertTrue(enabled)
        self.assertTrue(scanner._request_scoped_headers)
        self.assertEqual(
            session.fetch_commands.calls[-1],
            (
                "continueRequest",
                {
                    "requestId": "allowed-request",
                    "headers": [
                        {"name": "Accept", "value": "text/html"},
                        {
                            "name": "Authorization",
                            "value": "Bearer test-token",
                        },
                    ],
                },
                "event-session",
            ),
        )

    async def test_request_scoped_headers_omits_headers_for_disallowed_origin(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
        )
        session = _RequestScopedHeaderSession()

        enabled = await scanner._enable_request_scoped_headers(session)
        await session.fetch_registration.callback(
            {
                "requestId": "disallowed-request",
                "request": {
                    "url": "https://third-party.example/script.js",
                    "headers": {"Accept": "*/*"},
                },
            },
            None,
        )

        self.assertTrue(enabled)
        self.assertEqual(
            session.fetch_commands.calls[-1],
            (
                "continueRequest",
                {"requestId": "disallowed-request"},
                "target-session",
            ),
        )

    async def test_request_scoped_handler_exception_still_continues_request(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
        )
        session = _RequestScopedHeaderSession()
        await scanner._enable_request_scoped_headers(session)

        with patch(
            "wscan.llm_agent_browser.headers_allowed_for_url",
            side_effect=RuntimeError("origin check failed"),
        ):
            await session.fetch_registration.callback(
                {
                    "requestId": "fallback-request",
                    "request": {"url": "http://fixture.test/page", "headers": {}},
                },
                None,
            )

        self.assertEqual(
            session.fetch_commands.calls[-1],
            (
                "continueRequest",
                {"requestId": "fallback-request"},
                "target-session",
            ),
        )

    async def test_request_scoped_continue_failure_retries_without_headers(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
        )
        session = _RequestScopedHeaderSession(fail_header_continue=True)
        await scanner._enable_request_scoped_headers(session)

        await session.fetch_registration.callback(
            {
                "requestId": "retry-request",
                "request": {"url": "http://fixture.test/page", "headers": {}},
            },
            None,
        )

        continue_calls = [
            call
            for call in session.fetch_commands.calls
            if call[0] == "continueRequest"
        ]
        self.assertEqual(len(continue_calls), 2)
        self.assertIn("headers", continue_calls[0][1])
        self.assertEqual(
            continue_calls[1],
            (
                "continueRequest",
                {"requestId": "retry-request"},
                "target-session",
            ),
        )

    async def test_request_scoped_enable_failure_disables_and_returns_false(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
        )
        session = _RequestScopedHeaderSession(fail_enable=True)

        enabled = await scanner._enable_request_scoped_headers(session)

        self.assertFalse(enabled)
        self.assertFalse(scanner._request_scoped_headers)
        self.assertEqual(
            session.fetch_commands.calls[-1],
            ("disable", None, "target-session"),
        )

    async def test_request_scoped_registration_failure_never_enables_fetch(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
        )
        session = _RequestScopedHeaderSession(fail_registration=True)

        enabled = await scanner._enable_request_scoped_headers(session)

        self.assertFalse(enabled)
        self.assertFalse(scanner._request_scoped_headers)
        self.assertNotIn(
            "enable",
            [call[0] for call in session.fetch_commands.calls],
        )
        self.assertEqual(
            session.fetch_commands.calls[-1],
            ("disable", None, "target-session"),
        )

    async def test_request_scoped_headers_skips_empty_headers(self):
        scanner = AgentBrowserScanner("http://fixture.test")
        session = _RequestScopedHeaderSession()

        enabled = await scanner._enable_request_scoped_headers(session)

        self.assertFalse(enabled)
        self.assertEqual(session.calls, [])
        self.assertEqual(session.fetch_commands.calls, [])

    async def test_prepare_headers_before_run_uses_required_lifecycle_order(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
        )
        session = _RecordingInitialHeaderSession()

        await scanner._prepare_extra_headers_before_run(session)

        self.assertEqual(
            session.calls,
            [
                "start",
                "get_current_page",
                (
                    "set_extra_headers",
                    {"Authorization": "Bearer test-token"},
                ),
            ],
        )

    async def test_prepare_headers_uses_intended_url_on_blank_page(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
        )
        session = _RecordingInitialHeaderSession("about:blank")

        await scanner._prepare_extra_headers_before_run(
            session,
            "http://fixture.test/start",
        )

        self.assertEqual(
            session.calls,
            [
                "start",
                "get_current_page",
                (
                    "set_extra_headers",
                    {"Authorization": "Bearer test-token"},
                ),
            ],
        )

    async def test_prepare_headers_rejects_disallowed_intended_url_on_blank_page(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
        )
        session = _RecordingInitialHeaderSession("about:blank")

        await scanner._prepare_extra_headers_before_run(
            session,
            "https://evil.example/start",
        )

        self.assertEqual(
            session.calls,
            [
                "start",
                "get_current_page",
            ],
        )
        self.assertFalse(scanner._headers_applied)

    async def test_prepare_headers_before_run_skips_empty_headers(self):
        scanner = AgentBrowserScanner("http://fixture.test")
        session = _RecordingInitialHeaderSession()

        await scanner._prepare_extra_headers_before_run(session)

        self.assertEqual(session.calls, [])

    async def test_prepare_headers_before_run_skips_session_without_current_page(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"X-Tenant": "example"},
        )
        session = _SessionWithoutCurrentPage()

        await scanner._prepare_extra_headers_before_run(session)

        self.assertEqual(session.calls, [])

    async def test_prepare_headers_warns_when_apis_missing(self):
        # ヘッダ指定があるのにセッションが必要 API を欠く版では、未認証のまま静かに
        # 偵察するのを避けて警告する（ただしヘッダ値は出さない）。
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
        )
        session = _SessionWithoutCurrentPage()
        with patch("wscan.llm_agent_browser.console") as mock_console:
            await scanner._prepare_extra_headers_before_run(session)
        self.assertTrue(mock_console.print.called)
        printed = " ".join(str(c) for c in mock_console.print.call_args_list)
        self.assertNotIn("Bearer test-token", printed)

    async def test_apply_extra_headers_calls_session_once(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
        )
        session = _RecordingHeaderSession()

        await scanner._apply_extra_headers(session)

        self.assertEqual(
            session.calls,
            [{"Authorization": "Bearer test-token"}],
        )

    async def test_apply_extra_headers_skips_disallowed_origin(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
        )
        session = _RecordingHeaderSession("https://evil.example/page")

        await scanner._apply_extra_headers(session)

        self.assertEqual(session.calls, [])
        self.assertFalse(scanner._headers_applied)

    async def test_apply_extra_headers_clears_headers_after_leaving_allowed_origin(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
        )
        session = _RecordingHeaderSession()

        await scanner._apply_extra_headers(session)
        session.current_url = "https://evil.example/page"
        await scanner._apply_extra_headers(session)

        self.assertEqual(
            session.calls,
            [
                {"Authorization": "Bearer test-token"},
                {},
            ],
        )
        self.assertFalse(scanner._headers_applied)

    async def test_apply_extra_headers_without_current_url_api_fails_closed(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"X-Tenant": "example"},
        )
        session = _SessionWithoutCurrentPage()

        with patch("wscan.llm_agent_browser.console") as mock_console:
            await scanner._apply_extra_headers(session)
            await scanner._apply_extra_headers(session)

        self.assertEqual(session.calls, [])
        self.assertEqual(mock_console.print.call_count, 1)

    async def test_apply_extra_headers_skips_empty_headers(self):
        scanner = AgentBrowserScanner("http://fixture.test")
        session = _RecordingHeaderSession()

        await scanner._apply_extra_headers(session)

        self.assertEqual(session.calls, [])

    async def test_apply_extra_headers_ignores_session_without_api(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"X-Tenant": "example"},
        )

        await scanner._apply_extra_headers(object())

    async def test_apply_extra_headers_swallows_session_errors(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"X-Tenant": "example"},
        )

        await scanner._apply_extra_headers(_FailingHeaderSession())


if __name__ == "__main__":
    unittest.main()
