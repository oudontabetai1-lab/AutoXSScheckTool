"""Agent/Hybrid 偵察へ渡すカスタムヘッダの合成・配線テスト。

browser-use は optional 依存のため、実ブラウザや browser_use 自体は起動しない。
"""
import asyncio
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
    expand_scheme_variants,
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


class _TargetCommands:
    def __init__(self):
        self.calls = []

    async def setAutoAttach(self, params=None, session_id=None):
        self.calls.append(("setAutoAttach", params, session_id))


class _RuntimeCommands:
    def __init__(self):
        self.calls = []

    async def runIfWaitingForDebugger(self, params=None, session_id=None):
        self.calls.append(
            ("runIfWaitingForDebugger", params, session_id)
        )


class _TargetRegistration:
    def __init__(self, registry):
        self.registry = registry
        self.callback = None

    def attachedToTarget(self, callback):
        self.callback = callback
        self.registry._handlers["Target.attachedToTarget"] = callback


class _EventRegistry:
    def __init__(self, attached_handler):
        self._handlers = {"Target.attachedToTarget": attached_handler}

    def unregister(self, method):
        self._handlers.pop(method, None)


class _RequestScopedHeaderSession:
    def __init__(
        self,
        *,
        fail_enable=False,
        fail_registration=False,
        fail_header_continue=False,
        target_events=False,
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
        if target_events:
            self.attached_events = []

            def _existing_attached_handler(event, session_id=None):
                self.attached_events.append((event, session_id))

            event_registry = _EventRegistry(_existing_attached_handler)
            target_registration = _TargetRegistration(event_registry)
            self.target_commands = _TargetCommands()
            self.runtime_commands = _RuntimeCommands()
            self._cdp_client_root = SimpleNamespace(
                _event_registry=event_registry,
                send=SimpleNamespace(
                    Fetch=self.fetch_commands,
                    Target=self.target_commands,
                    Runtime=self.runtime_commands,
                ),
                register=SimpleNamespace(
                    Fetch=self.fetch_registration,
                    Target=target_registration,
                ),
            )
            self.target_registration = target_registration

    async def start(self):
        self.calls.append("start")

    async def get_current_page(self):
        self.calls.append("get_current_page")
        return object()

    async def get_or_create_cdp_session(self, target_id, focus=False):
        self.calls.append(("get_or_create_cdp_session", target_id, focus))
        return self.cdp_session


class AgentHeaderCompositionTests(unittest.TestCase):
    def test_multiline_config_headers_are_coerced_before_scan_setup(self):
        cfg = {"headers": "X-Tenant: example\nX-Trace: enabled"}

        headers = apply_bearer(main._coerce_headers(cfg.get("headers")), "")

        self.assertEqual(
            headers,
            {
                "X-Tenant": "example",
                "X-Trace": "enabled",
            },
        )
        self.assertIsInstance(headers, dict)

    def test_config_header_dict_is_copied(self):
        config_headers = {"X-Tenant": "example"}

        headers = main._coerce_headers(config_headers)
        headers["X-Trace"] = "enabled"

        self.assertEqual(config_headers, {"X-Tenant": "example"})
        self.assertIsNot(headers, config_headers)

    def test_empty_or_none_config_headers_become_empty_dict(self):
        for value in ("", "   \n", None):
            with self.subTest(value=value):
                self.assertEqual(main._coerce_headers(value), {})

    def test_unparseable_config_headers_do_not_raise(self):
        self.assertEqual(main._coerce_headers("not a header\nalso invalid"), {})

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

    def test_expand_scheme_variants_adds_http_and_https_for_omitted_scheme(self):
        origins = expand_scheme_variants(
            {"http://fixture.test"},
            {"fixture.test/start"},
        )

        self.assertEqual(
            origins,
            {"http://fixture.test", "https://fixture.test"},
        )

    def test_explicit_http_target_does_not_expand_to_https(self):
        scanner = AgentBrowserScanner("http://fixture.test")

        self.assertEqual(scanner._header_origins, {"http://fixture.test"})

    def test_omitted_scheme_with_port_preserves_port_for_both_variants(self):
        origins = expand_scheme_variants(
            {"http://fixture.test:8443"},
            {"fixture.test:8443/start"},
        )

        self.assertEqual(
            origins,
            {
                "http://fixture.test:8443",
                "https://fixture.test:8443",
            },
        )

    def test_scanner_wires_omitted_target_scheme_to_both_variants(self):
        scanner = AgentBrowserScanner("fixture.test/start")

        self.assertEqual(
            scanner._header_origins,
            {"http://fixture.test", "https://fixture.test"},
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
            error=None,
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

    async def test_request_scoped_headers_enable_fetch_for_new_target(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
        )
        session = _RequestScopedHeaderSession()
        await scanner._enable_request_scoped_headers(session)

        session.agent_focus_target_id = "target-2"
        enabled = await scanner._enable_fetch_for_current_target(session)

        self.assertTrue(enabled)
        self.assertEqual(
            [call[0] for call in session.fetch_commands.calls].count("enable"),
            2,
        )
        self.assertEqual(
            set(scanner._fetch_enabled_targets),
            {"target-1", "target-2"},
        )

    async def test_request_scoped_headers_enable_fetch_on_target_event(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
        )
        session = _RequestScopedHeaderSession(target_events=True)

        enabled = await scanner._enable_request_scoped_headers(session)

        self.assertTrue(enabled)
        self.assertIs(scanner._target_event_client, session._cdp_client_root)
        self.assertEqual(
            session.target_commands.calls,
            [(
                "setAutoAttach",
                {
                    "autoAttach": True,
                    "waitForDebuggerOnStart": True,
                    "flatten": True,
                },
                None,
            )],
        )

        event = {
            "sessionId": "popup-session",
            "waitingForDebugger": True,
            "targetInfo": {
                "targetId": "popup-target",
                "type": "page",
            },
        }
        session.target_registration.callback(event, "root-session")
        await asyncio.gather(*tuple(scanner._target_event_tasks))

        self.assertIn(
            ("enable", {"patterns": [{"urlPattern": "*"}]}, "popup-session"),
            session.fetch_commands.calls,
        )
        self.assertEqual(
            session.runtime_commands.calls,
            [("runIfWaitingForDebugger", None, "popup-session")],
        )
        self.assertEqual(
            session.attached_events,
            [(event, "root-session")],
        )
        self.assertIn("popup-target", scanner._fetch_enabled_targets)

    async def test_target_event_awaits_async_existing_handler_before_resume(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
        )
        session = _RequestScopedHeaderSession(target_events=True)
        handler_completed = False
        resume_observations = []

        async def _existing_handler(event, session_id=None):
            nonlocal handler_completed
            await asyncio.sleep(0)
            handler_completed = True

        async def _resume(params=None, session_id=None):
            resume_observations.append((handler_completed, session_id))

        session._cdp_client_root._event_registry._handlers[
            "Target.attachedToTarget"
        ] = _existing_handler
        session.runtime_commands.runIfWaitingForDebugger = _resume
        await scanner._enable_request_scoped_headers(session)

        session.target_registration.callback(
            {
                "sessionId": "popup-session",
                "targetInfo": {
                    "targetId": "popup-target",
                    "type": "page",
                },
            },
            "root-session",
        )
        await asyncio.gather(*tuple(scanner._target_event_tasks))

        self.assertTrue(handler_completed)
        self.assertEqual(resume_observations, [(True, "popup-session")])

    async def test_target_event_calls_sync_existing_handler_before_resume(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
        )
        session = _RequestScopedHeaderSession(target_events=True)
        call_order = []

        def _existing_handler(event, session_id=None):
            call_order.append(("handler", session_id))

        async def _resume(params=None, session_id=None):
            call_order.append(("resume", session_id))

        session._cdp_client_root._event_registry._handlers[
            "Target.attachedToTarget"
        ] = _existing_handler
        session.runtime_commands.runIfWaitingForDebugger = _resume
        await scanner._enable_request_scoped_headers(session)

        session.target_registration.callback(
            {
                "sessionId": "popup-session",
                "targetInfo": {
                    "targetId": "popup-target",
                    "type": "page",
                },
            },
            "root-session",
        )
        await asyncio.gather(*tuple(scanner._target_event_tasks))

        self.assertEqual(
            call_order,
            [("handler", "root-session"), ("resume", "popup-session")],
        )

    async def test_target_event_handler_exception_still_resumes_target(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
        )
        session = _RequestScopedHeaderSession(target_events=True)

        async def _existing_handler(event, session_id=None):
            raise RuntimeError("existing handler failed")

        session._cdp_client_root._event_registry._handlers[
            "Target.attachedToTarget"
        ] = _existing_handler
        await scanner._enable_request_scoped_headers(session)

        session.target_registration.callback(
            {
                "sessionId": "popup-session",
                "targetInfo": {
                    "targetId": "popup-target",
                    "type": "page",
                },
            },
            "root-session",
        )
        await asyncio.gather(*tuple(scanner._target_event_tasks))

        self.assertEqual(
            session.runtime_commands.calls,
            [("runIfWaitingForDebugger", None, "popup-session")],
        )

    async def test_target_event_handler_timeout_still_resumes_target(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
        )
        session = _RequestScopedHeaderSession(target_events=True)
        never_finishes = asyncio.Event()

        async def _existing_handler(event, session_id=None):
            await never_finishes.wait()

        session._cdp_client_root._event_registry._handlers[
            "Target.attachedToTarget"
        ] = _existing_handler
        await scanner._enable_request_scoped_headers(session)

        with patch(
            "wscan.llm_agent_browser._TARGET_HANDLER_TIMEOUT_SECONDS",
            0.01,
        ):
            session.target_registration.callback(
                {
                    "sessionId": "popup-session",
                    "targetInfo": {
                        "targetId": "popup-target",
                        "type": "page",
                    },
                },
                "root-session",
            )
            await asyncio.gather(*tuple(scanner._target_event_tasks))

        self.assertEqual(
            session.runtime_commands.calls,
            [("runIfWaitingForDebugger", None, "popup-session")],
        )

    async def test_target_event_fetch_failure_still_resumes_target(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
        )
        session = _RequestScopedHeaderSession(target_events=True)
        await scanner._enable_request_scoped_headers(session)
        session.fetch_commands.fail_enable = True

        session.target_registration.callback(
            {
                "sessionId": "popup-session",
                "waitingForDebugger": True,
                "targetInfo": {
                    "targetId": "popup-target",
                    "type": "page",
                },
            },
            "root-session",
        )
        await asyncio.gather(*tuple(scanner._target_event_tasks))

        self.assertNotIn("popup-target", scanner._fetch_enabled_targets)
        self.assertEqual(
            session.fetch_commands.calls[-1],
            ("disable", None, "popup-session"),
        )
        self.assertEqual(
            session.runtime_commands.calls,
            [("runIfWaitingForDebugger", None, "popup-session")],
        )

    async def test_request_scoped_headers_keep_step_path_without_target_events(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
        )
        session = _RequestScopedHeaderSession()

        enabled = await scanner._enable_request_scoped_headers(session)
        session.agent_focus_target_id = "target-2"
        step_enabled = await scanner._enable_fetch_for_current_target(session)

        self.assertTrue(enabled)
        self.assertIsNone(scanner._target_event_client)
        self.assertTrue(step_enabled)
        self.assertEqual(
            [call[0] for call in session.fetch_commands.calls].count("enable"),
            2,
        )

    async def test_request_scoped_headers_do_not_enable_same_target_twice(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
        )
        session = _RequestScopedHeaderSession()
        await scanner._enable_request_scoped_headers(session)

        enabled = await scanner._enable_fetch_for_current_target(session)

        self.assertTrue(enabled)
        self.assertEqual(
            [call[0] for call in session.fetch_commands.calls].count("enable"),
            1,
        )

    async def test_same_target_is_reenabled_when_client_or_session_changes(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
        )
        first_session = _RequestScopedHeaderSession()
        await scanner._enable_request_scoped_headers(first_session)

        enabled = await scanner._enable_fetch_for_cdp_target(
            first_session.cdp_session.cdp_client,
            "reconnected-session",
            "target-1",
        )

        self.assertTrue(enabled)
        self.assertEqual(
            [
                call
                for call in first_session.fetch_commands.calls
                if call[0] == "enable"
            ][-1],
            (
                "enable",
                {"patterns": [{"urlPattern": "*"}]},
                "reconnected-session",
            ),
        )

        second_fetch = _FetchCommands()
        second_client = SimpleNamespace(
            send=SimpleNamespace(Fetch=second_fetch),
            register=SimpleNamespace(Fetch=_FetchRegistration()),
        )
        enabled = await scanner._enable_fetch_for_cdp_target(
            second_client,
            "reconnected-session",
            "target-1",
        )

        self.assertTrue(enabled)
        self.assertEqual(
            second_fetch.calls,
            [(
                "enable",
                {"patterns": [{"urlPattern": "*"}]},
                "reconnected-session",
            )],
        )
        self.assertEqual(
            scanner._fetch_enabled_targets["target-1"],
            (id(second_client), "reconnected-session"),
        )

    async def test_request_scoped_headers_new_target_failure_is_swallowed(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
        )
        session = _RequestScopedHeaderSession()
        await scanner._enable_request_scoped_headers(session)
        session.agent_focus_target_id = "target-2"
        session.fetch_commands.fail_enable = True

        enabled = await scanner._enable_fetch_for_current_target(session)

        self.assertFalse(enabled)
        self.assertNotIn("target-2", scanner._fetch_enabled_targets)
        self.assertEqual(session.fetch_commands.calls[-1][0], "disable")

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
        monitor = SimpleNamespace(emit_status=AsyncMock())
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"Authorization": "Bearer test-token"},
            monitor=monitor,
        )
        session = _RecordingHeaderSession()

        await scanner._apply_extra_headers(session)

        self.assertEqual(
            session.calls,
            [{"Authorization": "Bearer test-token"}],
        )
        monitor.emit_status.assert_not_awaited()

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

    async def test_apply_extra_headers_warns_monitor_once_on_session_errors(self):
        monitor = SimpleNamespace(emit_status=AsyncMock())
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"X-Tenant": "example"},
            monitor=monitor,
        )
        session = _FailingHeaderSession()

        await scanner._apply_extra_headers(session)
        await scanner._apply_extra_headers(session)

        monitor.emit_status.assert_awaited_once_with(
            "Agent ブラウザへ認証ヘッダを適用できませんでした。"
            "認証が必要なページを偵察できない可能性があります。",
            "running",
        )

    async def test_apply_extra_headers_warns_console_without_monitor(self):
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"X-Tenant": "secret-tenant"},
        )

        with patch("wscan.llm_agent_browser.console") as mock_console:
            await scanner._apply_extra_headers(_FailingHeaderSession())

        mock_console.print.assert_called_once()
        printed = str(mock_console.print.call_args)
        self.assertIn("認証ヘッダを適用できませんでした", printed)
        self.assertNotIn("X-Tenant", printed)
        self.assertNotIn("secret-tenant", printed)

    async def test_prepare_extra_headers_warns_once_on_session_start_error(self):
        monitor = SimpleNamespace(emit_status=AsyncMock())
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"X-Tenant": "secret-tenant"},
            monitor=monitor,
        )
        session = SimpleNamespace(
            start=AsyncMock(side_effect=RuntimeError("session start failed")),
            get_current_page=AsyncMock(),
            set_extra_headers=AsyncMock(),
        )

        await scanner._prepare_extra_headers_before_run(session)
        await scanner._prepare_extra_headers_before_run(session)

        monitor.emit_status.assert_awaited_once_with(
            "Agent ブラウザへ認証ヘッダを適用できませんでした。"
            "認証が必要なページを偵察できない可能性があります。",
            "running",
        )

    async def test_clear_extra_headers_warns_monitor_once_on_session_errors(self):
        monitor = SimpleNamespace(emit_status=AsyncMock())
        scanner = AgentBrowserScanner(
            "http://fixture.test",
            extra_headers={"X-Tenant": "secret-tenant"},
            monitor=monitor,
        )
        scanner._headers_applied = True
        session = _FailingHeaderSession()

        await scanner._clear_extra_headers(session)
        await scanner._clear_extra_headers(session)

        monitor.emit_status.assert_awaited_once_with(
            "Agent ブラウザの認証ヘッダを解除できませんでした。"
            "対象外ページへ認証情報が送信される可能性があります。",
            "running",
        )


if __name__ == "__main__":
    unittest.main()
