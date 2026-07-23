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
from wscan.llm_agent_browser import AgentBrowserScanner


class _RecordingHeaderSession:
    def __init__(self):
        self.calls = []

    async def set_extra_headers(self, headers):
        self.calls.append(headers)


class _FailingHeaderSession:
    async def set_extra_headers(self, _headers):
        raise RuntimeError("header application failed")


class _RecordingInitialHeaderSession:
    def __init__(self):
        self.calls = []

    async def start(self):
        self.calls.append("start")

    async def get_current_page(self):
        self.calls.append("get_current_page")
        return object()

    async def set_extra_headers(self, headers):
        self.calls.append(("set_extra_headers", headers))


class _SessionWithoutCurrentPage:
    def __init__(self):
        self.calls = []

    async def start(self):
        self.calls.append("start")

    async def set_extra_headers(self, headers):
        self.calls.append(("set_extra_headers", headers))


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
