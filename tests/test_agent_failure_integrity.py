"""Agent 初期化失敗を正常な 0 findings と誤表示しないことを検証する。"""

from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from rich.console import Console

import main
from wscan.llm_agent_browser import (
    AgentBrowserScanner,
    _agent_config_directory_result,
)


def test_agent_config_directory_result_accepts_writable_directory():
    assert _agent_config_directory_result("/writable/config", True) == (True, "")


def test_agent_config_directory_result_has_actionable_xdg_guidance():
    ok, message = _agent_config_directory_result("/read-only/config", False)

    assert ok is False
    assert "/read-only/config" in message
    assert "XDG_CONFIG_HOME" in message
    assert "書込み可能" in message


def test_agent_exit_code_flags_errors_and_unsuccessful_empty_runs():
    # 明示エラー → 1。
    assert main._agent_exit_code(
        SimpleNamespace(error="initialization failed", success=False, findings=[])
    ) == 1
    # 正常成功（success=True）→ 0。
    assert main._agent_exit_code(
        SimpleNamespace(error="", success=True, findings=[])
    ) == 0
    # history 上の非成功 かつ 0 findings（誤成功表示の元）→ 1。
    assert main._agent_exit_code(
        SimpleNamespace(error="", success=False, findings=[])
    ) == 1
    # 非成功でも findings があれば検出は有効 → 0。
    assert main._agent_exit_code(
        SimpleNamespace(error="", success=False, findings=[object()])
    ) == 0
    assert main._agent_exit_code(None) == 0


@pytest.mark.asyncio
async def test_agent_initialization_error_prints_failed_not_zero_findings():
    output = StringIO()
    scanner = AgentBrowserScanner(target_url="http://fixture.test")

    with patch(
        "wscan.llm_agent_browser.check_agent_config_directory",
        return_value=(True, ""),
    ), patch(
        "wscan.llm_agent_browser._build_llm",
        side_effect=RuntimeError("provider unavailable"),
    ), patch(
        "wscan.llm_agent_browser.console",
        Console(file=output, force_terminal=False, color_system=None),
    ):
        result = await scanner.run()

    rendered = output.getvalue()
    assert result.error == "provider unavailable"
    assert main._agent_exit_code(result) == 1
    assert "Agent scan FAILED: provider unavailable" in rendered
    assert "脆弱性は検出されませんでした" not in rendered
    assert "0 findings" not in rendered


@pytest.mark.asyncio
async def test_agent_missing_browser_use_is_failed_not_traceback():
    # browser-use 未導入は _build_llm が ModuleNotFoundError(ImportError)を投げる。
    # traceback で漏らさず FAILED＋非0 exit にする（D8・Codex #101）。
    output = StringIO()
    scanner = AgentBrowserScanner(target_url="http://fixture.test")
    with patch(
        "wscan.llm_agent_browser.check_agent_config_directory", return_value=(True, ""),
    ), patch(
        "wscan.llm_agent_browser._build_llm",
        side_effect=ModuleNotFoundError("No module named 'browser_use'"),
    ), patch(
        "wscan.llm_agent_browser.console",
        Console(file=output, force_terminal=False, color_system=None),
    ):
        result = await scanner.run()

    assert result.error is not None
    assert main._agent_exit_code(result) == 1
    assert "Agent scan FAILED" in output.getvalue()


@pytest.mark.asyncio
async def test_agent_unsuccessful_history_is_incomplete_not_clean():
    # browser-use が例外でなく history.is_successful()=False で失敗を報告し、findings が
    # 空のとき、「正常完了・0 findings」と誤表示せず INCOMPLETE＋非0 exit にする（D8）。
    import sys
    import types

    output = StringIO()

    class _FakeHistory:
        def is_successful(self):
            return False

        def final_result(self):
            return ""

        def extracted_content(self):
            return []

        def errors(self):
            return []

        def model_actions(self):
            return []

        def urls(self):
            return []

    class _FakeAgent:
        def __init__(self, **_kwargs):
            pass

        async def run(self, **_kwargs):
            return _FakeHistory()

    class _FakeBrowser:
        def __init__(self, **_kwargs):
            pass

        async def stop(self):
            return None

    browser_use = types.ModuleType("browser_use")
    browser_use.Agent = _FakeAgent
    browser_use.Browser = _FakeBrowser

    scanner = AgentBrowserScanner(target_url="http://fixture.test")
    with patch(
        "wscan.llm_agent_browser.check_agent_config_directory", return_value=(True, ""),
    ), patch(
        "wscan.llm_agent_browser._build_llm", return_value=object(),
    ), patch(
        "wscan.llm_agent_browser.console",
        Console(file=output, force_terminal=False, color_system=None),
    ), patch.dict(sys.modules, {"browser_use": browser_use}):
        result = await scanner.run()

    rendered = output.getvalue()
    assert result.error is None
    assert result.success is False
    assert not result.findings
    assert main._agent_exit_code(result) == 1
    assert "INCOMPLETE" in rendered
    assert "Agent Scan Complete" not in rendered
    assert "脆弱性は検出されませんでした" not in rendered



@pytest.mark.asyncio
async def test_monitored_agent_incomplete_empty_returns_before_sleep():
    # monitored 経路（ダッシュボード有り）でも、incomplete-empty（success=False かつ
    # 0 findings）のとき sleep(3600) に入らず result を返し、_agent_exit_code が非0を
    # 返せることを検証する（D8・Codex #101 comment 3845791232）。early-return 条件を
    # `result.error` だけにしていると、Ctrl+C 待ちの sleep に落ちて非0 exit が消える。
    import types

    sleep_calls: list = []

    async def _fake_sleep(delay, *a, **k):
        sleep_calls.append(delay)
        return None

    incomplete = SimpleNamespace(error=None, success=False, findings=[])

    class _FakeEngine:
        def __init__(self, **_kwargs):
            pass

        async def run(self):
            return incomplete

    class _FakeMonitor:
        def __init__(self, **_kwargs):
            self.app = object()

    class _FakeConfig:
        def __init__(self, **_kwargs):
            pass

    class _FakeServer:
        def __init__(self, config):
            self.should_exit = False

        async def serve(self):
            return None

    fake_uvicorn = types.SimpleNamespace(Config=_FakeConfig, Server=_FakeServer)

    args = SimpleNamespace(
        url="http://fixture.test",
        llm="none",
        model="",
        ollama_url="http://localhost:11434",
        llm_base_url="",
        checks=["xss"],
        no_headless=True,
        auth_user="",
        auth_pass="",
        login_url="",
        max_steps=1,
        output="",
        open_report=False,
        no_open_report=True,
        no_monitor=False,
        port=9099,
        header_file="",
        bearer="",
        header=[],
    )

    with patch.dict("sys.modules", {"uvicorn": fake_uvicorn}), patch(
        "wscan.monitor.MonitorServer", _FakeMonitor
    ), patch(
        "wscan.agent_engine.AgentEngine", _FakeEngine
    ), patch(
        "main.webbrowser.open", lambda *a, **k: None
    ), patch(
        "main.asyncio.sleep", _fake_sleep
    ):
        result = await main.run_agent(args)

    assert result is incomplete
    assert main._agent_exit_code(result) == 1
    # sleep(3600)（Ctrl+C 待ち）へは絶対に入らない。
    assert 3600 not in sleep_calls
