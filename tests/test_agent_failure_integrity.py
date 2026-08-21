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


def test_agent_exit_code_depends_only_on_result_error():
    assert main._agent_exit_code(SimpleNamespace(error="initialization failed")) == 1
    assert main._agent_exit_code(SimpleNamespace(error="")) == 0
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

