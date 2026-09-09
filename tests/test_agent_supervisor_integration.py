"""browser-use を fake にした役割分割 supervisor の決定論的統合テスト。"""
from __future__ import annotations

import re
import json
import sys
import types
from unittest.mock import patch

import pytest

from wscan.llm_agent_browser import AgentBrowserScanner
from wscan.agent_harness import AgentHarness, AgentRunSpec


class _History:
    def __init__(self, text):
        self.text = text

    def is_successful(self):
        return True

    def final_result(self):
        return self.text

    def extracted_content(self):
        return []

    def errors(self):
        return []


@pytest.mark.asyncio
async def test_supervisor_runs_explore_probe_verify_and_adversarial_review(tmp_path):
    tasks = []
    budgets = []

    class _Agent:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            tasks.append(kwargs["task"])

        async def run(self, **_kwargs):
            budgets.append(_kwargs["max_steps"])
            task = self.kwargs["task"]
            if "Act only as the Explorer" in task:
                await self.kwargs["register_new_step_callback"](
                    types.SimpleNamespace(url="http://fixture.test/observed-only"),
                    types.SimpleNamespace(action=[]),
                    1,
                )
                await self.kwargs["register_new_step_callback"](
                    types.SimpleNamespace(url="http://idp.test/login"),
                    types.SimpleNamespace(action=[]),
                    2,
                )
                return _History("PAGE_FOUND: http://fixture.test/search\nEXPLORATION COMPLETE")
            if "probe specialist" in task:
                nonce = re.search(r"WSCAN-NONCE:([^\s]+)", self.kwargs["extend_system_message"]).group(1)
                return _History(
                    f"WSCAN-NONCE:{nonce}\nVULNERABILITY FOUND:\n"
                    "Type: xss\nSeverity: high\nURL: http://fixture.test/search\n"
                    "Field: q\nPayload: <svg/onload=alert(1)>\n"
                    f"Evidence: {'A' * 13050}\n"
                    f"WSCAN-NONCE:{nonce}\nVULNERABILITY FOUND:\n"
                    "Type: xss\nSeverity: high\nURL: http://fixture.test/search\n"
                    "Field: r\nPayload: <svg/onload=alert(2)>\n"
                    "Evidence: second dialog observed\nPROBE COMPLETE"
                )
            if "independent verifier" in task:
                # Fresh episode repeats the same nonce-bound evidence.
                nonce = re.search(r"WSCAN-NONCE:([^\s]+)", self.kwargs["extend_system_message"]).group(1)
                field = "r" if '"field_name": "r"' in task else "q"
                return _History(
                    f"WSCAN-NONCE:{nonce}\nVULNERABILITY FOUND:\n"
                    "Type: xss\nSeverity: high\nURL: http://fixture.test/search\n"
                    f"Field: {field}\nPayload: <svg/onload=alert(1)>\n"
                    "Evidence: dialog observed again\nVERIFICATION COMPLETE"
                )
            return _History("REVIEW COMPLETE")

    class _Browser:
        def __init__(self, **_kwargs):
            pass

        async def stop(self):
            pass

    module = types.ModuleType("browser_use")
    module.Agent = _Agent
    module.Browser = _Browser
    scanner = AgentBrowserScanner(
        "http://fixture.test", checks=["xss"], max_steps=40,
        access_urls=["http://idp.test"],
        harness_output_dir=tmp_path,
    )
    with patch("wscan.llm_agent_browser._build_llm", return_value=object()), patch(
        "wscan.llm_agent_browser.check_agent_config_directory", return_value=(True, "")
    ), patch.dict(sys.modules, {"browser_use": module}):
        result = await scanner.run()

    assert any("Act only as the Explorer" in task for task in tasks)
    assert budgets[0] <= 20  # 40-step run の半分以上を後続 role に予約する。
    assert any("probe specialist" in task for task in tasks)
    assert any("fixture.test/observed-only" in task for task in tasks)
    assert not any("probe specialist for http://idp.test" in task for task in tasks)
    assert any("independent verifier" in task for task in tasks)
    assert sum("independent verifier" in task for task in tasks) == 2
    assert any("adversarial reviewer" in task for task in tasks)
    assert result.harness_status == "complete"
    assert result.coverage_gaps == []
    assert len(result.findings) == 2
    assert all(finding.dynamic_verified for finding in result.findings)
    assert all(finding.agent_verified is False for finding in result.findings)


@pytest.mark.asyncio
async def test_pre_execution_callback_does_not_claim_action_was_executed(tmp_path):
    class _Action:
        def model_dump(self, **_kwargs):
            return {"click": {"index": 1}}

    scanner = AgentBrowserScanner("http://fixture.test")
    scanner._harness = AgentHarness(
        tmp_path,
        AgentRunSpec(
            mode="agent", target_url="http://fixture.test",
            target_urls=("http://fixture.test",), access_urls=(),
            exclude_urls=(), exclude_fields=(), checks=("xss",),
            provider="ollama", model="exact", max_steps=5,
        ),
    )
    scanner._active_episode_id = "episode"
    output = types.SimpleNamespace(action=[_Action()])
    await scanner._on_step(types.SimpleNamespace(url="http://fixture.test"), output, 1)

    record = json.loads((tmp_path / "agent_steps.jsonl").read_text())
    assert record["proposed_actions"]
    assert record["executed_actions"] == []
