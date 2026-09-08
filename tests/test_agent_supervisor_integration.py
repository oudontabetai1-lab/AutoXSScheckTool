"""browser-use を fake にした役割分割 supervisor の決定論的統合テスト。"""
from __future__ import annotations

import re
import sys
import types
from unittest.mock import patch

import pytest

from wscan.llm_agent_browser import AgentBrowserScanner


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

    class _Agent:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            tasks.append(kwargs["task"])

        async def run(self, **_kwargs):
            task = self.kwargs["task"]
            if "Act only as the Explorer" in task:
                return _History("PAGE_FOUND: http://fixture.test/search\nEXPLORATION COMPLETE")
            if "probe specialist" in task:
                nonce = re.search(r"WSCAN-NONCE:([^\s]+)", self.kwargs["extend_system_message"]).group(1)
                return _History(
                    f"WSCAN-NONCE:{nonce}\nVULNERABILITY FOUND:\n"
                    "Type: xss\nSeverity: high\nURL: http://fixture.test/search\n"
                    "Field: q\nPayload: <svg/onload=alert(1)>\n"
                    "Evidence: dialog observed\nPROBE COMPLETE"
                )
            if "independent verifier" in task:
                # Fresh episode repeats the same nonce-bound evidence.
                nonce = re.search(r"WSCAN-NONCE:([^\s]+)", self.kwargs["extend_system_message"]).group(1)
                block = task[task.find("WSCAN-CANDIDATE"):].replace(
                    "WSCAN-CANDIDATE", f"WSCAN-NONCE:{nonce}", 1
                )
                return _History(block + "\nVERIFICATION COMPLETE")
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
        harness_output_dir=tmp_path,
    )
    with patch("wscan.llm_agent_browser._build_llm", return_value=object()), patch(
        "wscan.llm_agent_browser.check_agent_config_directory", return_value=(True, "")
    ), patch.dict(sys.modules, {"browser_use": module}):
        result = await scanner.run()

    assert any("Act only as the Explorer" in task for task in tasks)
    assert any("probe specialist" in task for task in tasks)
    assert any("independent verifier" in task for task in tasks)
    assert any("adversarial reviewer" in task for task in tasks)
    assert result.harness_status == "complete"
    assert result.coverage_gaps == []
    assert result.findings and result.findings[0].dynamic_verified is True
    assert result.findings[0].agent_verified is False
