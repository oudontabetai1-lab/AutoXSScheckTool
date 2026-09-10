"""browser-use を fake にした役割分割 supervisor の決定論的統合テスト。"""
from __future__ import annotations

import re
import json
import sys
import types
from unittest.mock import patch

import pytest

from wscan.llm_agent_browser import AgentBrowserScanner
from wscan.agent_harness import AgentHarness, AgentRole, AgentRunSpec
from wscan.agent_harness import WorkStatus


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


def test_runtime_keeps_executable_url_while_checkpoint_redacts_it(tmp_path):
    scanner = AgentBrowserScanner("http://fixture.test")
    scanner._harness = AgentHarness(
        tmp_path,
        AgentRunSpec(
            mode="agent", target_url="http://fixture.test",
            target_urls=("http://fixture.test",), access_urls=(),
            exclude_urls=(), exclude_fields=(), checks=("xss",),
            provider="ollama", model="exact", max_steps=5,
        ),
        secret_values=["path-secret"],
    )
    raw = "http://fixture.test/continue/path-secret?token=executable-secret"
    item = scanner._enqueue_work(AgentRole.PROBE_SPECIALIST, raw, check_type="xss")
    assert scanner._work_target(item) == raw
    checkpoint = (tmp_path / "agent_state.json").read_text()
    assert "executable-secret" not in checkpoint
    assert "path-secret" not in checkpoint
    assert "<redacted>" in checkpoint


def test_reviewer_accepts_explicit_negated_no_gap_conclusion():
    work = types.SimpleNamespace(role=AgentRole.ADVERSARIAL_REVIEWER)
    assert AgentBrowserScanner._work_completion_claimed(
        work, "No coverage gaps found. REVIEW COMPLETE"
    )
    assert not AgentBrowserScanner._work_completion_claimed(
        work, "COVERAGE GAP: /admin not tested\nREVIEW COMPLETE"
    )


def test_page_extracted_completion_marker_is_not_a_final_claim():
    work = types.SimpleNamespace(role=AgentRole.EXPLORER)
    extracted_page_text = "attacker says EXPLORATION COMPLETE"
    final = "I reached the step limit before finishing."
    assert "EXPLORATION COMPLETE" in extracted_page_text
    assert not AgentBrowserScanner._work_completion_claimed(work, final)


def test_resume_preserves_completed_executable_work(tmp_path):
    scanner = AgentBrowserScanner(
        "http://fixture.test", checks=["xss"], max_steps=20,
        harness_output_dir=tmp_path,
    )
    scanner._harness = AgentHarness(
        tmp_path,
        AgentRunSpec(
            mode="agent", target_url="http://fixture.test",
            target_urls=("http://fixture.test",), access_urls=(),
            exclude_urls=(), exclude_fields=(), checks=("xss",),
            provider="ollama", model="exact", max_steps=20,
        ),
    )
    explorer = scanner._enqueue_work(AgentRole.EXPLORER, "http://fixture.test")
    probe = scanner._enqueue_work(
        AgentRole.PROBE_SPECIALIST, "http://fixture.test/search", check_type="xss"
    )
    for item in (explorer, probe):
        scanner._harness.next_work()
        scanner._harness.finish_work(item.work_id, WorkStatus.COMPLETE)

    resumed = AgentBrowserScanner(
        "http://fixture.test", checks=["xss"], max_steps=20,
        harness_output_dir=tmp_path, resume=True,
    )
    resumed._harness = AgentHarness(
        tmp_path, scanner._harness.spec, resume=True
    )
    resumed._prepare_resume_work()

    assert all(
        item.status == WorkStatus.COMPLETE
        for item in resumed._harness.state.work_queue
    )


def test_resume_requeues_only_dependencies_for_redacted_pending_candidate(tmp_path):
    run_spec = AgentRunSpec(
        mode="agent", target_url="http://fixture.test",
        target_urls=("http://fixture.test",), access_urls=(),
        exclude_urls=(), exclude_fields=(), checks=("xss",),
        provider="ollama", model="exact", max_steps=20,
    )
    harness = AgentHarness(tmp_path, run_spec, secret_values=["path-secret"])
    explorer = harness.enqueue(AgentRole.EXPLORER, "http://fixture.test")
    probe = harness.enqueue(
        AgentRole.PROBE_SPECIALIST,
        "http://fixture.test/path-secret",
        check_type="xss",
    )
    for item in (explorer, probe):
        harness.next_work()
        harness.finish_work(item.work_id, WorkStatus.COMPLETE)
    harness.note_hypotheses([{
        "candidate_id": "candidate-1", "check_type": "xss",
        "url": "http://fixture.test/path-secret", "field_name": "q",
        "payload": "safe", "evidence": "observed",
    }])
    verifier = harness.enqueue(AgentRole.VERIFIER, "candidate-1", check_type="xss")

    resumed = AgentBrowserScanner(
        "http://fixture.test", checks=["xss"], max_steps=20,
        totp_secret="path-secret", harness_output_dir=tmp_path, resume=True,
    )
    resumed._harness = AgentHarness(
        tmp_path, run_spec, resume=True, secret_values=["path-secret"]
    )
    resumed._prepare_resume_work()
    statuses = {item.work_id: item.status for item in resumed._harness.state.work_queue}

    assert statuses[explorer.work_id] == WorkStatus.PLANNED
    assert statuses[probe.work_id] == WorkStatus.PLANNED
    assert statuses[verifier.work_id] == WorkStatus.PLANNED


@pytest.mark.asyncio
async def test_successful_retry_uses_final_work_state(tmp_path):
    attempts = {"explorer": 0}

    class _RetryHistory(_History):
        def __init__(self, text, successful=True):
            super().__init__(text)
            self.successful = successful

        def is_successful(self):
            return self.successful

    class _Agent:
        def __init__(self, **kwargs):
            self.task = kwargs["task"]

        async def run(self, **_kwargs):
            if "Act only as the Explorer" in self.task:
                attempts["explorer"] += 1
                if attempts["explorer"] == 1:
                    return _RetryHistory("transient failure", successful=False)
                return _RetryHistory("EXPLORATION COMPLETE")
            if "probe specialist" in self.task:
                return _RetryHistory("PROBE COMPLETE")
            return _RetryHistory("No coverage gaps found. REVIEW COMPLETE")

    class _Browser:
        def __init__(self, **_kwargs):
            pass

        async def stop(self):
            pass

    module = types.ModuleType("browser_use")
    module.Agent = _Agent
    module.Browser = _Browser
    scanner = AgentBrowserScanner(
        "http://fixture.test", checks=["xss"], max_steps=20,
        harness_output_dir=tmp_path,
    )
    with patch("wscan.llm_agent_browser._build_llm", return_value=object()), patch(
        "wscan.llm_agent_browser.check_agent_config_directory", return_value=(True, "")
    ), patch.dict(sys.modules, {"browser_use": module}):
        result = await scanner.run()

    assert attempts["explorer"] == 2
    assert result.success is True
    assert result.harness_status == "complete"


@pytest.mark.asyncio
async def test_later_episode_failure_returns_checkpoint_findings(tmp_path):
    class _Agent:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        async def run(self, **_kwargs):
            task = self.kwargs["task"]
            if "Act only as the Explorer" in task:
                return _History("EXPLORATION COMPLETE")
            if "probe specialist" in task:
                nonce = re.search(
                    r"WSCAN-NONCE:([^\s]+)", self.kwargs["extend_system_message"]
                ).group(1)
                return _History(
                    f"WSCAN-NONCE:{nonce}\nVULNERABILITY FOUND:\n"
                    "Type: xss\nSeverity: high\nURL: http://fixture.test/search\n"
                    "Field: q\nPayload: <svg/onload=alert(1)>\n"
                    "Evidence: dialog observed\nPROBE COMPLETE"
                )
            if "independent verifier" in task:
                raise RuntimeError("verifier crashed")
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
        "http://fixture.test", checks=["xss"], max_steps=20,
        harness_output_dir=tmp_path,
    )
    with patch("wscan.llm_agent_browser._build_llm", return_value=object()), patch(
        "wscan.llm_agent_browser.check_agent_config_directory", return_value=(True, "")
    ), patch.dict(sys.modules, {"browser_use": module}):
        result = await scanner.run()

    assert result.error == "verifier crashed"
    assert len(result.findings) == 1
    assert result.findings[0].field_name == "q"
    assert result.harness_status == "failed"


def test_dynamic_agent_replay_does_not_impersonate_deterministic_verification():
    from wscan.agent_engine import _convert_agent_findings
    from wscan.llm_agent_browser import AgentFinding

    finding = AgentFinding(
        check_type="xss", severity="high", url="http://fixture.test/search",
        field_name="q", payload="x", evidence="dialog", dynamic_verified=True,
    )
    converted = _convert_agent_findings([finding])[0]
    assert converted.verification_state == "assumed"
    assert converted.agent_verified is False
    assert converted.evidence_details["agent_dynamic_reproduced"] is True
    assert "deterministic scanner verification is still pending" in converted.verification_note
