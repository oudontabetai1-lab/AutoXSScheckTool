"""Agent supervisor harness の状態・証跡・resume契約。"""
from __future__ import annotations

import json

import pytest

from wscan.agent_harness import (
    AgentHarness,
    AgentPhase,
    AgentRole,
    AgentRunSpec,
    AgentRunStatus,
    WorkStatus,
    step_signature,
)


def spec(*, model="exact-model", max_steps=5):
    return AgentRunSpec(
        mode="agent",
        target_url="http://fixture.test",
        target_urls=("http://fixture.test",),
        access_urls=(),
        exclude_urls=("/logout",),
        exclude_fields=("csrf_token",),
        checks=("xss", "sqli"),
        provider="ollama",
        model=model,
        max_steps=max_steps,
    )


def test_spec_hash_is_stable_and_model_sensitive():
    assert spec().spec_hash == spec().spec_hash
    assert spec().spec_hash != spec(model="other").spec_hash


def test_step_trace_redacts_secrets_and_checkpoints_budget(tmp_path):
    harness = AgentHarness(tmp_path, spec())
    harness.set_phase(AgentPhase.EXECUTING)

    harness.record_step(
        episode_id="episode-1",
        local_step=2,
        url="http://fixture.test/a?access_token=secret-token",
        proposed_actions=[{"input_text": {"text": "password=secret-value"}}],
        executed_actions=[{"click": {"index": 2}}],
    )

    state = json.loads((tmp_path / "agent_state.json").read_text())
    trace = (tmp_path / "agent_steps.jsonl").read_text()
    assert state["consumed_steps"] == 2
    assert harness.remaining_steps == 3
    assert "secret-token" not in trace
    assert "secret-value" not in trace
    assert "<redacted>" in trace


def test_loop_breaker_marks_partial_without_losing_coverage(tmp_path):
    harness = AgentHarness(tmp_path, spec(max_steps=10), repeat_threshold=3)
    for step in range(1, 4):
        harness.record_step(
            episode_id="episode-1",
            local_step=step,
            url="http://fixture.test/search",
            proposed_actions=[{"click": {"index": 1}}],
            executed_actions=[{"click": {"index": 1}}],
        )
    harness.note_coverage(
        visited_urls=["http://fixture.test/search"],
        coverage_gaps=["q:sqli"],
    )

    status = harness.finalize(success=False, coverage_complete=False)

    assert status == AgentRunStatus.PARTIAL
    assert harness.state.stop_reason == "loop_detected"
    assert harness.state.coverage_gaps == ["q:sqli"]
    assert json.loads((tmp_path / "agent_manifest.json").read_text())["status"] == "partial"


def test_resume_preserves_global_budget_and_rejects_spec_drift(tmp_path):
    first = AgentHarness(tmp_path, spec(max_steps=5))
    first.record_step(
        episode_id="episode-1", local_step=3, url="http://fixture.test/a",
        proposed_actions=[], executed_actions=[],
    )

    resumed = AgentHarness(tmp_path, spec(max_steps=5), resume=True)
    assert resumed.remaining_steps == 2
    assert "2 global steps remain" in resumed.resume_context()
    resumed.record_step(
        episode_id="episode-2", local_step=2, url="http://fixture.test/b",
        proposed_actions=[], executed_actions=[],
    )
    assert resumed.remaining_steps == 0

    with pytest.raises(ValueError, match="spec mismatch"):
        AgentHarness(tmp_path, spec(model="different", max_steps=5), resume=True)


def test_complete_requires_explicit_coverage_contract(tmp_path):
    harness = AgentHarness(tmp_path, spec())
    assert harness.finalize(success=True, coverage_complete=False) == AgentRunStatus.PARTIAL

    other = AgentHarness(tmp_path / "complete", spec())
    other.note_coverage(visited_urls=["http://fixture.test"])
    assert other.finalize(success=True, coverage_complete=True) == AgentRunStatus.COMPLETE


def test_step_signature_is_deterministic():
    assert step_signature("http://a/", ["click"]) == step_signature("http://a", ["click"])


def test_work_queue_is_persistent_and_requires_every_role_to_complete(tmp_path):
    harness = AgentHarness(tmp_path, spec())
    explore = harness.enqueue(AgentRole.EXPLORER, "http://fixture.test/")
    probe = harness.enqueue(
        AgentRole.PROBE_SPECIALIST,
        "http://fixture.test/search?q=",
        check_type="xss",
    )
    assert harness.enqueue(AgentRole.EXPLORER, "http://fixture.test/").work_id == explore.work_id
    assert harness.next_work().work_id == explore.work_id
    harness.finish_work(explore.work_id, WorkStatus.COMPLETE)
    assert harness.coverage_complete is False

    resumed = AgentHarness(tmp_path, spec(), resume=True)
    assert resumed.next_work().work_id == probe.work_id
    resumed.finish_work(probe.work_id, WorkStatus.COMPLETE)
    assert resumed.coverage_complete is True


def test_inconclusive_verification_prevents_complete(tmp_path):
    harness = AgentHarness(tmp_path, spec())
    verifier = harness.enqueue(AgentRole.VERIFIER, "hypothesis:1", check_type="sqli")
    harness.next_work()
    harness.finish_work(verifier.work_id, WorkStatus.INCONCLUSIVE)
    assert harness.coverage_complete is False


def test_resume_requeues_interrupted_running_work(tmp_path):
    harness = AgentHarness(tmp_path, spec(max_steps=8))
    item = harness.enqueue(AgentRole.EXPLORER, "http://fixture.test")
    assert harness.next_work().status == WorkStatus.RUNNING
    resumed = AgentHarness(tmp_path, spec(max_steps=8), resume=True)
    assert resumed.next_work().work_id == item.work_id


def test_runtime_secret_values_are_removed_from_trace_and_checkpoint(tmp_path):
    harness = AgentHarness(tmp_path, spec(), secret_values=["unlabeled-secret"])
    item = harness.enqueue(AgentRole.AUTHENTICATOR, "http://fixture.test/login")
    harness.next_work()
    harness.record_step(
        episode_id=item.work_id, local_step=1, url="http://fixture.test/login",
        proposed_actions=[{"input_text": {"text": "unlabeled-secret"}}],
        executed_actions=[],
    )
    harness.finish_work(item.work_id, WorkStatus.COMPLETE, summary="echo unlabeled-secret")
    artifacts = (tmp_path / "agent_steps.jsonl").read_text() + (tmp_path / "agent_state.json").read_text()
    assert "unlabeled-secret" not in artifacts
    assert "<redacted>" in artifacts


def test_requeue_role_resets_completed_authentication(tmp_path):
    harness = AgentHarness(tmp_path, spec())
    auth = harness.enqueue(AgentRole.AUTHENTICATOR, "http://fixture.test/login")
    harness.next_work()
    harness.finish_work(auth.work_id, WorkStatus.COMPLETE, summary="AUTH COMPLETE")
    assert harness.requeue_role(AgentRole.AUTHENTICATOR) == 1
    assert harness.next_work().work_id == auth.work_id


def test_structured_hypotheses_survive_resume_without_session_nonce(tmp_path):
    harness = AgentHarness(tmp_path, spec(max_steps=8))
    hypothesis = {
        "candidate_id": "candidate-1",
        "check_type": "xss",
        "severity": "high",
        "url": "http://fixture.test/search",
        "field_name": "q",
        "payload": "<svg/onload=alert(1)>",
        "evidence": "dialog observed",
        "dynamic_verified": False,
    }
    harness.note_hypotheses([hypothesis])
    resumed = AgentHarness(tmp_path, spec(max_steps=8), resume=True)
    assert resumed.state.hypotheses == [hypothesis]
    resumed.mark_dynamic_verification("candidate-1", True)
    assert resumed.state.hypotheses[0]["dynamic_verified"] is True
