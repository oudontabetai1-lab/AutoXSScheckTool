"""検証ライフサイクル型のユニットテスト（0015 MODEL-001a・ブラウザ非依存）。

型の不変条件と、既存 verification_state 文字列との後方互換を固定する。
"""
import dataclasses
import json

import pytest

from wscan.verification_model import (
    Hypothesis,
    HypothesisSource,
    Observation,
    ProbeAttempt,
    ProbeKind,
    VerificationResult,
    VerificationState,
)


def test_state_values_match_base_py_strings():
    # base.py の verification_state 文字列（#105 RESULT-001）と一致＝str Enum で相互運用可
    assert VerificationState.REPRODUCED == "reproduced"
    assert VerificationState.ASSUMED == "assumed"
    assert VerificationState.UNREPRODUCED == "unreproduced"
    assert VerificationState.SKIPPED == "skipped"
    assert {s.value for s in VerificationState} == {
        "reproduced", "assumed", "unreproduced", "skipped"
    }


def test_probe_attempt_failed_property():
    ok = ProbeAttempt(kind=ProbeKind.PAYLOAD, url="/a", status=200)
    assert not ok.failed
    broken = ProbeAttempt(kind=ProbeKind.PAYLOAD, url="/a", status=None, error="ConnectTimeout")
    assert broken.failed
    # status 無し・error 無しは「失敗」と断定しない（不明を失敗にしない）
    unknown = ProbeAttempt(kind=ProbeKind.PROBE, url="/a")
    assert not unknown.failed


def test_hypothesis_confidence_bounds_enforced():
    Hypothesis(check_type="xss", source=HypothesisSource.LLM, confidence=0.0)
    Hypothesis(check_type="xss", source=HypothesisSource.LLM, confidence=1.0)
    for bad in (-0.1, 1.1, 2.0):
        with pytest.raises(ValueError):
            Hypothesis(check_type="xss", source=HypothesisSource.AGENT, confidence=bad)


def test_hypothesis_holds_agent_llm_output_without_promotion():
    # Agent/LLM 出自を保持（捨てない）。Finding への昇格はここでは起きない（型は仮説のまま）
    h = Hypothesis(
        check_type="sqli",
        source=HypothesisSource.AGENT,
        confidence=0.4,
        rationale="agent noticed boolean-diff",
        observations=(Observation(kind="diff", detail="len 120 vs 118", probe_ref=2),),
    )
    assert h.source == HypothesisSource.AGENT
    assert h.observations[0].kind == "diff"


def test_verification_result_confirmed_only_when_reproduced():
    assert VerificationResult(state=VerificationState.REPRODUCED).confirmed
    for s in (VerificationState.ASSUMED, VerificationState.UNREPRODUCED, VerificationState.SKIPPED):
        assert not VerificationResult(state=s).confirmed


def test_types_are_frozen():
    p = ProbeAttempt(kind=ProbeKind.BASELINE, url="/a")
    with pytest.raises(dataclasses.FrozenInstanceError):
        p.url = "/b"  # type: ignore[misc]


def test_types_are_json_serializable():
    h = Hypothesis(
        check_type="xss",
        source=HypothesisSource.DETERMINISTIC,
        confidence=0.5,
        observations=(Observation(kind="reflection", detail="in <script>"),),
    )
    # str Enum なので asdict→json 可
    payload = json.dumps(dataclasses.asdict(h))
    assert json.loads(payload)["source"] == "deterministic"

    v = VerificationResult(
        state=VerificationState.REPRODUCED,
        reproduced_by=(ProbeAttempt(kind=ProbeKind.PAYLOAD, url="/a", status=200),),
    )
    assert json.loads(json.dumps(dataclasses.asdict(v)))["state"] == "reproduced"
