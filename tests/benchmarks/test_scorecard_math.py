import json

import pytest

from wscan.benchmark_model import (
    INCOMPLETE_STATES,
    BenchmarkCase,
    BenchmarkSuite,
    CaseExecutionState,
    CaseResult,
    Classification,
    ExpectedOutcome,
    GateKind,
    OverallStatus,
    RequestSpec,
    SourceKind,
    build_scorecard,
    case_classification,
    classify,
    compute_metrics,
    overall_status,
    scorecard_to_markdown,
)


def _case(
    case_id: str,
    expected: ExpectedOutcome,
    *,
    gate: GateKind = GateKind.OBSERVED,
) -> BenchmarkCase:
    return BenchmarkCase(
        case_id=case_id,
        expected=expected,
        check="xss",
        request=RequestSpec(method="GET", path="/search"),
        gate=gate,
    )


@pytest.mark.parametrize(
    ("expected", "matched", "classification"),
    [
        (ExpectedOutcome.VULNERABLE, True, Classification.TP),
        (ExpectedOutcome.VULNERABLE, False, Classification.FN),
        (ExpectedOutcome.SAFE, True, Classification.FP),
        (ExpectedOutcome.SAFE, False, Classification.TN),
    ],
)
def test_classify_four_quadrants(expected, matched, classification):
    assert classify(expected, matched) == classification


@pytest.mark.parametrize("state", sorted(INCOMPLETE_STATES, key=lambda item: item.value))
def test_incomplete_states_are_not_negative_or_in_any_denominator(state):
    case = _case("vulnerable", ExpectedOutcome.VULNERABLE)
    result = CaseResult(
        case_id=case.case_id,
        state=state,
        candidate_match=True,
        confirmed_match=True,
    )

    assert case_classification(case, result, tier="candidate") is None
    assert case_classification(case, result, tier="confirmed") is None
    metrics = compute_metrics((case,), (result,))
    for tier in ("candidate", "confirmed"):
        assert {key: metrics[tier][key] for key in ("tp", "fn", "fp", "tn")} == {
            "tp": 0,
            "fn": 0,
            "fp": 0,
            "tn": 0,
        }
        assert metrics[tier]["recall_denominator"] == 0
        assert metrics[tier]["precision_denominator"] == 0


def test_candidate_and_confirmed_are_separate_accounts():
    case = _case("vulnerable", ExpectedOutcome.VULNERABLE)
    result = CaseResult(
        case_id=case.case_id,
        state=CaseExecutionState.COMPLETED,
        candidate_match=True,
        confirmed_match=False,
    )

    metrics = compute_metrics((case,), (result,))

    assert metrics["candidate"]["tp"] == 1
    assert metrics["candidate"]["recall"] == 1.0
    assert metrics["confirmed"]["fn"] == 1
    assert metrics["confirmed"]["recall"] == 0.0


def test_zero_denominators_are_none_not_vacuous_success():
    safe = _case("safe", ExpectedOutcome.SAFE)
    metrics = compute_metrics(
        (safe,),
        (CaseResult("safe", CaseExecutionState.COMPLETED),),
    )

    assert metrics["candidate"]["recall"] is None
    assert metrics["candidate"]["recall_denominator"] == 0
    assert metrics["confirmed"]["recall"] is None
    assert metrics["confirmed"]["recall_denominator"] == 0


def test_duplicate_case_results_are_counted_once():
    case = _case("vulnerable", ExpectedOutcome.VULNERABLE)
    duplicate_results = (
        CaseResult("vulnerable", CaseExecutionState.COMPLETED, True, True),
        CaseResult("vulnerable", CaseExecutionState.COMPLETED, True, True),
    )

    metrics = compute_metrics((case,), duplicate_results)

    assert metrics["candidate"]["tp"] == 1
    assert metrics["confirmed"]["tp"] == 1


def test_overall_status_incomplete_invalid_and_complete():
    required = _case(
        "vulnerable",
        ExpectedOutcome.VULNERABLE,
        gate=GateKind.REQUIRED,
    )
    safe = _case("safe", ExpectedOutcome.SAFE)

    assert overall_status(
        (required, safe),
        (
            CaseResult("vulnerable", CaseExecutionState.COMPLETED, True, True),
            CaseResult("safe", CaseExecutionState.TIMEOUT),
        ),
    ) == OverallStatus.INCOMPLETE
    assert overall_status(
        (required,),
        (CaseResult("vulnerable", CaseExecutionState.INVALID_MANIFEST),),
    ) == OverallStatus.FAILED
    assert overall_status(
        (required, safe),
        (
            CaseResult("vulnerable", CaseExecutionState.COMPLETED, True, True),
            CaseResult("safe", CaseExecutionState.COMPLETED, False, False),
        ),
    ) == OverallStatus.COMPLETE


def test_scorecard_is_json_serializable_and_markdown_uses_its_metrics():
    required = _case(
        "vulnerable",
        ExpectedOutcome.VULNERABLE,
        gate=GateKind.REQUIRED,
    )
    suite = BenchmarkSuite(
        schema_version=1,
        suite_id="unit",
        fixture_id="unit_fixture",
        runner_profile="http",
        mode="normal-deterministic",
        source_kind=SourceKind.FIRST_PARTY,
        cases=(required,),
    )
    scorecard = build_scorecard(
        suite,
        (CaseResult("vulnerable", CaseExecutionState.COMPLETED, True, False),),
        run_id="run-1",
        source_sha="abc123",
        manifest_digest="manifest",
        registry_digest="registry",
        environment={"workers": 1},
    )

    json.dumps(scorecard)
    markdown = scorecard_to_markdown(scorecard)

    assert scorecard["metrics"]["candidate"]["recall"] == 1.0
    assert scorecard["metrics"]["confirmed"]["recall"] == 0.0
    assert "1.0" in markdown
    assert "0.0" in markdown
    assert "PARTIAL" in markdown
    assert "| check | xss | candidate |" in markdown


def test_confirmed_match_without_candidate_is_rejected():
    # confirmed ⊆ candidate（P1）: confirmed_match=True かつ candidate_match=False は矛盾。
    with pytest.raises(ValueError):
        CaseResult(
            "c",
            CaseExecutionState.COMPLETED,
            candidate_match=False,
            confirmed_match=True,
        )


def test_markdown_escapes_pipe_and_newline_in_breakdown_keys():
    # taxonomy/mode に | や改行があっても Markdown table を壊さない（P2）。
    tier = {
        "tp": 0, "fn": 0, "fp": 0, "tn": 0,
        "recall": None, "precision": None,
        "recall_denominator": 0, "precision_denominator": 0,
    }
    scorecard = {
        "run_id": "r|x",
        "overall_status": "PARTIAL",
        "case_counts": {"planned": 0, "completed": 0, "incomplete": 0},
        "metrics": {"candidate": dict(tier), "confirmed": dict(tier)},
        "breakdowns": {
            "check": {}, "carrier": {},
            "taxonomy": {"a|b": {"candidate": dict(tier), "confirmed": dict(tier)}},
            "mode": {},
        },
    }
    md = scorecard_to_markdown(scorecard)
    # エスケープ済みで、生の "a|b" 由来の余分な列区切りが出ない
    assert "a\\|b" in md
    assert "r\\|x" in md
    # taxonomy 行は candidate/confirmed の2行だけ（| による列注入・改行による行注入が無い）
    rows = [ln for ln in md.splitlines() if ln.startswith("| taxonomy |")]
    assert len(rows) == 2
