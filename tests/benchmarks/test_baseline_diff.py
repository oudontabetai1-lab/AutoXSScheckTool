"""benchmark scorecard の baseline 差分（0034）の純粋テスト。

main baseline との差分（追加/消失/回帰/改善）を case 単位で検出できることを固定する。
精度の回帰（TP→FN 等）と measurement の欠落（分類 None）を混同しないことも確認する。
"""
import pytest

from wscan.benchmark_model import compute_baseline_diff


def _card(cases):
    # scorecard の必要部分だけを持つ最小 dict（cases: [{case_id, classification:{candidate,confirmed}}]）
    return {"cases": cases}


def _case(case_id, candidate=None, confirmed=None):
    return {
        "case_id": case_id,
        "classification": {"candidate": candidate, "confirmed": confirmed},
    }


def test_new_and_removed_cases():
    current = _card([_case("a", "tp"), _case("b", "tp")])
    baseline = _card([_case("a", "tp"), _case("c", "tp")])
    diff = compute_baseline_diff(current, baseline)
    assert diff["new"] == ["b"]
    assert diff["removed"] == ["c"]
    assert diff["regressed"] == [] and diff["improved"] == []


def test_regressed_detects_tp_to_fn_and_tn_to_fp():
    baseline = _card([_case("v", "tp"), _case("s", "tn")])
    current = _card([_case("v", "fn"), _case("s", "fp")])  # 取りこぼし・誤検知に悪化
    diff = compute_baseline_diff(current, baseline)
    assert diff["regressed"] == ["s", "v"]
    assert diff["improved"] == []


def test_improved_detects_fn_to_tp_and_fp_to_tn():
    baseline = _card([_case("v", "fn"), _case("s", "fp")])
    current = _card([_case("v", "tp"), _case("s", "tn")])
    diff = compute_baseline_diff(current, baseline)
    assert diff["improved"] == ["s", "v"]
    assert diff["regressed"] == []


def test_measurement_dropout_is_not_a_regression():
    # baseline は TP、current は未完了（分類 None）＝measurement 欠落。精度回帰に数えない。
    baseline = _card([_case("v", "tp")])
    current = _card([_case("v", None)])
    diff = compute_baseline_diff(current, baseline)
    assert diff["regressed"] == [] and diff["improved"] == []


def test_confirmed_tier_compared_independently():
    baseline = _card([_case("v", candidate="tp", confirmed="tp")])
    current = _card([_case("v", candidate="tp", confirmed="fn")])  # confirmed だけ悪化
    assert compute_baseline_diff(current, baseline, tier="candidate")["regressed"] == []
    assert compute_baseline_diff(current, baseline, tier="confirmed")["regressed"] == ["v"]


def test_invalid_tier_rejected():
    with pytest.raises(ValueError):
        compute_baseline_diff(_card([]), _card([]), tier="bogus")


def test_empty_scorecards_have_empty_diff():
    diff = compute_baseline_diff({}, {})
    assert diff == {"new": [], "removed": [], "regressed": [], "improved": []}
