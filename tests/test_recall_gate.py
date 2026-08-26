"""recall_gate 純粋ロジックのユニットテスト（0015 PRINCIPLE-001 / ADR-0016）。

ブラウザ非依存。見逃し0（recall 100%）ゲートの合否・分母の数え方・target_check 絞り込みを固定。
"""
from wscan.recall_gate import compute_recall, spec_key, RecallReport


def _spec(check, path, field="q", note="planted"):
    return {"check": check, "path": path, "field": field, "note": note}


def test_full_recall_all_matched():
    expected = [_spec("xss", "/a"), _spec("sqli", "/b")]
    reported = [("xss", "/a", "q"), ("sqli", "/b", "q")]
    r = compute_recall(expected, reported)
    assert r.recall == 1.0
    assert r.is_complete
    assert r.missed == ()


def test_false_negative_lowers_recall_and_lists_miss():
    expected = [_spec("xss", "/a"), _spec("sqli", "/b", note="blind")]
    reported = [("xss", "/a", "q")]  # /b sqli 未検出
    r = compute_recall(expected, reported)
    assert r.matched_total == 1 and r.expected_total == 2
    assert r.recall == 0.5
    assert not r.is_complete
    assert len(r.missed) == 1 and r.missed[0]["path"] == "/b"
    assert "blind" in r.describe()  # note がゲートメッセージに出る


def test_empty_expected_is_vacuously_complete():
    r = compute_recall([], [("xss", "/a", "q")])
    assert r.recall == 1.0 and r.is_complete
    assert r.expected_total == 0


def test_target_checks_filters_denominator():
    # sqli を無効化したスキャンで、sqli spec の未検出を見逃し扱いしない
    expected = [_spec("xss", "/a"), _spec("sqli", "/b")]
    reported = [("xss", "/a", "q")]
    r = compute_recall(expected, reported, target_checks=["xss"])
    assert r.expected_total == 1 and r.is_complete
    assert "sqli" not in r.by_check


def test_duplicate_keys_counted_once():
    expected = [_spec("xss", "/a", note="n1"), _spec("xss", "/a", note="n2")]
    r = compute_recall(expected, [])
    assert r.expected_total == 1  # 同一キーは分母1回


def test_extra_reported_keys_ignored_for_recall():
    # expected 外の報告（precision の話）は recall に無関係
    expected = [_spec("xss", "/a")]
    reported = [("xss", "/a", "q"), ("os", "/z", "cmd")]
    r = compute_recall(expected, reported)
    assert r.recall == 1.0


def test_by_check_breakdown():
    expected = [_spec("xss", "/a"), _spec("xss", "/b"), _spec("sqli", "/c")]
    reported = [("xss", "/a", "q")]
    r = compute_recall(expected, reported)
    assert r.by_check["xss"] == (1, 2)
    assert r.by_check["sqli"] == (0, 1)


def test_spec_key_normalizes_missing_fields():
    assert spec_key({"check": "xss", "path": "/a"}) == ("xss", "/a", "")


def test_report_is_frozen_dataclass():
    r = compute_recall([_spec("xss", "/a")], [("xss", "/a", "q")])
    assert isinstance(r, RecallReport)
    try:
        r.matched_total = 0  # frozen
        assert False, "should be immutable"
    except Exception:
        pass
