"""学習済み payload 成功率のプロンプト整形（format_learning_for_prompt）を検証する。

本番は finding を出した payload のみ success=True で記録する（engine `_record_finding`）ため、
本関数は「過去に効いた払い」の要約に徹する。呼び出し側は stats(domain=None)（global 集計）を
渡す前提（domain 付きは二重計上になる）。
"""

from wscan.payload_learning import PayloadLearner, format_learning_for_prompt


def test_empty_rows_returns_empty():
    assert format_learning_for_prompt([]) == ""


def test_rows_below_min_tries_return_empty():
    # 1 回きり（tries<min_tries）はノイズとして除外 → 空文字。
    rows = [
        {"payload": "worked-once", "hits": 1, "tries": 1, "rate": 1.0},
    ]
    assert format_learning_for_prompt(rows) == ""


def test_effective_rows_show_success_counts_sorted_by_rate():
    rows = [
        {"payload": "high", "hits": 3, "tries": 5, "rate": 0.6},
        {"payload": "higher", "hits": 4, "tries": 5, "rate": 0.8},
    ]
    block = format_learning_for_prompt(rows)

    assert "LEARNED payloads that produced findings" in block
    assert "- `high` -> 3/5 succeeded" in block
    assert "- `higher` -> 4/5 succeeded" in block
    # rate 降順: higher(0.8) が high(0.6) より前
    assert block.index("`higher`") < block.index("`high`")


def test_low_rate_rows_are_excluded():
    # rate<0.5 は effective 群に入らない（失敗記録が入る将来のみ現れる想定）。
    rows = [
        {"payload": "weak", "hits": 1, "tries": 12, "rate": 0.08},
    ]
    assert format_learning_for_prompt(rows) == ""


def test_success_count_limit_is_applied():
    rows = [
        {"payload": f"effective-{i}", "hits": 2, "tries": 2, "rate": 1.0}
        for i in range(6)
    ]
    block = format_learning_for_prompt(rows, max_success=2)
    assert block.count(" succeeded") == 2


def test_long_payload_is_truncated_to_max_length():
    payload = "abcdefghijklmno"
    rows = [{"payload": payload, "hits": 2, "tries": 2, "rate": 1.0}]

    block = format_learning_for_prompt(rows, max_payload_len=10)
    assert "`abcdefg...`" in block
    assert payload not in block


def test_non_dict_and_missing_payload_rows_are_skipped():
    rows = [
        "not-a-dict",
        {"hits": 2, "tries": 2, "rate": 1.0},          # payload 欠落
        {"payload": "", "hits": 2, "tries": 2, "rate": 1.0},  # 空 payload
        {"payload": "good", "hits": 2, "tries": 2, "rate": 1.0},
    ]
    block = format_learning_for_prompt(rows)
    assert "- `good` -> 2/2 succeeded" in block
    assert block.count(" succeeded") == 1


def test_roundtrip_success_only_recording_is_not_double_counted(tmp_path):
    """本番相当（success のみ・global 集計）で 1 回の成功が 1/1 として出ることを保証。

    domain 付きで stats を取ると 2/2 に二重計上されるため、呼び出し側は domain=None を使う。
    ここではその前提（global 集計は二重計上しない）を固定する。
    """
    lf = tmp_path / "learn.json"
    learner = PayloadLearner(learning_file=str(lf))
    # 本番の唯一経路と同じく success=True・domain 付きで 2 回記録。
    learner.record("xss", "<svg onload=x>", success=True, domain="target.test")
    learner.record("xss", "<svg onload=x>", success=True, domain="target.test")

    rows_global = learner.stats("xss", domain=None)
    block = format_learning_for_prompt(rows_global)
    # global 集計は 2 回の成功をそのまま 2/2 として表す（二重計上なし）。
    assert "- `<svg onload=x>` -> 2/2 succeeded" in block

    # domain 付きだと global+domain を加算し 4/4 に膨れる（＝呼び出し側が使ってはいけない形）。
    rows_domain = learner.stats("xss", domain="target.test")
    row = next(r for r in rows_domain if r["payload"] == "<svg onload=x>")
    assert row["tries"] == 4
