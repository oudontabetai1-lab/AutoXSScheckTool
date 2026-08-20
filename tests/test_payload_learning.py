"""学習済み payload 成功率のプロンプト整形を検証する。"""

from wscan.payload_learning import format_learning_for_prompt


def test_empty_rows_returns_empty():
    assert format_learning_for_prompt([]) == ""


def test_rows_below_min_tries_return_empty():
    rows = [
        {"payload": "worked-once", "hits": 1, "tries": 1, "rate": 1.0},
        {"payload": "failed-once", "hits": 0, "tries": 1, "rate": 0.0},
    ]

    assert format_learning_for_prompt(rows) == ""


def test_effective_rows_show_success_counts():
    rows = [
        {"payload": "high", "hits": 3, "tries": 5, "rate": 0.6},
        {"payload": "higher", "hits": 4, "tries": 5, "rate": 0.8},
    ]

    block = format_learning_for_prompt(rows)

    assert "EFFECTIVE (worked before):" in block
    assert "- `high` -> 3/5 succeeded" in block
    assert block.index("`higher`") < block.index("`high`")


def test_blocked_rows_are_sorted_by_tries_descending():
    rows = [
        {"payload": "few", "hits": 0, "tries": 3, "rate": 0.0},
        {"payload": "many", "hits": 1, "tries": 12, "rate": 0.08},
    ]

    block = format_learning_for_prompt(rows)

    assert "CONSISTENTLY BLOCKED/INEFFECTIVE:" in block
    assert "- `many` -> 1/12 (blocked/ineffective)" in block
    assert block.index("`many`") < block.index("`few`")


def test_effective_payload_is_not_repeated_in_blocked_rows():
    rows = [
        {"payload": "same", "hits": 2, "tries": 2, "rate": 1.0},
        {"payload": "same", "hits": 0, "tries": 10, "rate": 0.0},
    ]

    block = format_learning_for_prompt(rows)

    assert block.count("`same`") == 1
    assert "CONSISTENTLY BLOCKED/INEFFECTIVE:" not in block


def test_group_item_limits_are_applied():
    rows = [
        {"payload": f"effective-{i}", "hits": 2, "tries": 2, "rate": 1.0}
        for i in range(4)
    ] + [
        {"payload": f"blocked-{i}", "hits": 0, "tries": i + 2, "rate": 0.0}
        for i in range(4)
    ]

    block = format_learning_for_prompt(rows, max_success=2, max_fail=1)

    assert block.count(" succeeded") == 2
    assert block.count(" (blocked/ineffective)") == 1


def test_long_payload_is_truncated_to_max_length():
    payload = "abcdefghijklmno"
    rows = [{"payload": payload, "hits": 2, "tries": 2, "rate": 1.0}]

    block = format_learning_for_prompt(rows, max_payload_len=10)

    assert "`abcdefg...`" in block
    assert payload not in block
