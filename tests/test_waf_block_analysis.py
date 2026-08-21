"""G6: WAF passed/blocked フィードバック整形（純関数）の回帰テスト。

WAF 固有の signal（403/406）だけを blocked とし、汎用アプリエラー（400/401/404/422/500）や
transport 失敗はアプリ到達の可能性があるため unknown 扱い（回避させない）。
"""
from types import SimpleNamespace

from wscan.waf_detector import (
    format_waf_block_analysis,
    is_waf_block_attempt,
)


def _e(payload, status=None, error=False):
    return SimpleNamespace(payload=payload, status=status, error=error)


def test_is_waf_block_only_waf_specific_statuses():
    assert is_waf_block_attempt(403) is True
    assert is_waf_block_attempt(406) is True
    # 汎用アプリエラーはブロックにしない（アプリに到達した可能性）
    for s in (400, 401, 404, 422, 500, 502, 200, 302, None):
        assert is_waf_block_attempt(s) is False
    # transport 失敗も WAF ブロックとはみなさない
    assert is_waf_block_attempt(None, error=True) is False


def test_partitions_passed_and_blocked():
    entries = [
        _e("<script>alert(1)</script>", 403),
        _e("<svg onload=alert(1)>", 200),
        _e("bad-input", 400),               # アプリエラー → どちらにも入れない
        _e("<img src=x onerror=alert(1)>", None, error=True),  # transport 失敗 → unknown
        _e("<sVg OnLoad=alert(1)>", 200),
    ]
    out = format_waf_block_analysis(entries, "Cloudflare")
    assert "WAF (Cloudflare) response analysis" in out
    assert "BLOCKED by the WAF (HTTP 403/406)" in out
    assert "<script>alert(1)</script>  -> 403" in out
    assert "<svg onload=alert(1)>" in out       # passed
    assert "bad-input" not in out               # app error は含めない
    assert "no response" not in out             # transport 失敗は含めない


def test_dedup_and_bounds():
    entries = [_e(f"p{i}", 403) for i in range(20)]
    out = format_waf_block_analysis(entries, "AWS WAF", max_each=3)
    assert out.count("-> 403") == 3


def test_empty_conditions():
    assert format_waf_block_analysis([_e("x", 403)], "") == ""       # WAF 未検出
    assert format_waf_block_analysis([], "Cloudflare") == ""         # 履歴なし
    # 403/406 も 2xx も無い（app エラーのみ）→ 信号なし
    assert format_waf_block_analysis([_e("x", 404), _e("y", 500)], "Cloudflare") == ""


if __name__ == "__main__":
    import unittest
    unittest.main()
