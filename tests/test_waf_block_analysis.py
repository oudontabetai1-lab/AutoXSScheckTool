"""G6: WAF passed/blocked フィードバック整形（純関数）の回帰テスト。

生きた WAF バイパス経路は adaptive。試行台帳の per-payload status から passed/blocked を
分けて adaptive プロンプトへ供給し、狙いを絞らせる。判定はせず観測の整形のみ。
"""
from types import SimpleNamespace

from wscan.waf_detector import (
    format_waf_block_analysis,
    is_waf_block_attempt,
)


def _e(payload, status=None, error=False):
    return SimpleNamespace(payload=payload, status=status, error=error)


def test_is_waf_block_attempt():
    assert is_waf_block_attempt(403) is True
    assert is_waf_block_attempt(406) is True
    assert is_waf_block_attempt(500) is True
    assert is_waf_block_attempt(None, error=True) is True
    assert is_waf_block_attempt(200) is False
    assert is_waf_block_attempt(302) is False
    assert is_waf_block_attempt(None) is False


def test_partitions_passed_and_blocked_with_status():
    entries = [
        _e("<script>alert(1)</script>", 403),
        _e("<svg onload=alert(1)>", 200),
        _e("<img src=x onerror=alert(1)>", None, error=True),
        _e("<sVg OnLoad=alert(1)>", 200),
    ]
    out = format_waf_block_analysis(entries, "Cloudflare")
    assert "WAF (Cloudflare) response analysis" in out
    assert "BLOCKED" in out and "PASSED" in out
    assert "<script>alert(1)</script>  -> 403" in out
    assert "-> no response" in out           # transport 失敗
    assert "<svg onload=alert(1)>" in out     # passed


def test_dedup_and_bounds():
    entries = [_e(f"p{i}", 403) for i in range(20)]
    out = format_waf_block_analysis(entries, "AWS WAF", max_each=3)
    # blocked は max_each=3 まで
    assert out.count("-> 403") == 3


def test_empty_when_no_waf_or_no_signal():
    assert format_waf_block_analysis([_e("x", 200)], "") == ""     # WAF 未検出
    assert format_waf_block_analysis([], "Cloudflare") == ""       # 履歴なし
    # status 不明のみ（passed/blocked の信号なし）
    assert format_waf_block_analysis([_e("x", None)], "Cloudflare") == ""


if __name__ == "__main__":
    import unittest
    unittest.main()
