"""G6: WAF passed/blocked フィードバック整形（純関数）の回帰テスト。

- blocked: WAF 固有 signal（403/406）のみ。汎用エラー/transport 失敗は unknown。
- passed: 2xx **かつ reflected**（payload が本文に現れた＝アプリが処理した確証）のみ。
  2xx だけでは WAF のソフトブロック/CAPTCHA/challenge を誤って passed にし得るため。
- 同一 payload は最新の試行結果に集約（403 と 2xx が混在しても両リストに載せない）。
"""
from types import SimpleNamespace

from wscan.waf_detector import (
    format_waf_block_analysis,
    is_waf_block_attempt,
)


def _e(payload, status=None, error=False, reflected=False):
    return SimpleNamespace(payload=payload, status=status, error=error, reflected=reflected)


def test_is_waf_block_only_waf_specific_statuses():
    assert is_waf_block_attempt(403) is True
    assert is_waf_block_attempt(406) is True
    for s in (400, 401, 404, 422, 500, 502, 200, 302, None):
        assert is_waf_block_attempt(s) is False
    assert is_waf_block_attempt(None, error=True) is False


def test_passed_requires_reflection():
    # 2xx でも reflected でなければ passed にしない（challenge/soft-block の可能性）。
    out_no_refl = format_waf_block_analysis([_e("<svg onload=x>", 200, reflected=False)], "Cloudflare")
    assert out_no_refl == ""
    out_refl = format_waf_block_analysis([_e("<svg onload=x>", 200, reflected=True)], "Cloudflare")
    assert "PASSED" in out_refl and "<svg onload=x>" in out_refl


def test_partitions_and_excludes_generic_errors():
    entries = [
        _e("<script>alert(1)</script>", 403),
        _e("<svg onload=alert(1)>", 200, reflected=True),
        _e("bad-input", 400),                    # app error → 除外
        _e("<img src=x onerror=alert(1)>", None, error=True),  # transport → 除外
    ]
    out = format_waf_block_analysis(entries, "Cloudflare")
    assert "<script>alert(1)</script>  -> 403" in out
    assert "<svg onload=alert(1)>" in out
    assert "bad-input" not in out
    assert "no response" not in out


def test_same_payload_consolidated_to_latest():
    # 同一 payload が 403 → 200(reflected) の順。最新=passed に確定し、両リストに載らない。
    entries = [_e("p", 403), _e("p", 200, reflected=True)]
    out = format_waf_block_analysis(entries, "AWS WAF")
    assert "PASSED" in out
    assert "-> 403" not in out          # 最新は 200 なので blocked に載らない
    # 逆順（最新=403）なら blocked のみ
    out2 = format_waf_block_analysis([_e("p", 200, reflected=True), _e("p", 403)], "AWS WAF")
    assert "-> 403" in out2
    assert "Payloads that PASSED" not in out2


def test_dedup_and_bounds():
    entries = [_e(f"p{i}", 403) for i in range(20)]
    out = format_waf_block_analysis(entries, "AWS WAF", max_each=3)
    assert out.count("-> 403") == 3


def test_empty_conditions():
    assert format_waf_block_analysis([_e("x", 403)], "") == ""
    assert format_waf_block_analysis([], "Cloudflare") == ""
    assert format_waf_block_analysis([_e("x", 404), _e("y", 500)], "Cloudflare") == ""


if __name__ == "__main__":
    import unittest
    unittest.main()
