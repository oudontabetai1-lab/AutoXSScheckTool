"""F04: デシリアライズ検査の誤確証（反射≠実行）を防ぐ回帰テスト。

単なる入力反射ページ（vuln_app /search 相当）を critical・reproduced な
deserialization として誤確証していた問題を、
(1) error パターンから PHP 構造マーカー `O:\\d+:"...` を除外、
(2) 反射 payload を照合前に除去、の2点で修正したことを検証する。
"""
import re

from wscan.scanners.deserialization import (
    _DESER_ERROR_PATTERNS,
    _PROBES,
    _strip_reflected_payload,
)


def _matches(body: str) -> str | None:
    """base.check_response_for_patterns と同じ照合セマンティクスを再現する。"""
    for pattern in _DESER_ERROR_PATTERNS:
        m = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
        if m:
            return m.group(0)
    return None


def _php_malformed_payload() -> str:
    for probe_id, _desc, payload, _ct in _PROBES:
        if probe_id == "php_serialize_malformed":
            return payload
    raise AssertionError("php_serialize_malformed probe が見つからない")


def test_reflected_php_payload_is_not_confirmed():
    """反射のみのページ（payloadをそのままエコー）は誤確証しない。"""
    payload = _php_malformed_payload()
    reflected = f"<html><body>Search result: {payload}</body></html>"
    # (a) 構造マーカー除外により、strip 前でも error パターンに一致しない。
    assert _matches(reflected) is None
    # (b) 反射除去後も当然一致しない。
    assert _matches(_strip_reflected_payload(reflected, payload)) is None


def test_structure_marker_removed_from_patterns():
    """`O:\\d+:"...` 構造マーカーが error パターンから除外されている。"""
    assert not any("O:" in p and r"\d" in p for p in _DESER_ERROR_PATTERNS)


def test_real_unserialize_error_still_detected():
    """実際の PHP unserialize エラー文言は引き続き検出する（検出力維持）。"""
    payload = _php_malformed_payload()
    real_error = (
        "<b>Warning</b>: unserialize(): Error at offset 0 of 33 bytes "
        "in /var/www/app.php on line 12"
    )
    # 反射除去は payload 文字列だけを消すので、アプリ生成のエラー文言は残る。
    assert _matches(_strip_reflected_payload(real_error, payload)) is not None


def test_strip_reflected_payload_helper():
    assert _strip_reflected_payload("", "x") == ""
    assert _strip_reflected_payload("abc", "") == "abc"
    assert "PAYLOAD" not in _strip_reflected_payload("aPAYLOADbPAYLOADc", "PAYLOAD")
