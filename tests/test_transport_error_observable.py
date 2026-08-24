"""注入系スキャナの `_apply_payload` transport 失敗が *観測可能* であることの回帰テスト。

`_apply_payload` は browser のナビゲーション/送信失敗を握りつぶして ``("", {})`` を返す
（ループ挙動は不変＝偽陽性を作らない設計）。だが失敗を記録しないと
``engine.observability_summary()`` が ``total: 0`` と報告し、SQLi/OS の全攻撃要求が
落ちても「完全なスキャン」と誤表示してしまう（Codex #101 P1）。修正後は XSS と同様に
``transport_error:<check>`` を ``wave_errors`` へ記録する（挙動は不変）。
"""
import unittest

import pytest

from wscan.scanners import SCANNERS


class _BoomBrowser:
    """全メソッドが例外を投げる最小ブラウザ。"""
    async def test_url_param(self, *a, **k):
        raise RuntimeError("navigation boom")

    async def navigate(self, *a, **k):
        raise RuntimeError("navigation boom")

    async def fill_and_submit_form(self, *a, **k):
        raise RuntimeError("submit boom")


class _FakeEngine:
    def __init__(self):
        self.browser = _BoomBrowser()
        self.monitor = None
        self.payload_gen = None
        self.wave_errors: list = []


# 既定 (sqli/os) を含め、`_apply_payload` が transport を握りつぶす注入系スキャナ。
_SWALLOWING = [
    "sqli", "os", "header_injection", "open_redirect",
    "path_traversal", "ssti", "ssrf", "mail_header",
]


class TransportErrorObservableTests(unittest.IsolatedAsyncioTestCase):
    async def test_apply_payload_records_transport_error(self):
        for check in _SWALLOWING:
            cls = SCANNERS[check]
            engine = _FakeEngine()
            scanner = cls(engine)
            with self.subTest(check=check):
                # URL パラメータ経路（test_url_param が boom）。
                source, pair = await scanner._apply_payload(
                    "http://x/", 0, "q", "payload", True
                )
                self.assertEqual((source, pair), ("", {}))
                ct = getattr(scanner, "CHECK_TYPE", check)
                self.assertTrue(
                    any(e.startswith(f"transport_error:{ct}:") for e in engine.wave_errors),
                    f"{check}: transport_error not recorded: {engine.wave_errors}",
                )


if __name__ == "__main__":
    unittest.main()


class _XmlBoomBrowser:
    async def test_url_param(self, *a, **k):
        raise RuntimeError("nav boom")

    async def navigate(self, *a, **k):
        raise RuntimeError("nav boom")

    async def fill_and_submit_form(self, *a, **k):
        raise RuntimeError("submit boom")


class _XxeFakeEngine:
    def __init__(self):
        self.browser = _XmlBoomBrowser()
        self.monitor = None
        self.payload_gen = None
        self.wave_errors: list = []
        self.timeout = 5


class XxeTransportObservableTests(unittest.IsolatedAsyncioTestCase):
    """XXE は独自の direct-HTTP 経路（_post_xml）を持つ。baseline/attack 失敗を
    握りつぶすと --checks xxe が丸ごと落ちても total:0 と誤表示する（Codex #101 P1）。
    _post_xml を失敗させ、baseline 失敗が transport_error として記録されることを検証。
    """

    async def test_baseline_failure_is_recorded(self):
        from unittest.mock import patch
        from wscan.scanners import SCANNERS

        engine = _XxeFakeEngine()
        scanner = SCANNERS["xxe"](engine)
        field = {"name": "data", "content_type": "application/xml"}

        async def _boom(*a, **k):
            raise RuntimeError("post boom")

        with patch.object(scanner, "_post_xml", _boom), \
             patch("wscan.scanners.xxe._looks_like_xml_endpoint", return_value=True):
            out = await scanner.scan_field("http://x/api", 0, field, False)

        self.assertEqual(out, [])
        self.assertTrue(
            any(e.startswith("transport_error:xxe:") for e in engine.wave_errors),
            f"xxe transport_error not recorded: {engine.wave_errors}",
        )
