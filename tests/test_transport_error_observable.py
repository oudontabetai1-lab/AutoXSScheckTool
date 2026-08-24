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
