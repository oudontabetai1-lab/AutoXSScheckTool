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


class _SilentSwallowBrowser:
    """実 fill_and_submit_form のように例外を内部で握りつぶし空 pair を返す（raise しない）。

    送達失敗は last_probe_delivered=False で残す（_apply_ip がこれを見て transport_error を刻む）。
    """
    def __init__(self):
        self.last_probe_delivered = True

    async def fill_and_submit_form(self, *a, **k):
        self.last_probe_delivered = False
        return "", {}


class _SwallowEngine:
    def __init__(self):
        self.browser = _SilentSwallowBrowser()
        self.monitor = None
        self.payload_gen = None
        self.wave_errors: list = []
        self.state_profile = "unrestricted"
        self.attempt_ledger = None


class _FormScanner:
    """_apply_ip を通す最小 form scanner（BaseScanner 継承・_apply_payload は fill_and_submit_form）。"""
    pass


class SilentSwallowObservableTests(unittest.IsolatedAsyncioTestCase):
    """fill_and_submit_form の **沈黙 swallow**（空 pair・例外なし）でも送達失敗を
    transport_error として observability に残す（Codex #134 P1）。従来の
    test_apply_payload_records_transport_error は browser が *raise* する経路のみをカバーし、
    実 browser の内部 swallow は素通りしていた。
    """

    async def test_apply_ip_records_transport_error_on_silent_swallow(self):
        from wscan.scanners.base import BaseScanner
        from wscan.injection_point import InjectionPoint

        class Scanner(BaseScanner):
            CHECK_TYPE = "xss"
            ALWAYS_STATE_CHANGING = False

            async def scan_field(self, *a, **k):
                return []

            async def _apply_payload(self, url, form_index, field_name, payload, is_url_param):
                return await self.browser.fill_and_submit_form(form_index, field_name, payload)

        engine = _SwallowEngine()
        scanner = Scanner(engine)
        ip = InjectionPoint.for_form("http://x/", "q", form_index=0, method="GET")

        source, pair = await scanner._apply_ip(ip, "payload")

        # 制御フローは不変（空 pair をそのまま返す）。
        self.assertEqual((source, pair), ("", {}))
        # 送達失敗が transport_error として記録される。
        self.assertTrue(
            any(e.startswith("transport_error:xss:") for e in engine.wave_errors),
            f"silent swallow not recorded: {engine.wave_errors}",
        )

    async def test_delivered_probe_records_no_transport_error(self):
        """送達成功（last_probe_delivered=True）では偽の transport_error を刻まない（FP 非増加）。"""
        from wscan.scanners.base import BaseScanner
        from wscan.injection_point import InjectionPoint

        class DeliveredBrowser:
            def __init__(self):
                self.last_probe_delivered = True

            async def fill_and_submit_form(self, *a, **k):
                self.last_probe_delivered = True
                return "src", {}  # pair 未捕捉でも submit は成功（delivered=True）

        class Scanner(BaseScanner):
            CHECK_TYPE = "xss"
            ALWAYS_STATE_CHANGING = False

            async def scan_field(self, *a, **k):
                return []

            async def _apply_payload(self, url, form_index, field_name, payload, is_url_param):
                return await self.browser.fill_and_submit_form(form_index, field_name, payload)

        engine = _SwallowEngine()
        engine.browser = DeliveredBrowser()
        scanner = Scanner(engine)
        ip = InjectionPoint.for_form("http://x/", "q", form_index=0, method="GET")

        await scanner._apply_ip(ip, "payload")
        self.assertEqual(engine.wave_errors, [])  # 偽記録なし


class _NullNetwork:
    def clear(self):
        pass

    def latest_for_url(self, *a, **k):
        return None

    def best_pair_for_page(self, *a, **k):
        return None

    def latest(self):
        return None


class _FakeSubmitBtn:
    async def click(self):
        pass


class _FakeFormPage:
    """実 fill_and_submit_form を駆動する fake page。evaluate 結果と post-submit 例外を制御。"""

    def __init__(self, *, result, wait_raises=False):
        self._result = result
        self._wait_raises = wait_raises

    async def evaluate(self, *a, **k):
        # 1 回目=fill JS（result を返す）。submit 経路（btn 無し）では 2 回目に submit JS が
        # 呼ばれるが、テストは submit_btn を返すので基本 1 回。
        return self._result

    async def query_selector(self, *a, **k):
        return _FakeSubmitBtn()

    async def wait_for_load_state(self, *a, **k):
        if self._wait_raises:
            raise RuntimeError("post-submit wait boom (slow/streaming)")


class _FakeFormBrowser:
    """実 BrowserManager.fill_and_submit_form を駆動する最小 fake。"""

    def __init__(self, *, result, nav_status=200, wait_raises=False, prior_delivered=None):
        self.page = _FakeFormPage(result=result, wait_raises=wait_raises)
        self.network = _NullNetwork()
        self.timeout = 5
        self.sleep_factor = 0.0
        self.auth_user = ""
        self.auth_pass = ""
        self.last_navigation_status = nav_status
        # 直前 probe が残した値（stale が漏れないことの検証用）。
        self.last_probe_delivered = True if prior_delivered is None else prior_delivered

    def reset_dialog(self):
        pass

    async def get_page_source(self):
        return "<html></html>"


class FormDeliveryFlagTests(unittest.IsolatedAsyncioTestCase):
    """fill_and_submit_form の送達フラグ（Codex #137 P1/P2）。

    P1: フォーム不在は直前 navigate が応答を得ていれば speculative（True）、応答なし
        （status None＝失敗ロード）なら未送達（False）。
    P2: submit dispatch 後の wait/get_source 例外は送達済みを維持（True）。dispatch 前の
        例外のみ未送達（False）。
    """

    async def _run(self, **kw):
        from wscan.browser import BrowserManager

        fake = _FakeFormBrowser(**kw)
        await BrowserManager.fill_and_submit_form(fake, 0, "q", "payload")
        return fake.last_probe_delivered

    async def test_success_marks_delivered(self):
        self.assertTrue(await self._run(result={"success": True, "action": "http://x/"}))

    async def test_form_absent_after_loaded_page_is_speculative_delivered(self):
        # ページは正常ロード（status 200）だが form 不在＝speculative probe＝送達成功扱い。
        self.assertTrue(
            await self._run(result={"success": False, "error": "form not found"}, nav_status=200)
        )

    async def test_form_absent_after_failed_load_is_undelivered(self):
        # 直前 navigate が応答なし（status None＝失敗ロード）→ stale ページの form 不在＝未送達。
        self.assertFalse(
            await self._run(result={"success": False, "error": "form not found"}, nav_status=None)
        )

    async def test_post_dispatch_exception_keeps_delivered(self):
        # submit 済みで wait_for_load_state が例外（slow/streaming）→ 送達済みを維持。
        self.assertTrue(
            await self._run(result={"success": True, "action": "http://x/"}, wait_raises=True)
        )

    async def test_form_absent_does_not_leak_prior_true(self):
        # 失敗ロードの form 不在は、直前 probe が True でも False にする（stale を漏らさない）。
        self.assertFalse(
            await self._run(
                result={"success": False}, nav_status=None, prior_delivered=True
            )
        )


class _FakeUrlParamBrowser:
    """実 BrowserManager.test_url_param を駆動する最小 fake（navigate をスタブ）。"""

    def __init__(self, *, nav_ok: bool, nav_status):
        self._nav_ok = nav_ok
        self._nav_status = nav_status
        self.last_navigation_status = None
        self.last_probe_delivered = True
        self.sleep_factor = 0.0
        self.network = _NullNetwork()

    def reset_dialog(self):
        pass

    async def navigate(self, *a, **k):
        # 実 navigate と同契約: 応答があれば status を残し、例外/応答なしのみ None。
        self.last_navigation_status = self._nav_status
        return self._nav_ok

    async def get_page_source(self):
        return ""


class UrlParamDeliveryFlagTests(unittest.IsolatedAsyncioTestCase):
    """`test_url_param` は送達フラグを常に True にリセットする（url param は本フラグで観測しない）。

    送達フラグは form 経路（fill_and_submit_form）の沈黙 swallow 観測専用（#134 の対象）。URL param
    経路は navigate 結果から未送達を導かない: ssti/open_redirect 等は payload 次第で goto が正常に
    例外/応答なしになり（payload 単位の通常挙動）、これを未送達として刻むと check 粒度の
    degraded_checks が当該 check の tested を全除外し無関係な url_param safe twin まで NOT_REACHED 化して
    benchmark を壊す（実測で確認）。リセットで直前 form probe の False が漏れる stale も防ぐ。
    """

    async def _run(self, *, nav_ok, nav_status, prior=False):
        from wscan.browser import BrowserManager

        fake = _FakeUrlParamBrowser(nav_ok=nav_ok, nav_status=nav_status)
        fake.last_probe_delivered = prior  # 直前 probe が残した値
        await BrowserManager.test_url_param(fake, "http://x/products", "category", "'")
        return fake.last_probe_delivered

    async def test_delivered_true_on_success(self):
        self.assertTrue(await self._run(nav_ok=True, nav_status=200))

    async def test_delivered_true_even_on_error_response(self):
        self.assertTrue(await self._run(nav_ok=False, nav_status=500))

    async def test_delivered_true_even_on_navigation_failure(self):
        # payload 単位の goto 例外/応答なしでも url param は未送達扱いにしない（check 巻き添え防止）。
        self.assertTrue(await self._run(nav_ok=False, nav_status=None))

    async def test_resets_stale_false_from_prior_form_probe(self):
        # 直前 form probe が残した False を url probe に漏らさない。
        self.assertTrue(await self._run(nav_ok=True, nav_status=200, prior=False))


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
