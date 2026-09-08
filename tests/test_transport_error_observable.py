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
from wscan.scanners.base import PageDocumentUnavailable


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
    def __init__(self, base_count=0):
        # base_count＝clear() 後に残る fill 由来 XHR/背景 polling のノイズ。
        self.count = base_count

    def clear(self):
        pass

    def latest_for_url(self, *a, **k):
        return None

    def best_pair_for_page(self, *a, **k):
        return None

    def latest(self):
        return None

    def request_count(self):
        return self.count


class _FakeSubmitBtn:
    def __init__(self, network, *, sends=True, raises=False):
        self._network = network
        self._sends = sends
        self._raises = raises

    async def click(self):
        if self._sends:
            # submit がリクエストを送る＝network カウントが増える。
            self._network.count += 1
        if self._raises:
            # click() が post-dispatch の navigation 待ちで raise する状況を模す。
            raise RuntimeError("navigation interrupted after request sent")


class _FakeFormPage:
    """実 fill_and_submit_form を駆動する fake page。evaluate 結果と各種例外を制御。"""

    def __init__(self, *, network, result, wait_raises=False, click_raises=False,
                 submit_sends=True):
        self._network = network
        self._result = result
        self._wait_raises = wait_raises
        self._click_raises = click_raises
        self._submit_sends = submit_sends

    async def evaluate(self, *a, **k):
        # 1 回目=fill JS（result を返す）。submit 経路（btn 無し）では 2 回目に submit JS が
        # 呼ばれるが、テストは submit_btn を返すので基本 1 回。
        return self._result

    async def query_selector(self, *a, **k):
        return _FakeSubmitBtn(
            self._network, sends=self._submit_sends, raises=self._click_raises
        )

    async def wait_for_load_state(self, *a, **k):
        if self._wait_raises:
            raise RuntimeError("post-submit wait boom (slow/streaming)")


class _FakeFormBrowser:
    """実 BrowserManager.fill_and_submit_form を駆動する最小 fake。"""

    def __init__(self, *, result, nav_status=200, wait_raises=False, click_raises=False,
                 submit_sends=True, net_base=0, prior_delivered=None):
        self.network = _NullNetwork(base_count=net_base)
        self.page = _FakeFormPage(
            network=self.network, result=result, wait_raises=wait_raises,
            click_raises=click_raises, submit_sends=submit_sends,
        )
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
        # submit を dispatch できたら送達成功（dispatch 点で確定）。
        self.assertTrue(
            await self._run(result={"success": True, "action": "http://x/"}, submit_sends=True)
        )

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

    async def test_click_raises_but_request_sent_is_delivered(self):
        # click() が post-dispatch の navigation 待ちで raise しても、submit がリクエストを
        # 送っていれば（差分 +1）送達成功（Codex #137 P2）。
        self.assertTrue(
            await self._run(
                result={"success": True, "action": "http://x/"},
                click_raises=True, submit_sends=True,
            )
        )

    async def test_click_raises_without_request_is_undelivered(self):
        # click() が raise し submit がリクエストを送っていない（差分 0）＝未送達。
        self.assertFalse(
            await self._run(
                result={"success": True, "action": "http://x/"},
                click_raises=True, submit_sends=False,
            )
        )

    async def test_prior_noise_not_mistaken_for_submission(self):
        # fill 由来 XHR/背景 polling が clear() 後に残っていても（net_base=3）、submit が
        # リクエストを送らず raise した場合は差分 0＝未送達。ノイズを submit と取り違えない
        # （Codex #137 P2 再々指摘）。
        self.assertFalse(
            await self._run(
                result={"success": True, "action": "http://x/"},
                click_raises=True, submit_sends=False, net_base=3,
            )
        )

    async def test_submission_over_prior_noise_is_delivered(self):
        # ノイズ（net_base=3）があっても submit が実際にリクエストを送れば差分 +1＝送達。
        self.assertTrue(
            await self._run(
                result={"success": True, "action": "http://x/"},
                click_raises=True, submit_sends=True, net_base=3,
            )
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


class ClickjackingHeaderEvidenceTests(unittest.IsolatedAsyncioTestCase):
    """clickjacking は対象ページの実ヘッダ（直接 GET）で framing 保護を判定する（0034 FP 修正）。

    XFO: DENY または CSP frame-ancestors があれば安全（finding なし）。current_page_pair の
    latest() フォールバックで別リクエストの誤ヘッダを掴んで安全ページを FP にしない。
    """

    def _scanner(self):
        engine = _FakeEngine()
        engine.browser.network = None
        return engine, SCANNERS["clickjacking"](engine)

    async def _run(self, resp_headers):
        engine, scanner = self._scanner()

        async def _pair(url):
            return {"request": {"url": url}, "response": {"status": 200, "headers": resp_headers}}

        scanner._response_pair = _pair
        recorded = []

        async def _rec(**kw):
            recorded.append(kw)
            return object()

        scanner.record_finding = _rec
        out = await scanner.scan_page("http://x/portal/embed")
        return recorded, engine

    async def test_xfo_deny_is_safe(self):
        recorded, _ = await self._run({"X-Frame-Options": "DENY"})
        self.assertFalse(recorded)  # 保護あり＝finding なし（FP を出さない）

    async def test_csp_frame_ancestors_is_safe(self):
        recorded, _ = await self._run(
            {"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"}
        )
        self.assertFalse(recorded)

    async def test_full_secure_headers_is_safe(self):
        # /portal/embed-safe 相当（XFO DENY と frame-ancestors 'none' 両方）＝安全。
        recorded, _ = await self._run(
            {"X-Frame-Options": "DENY",
             "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"}
        )
        self.assertFalse(recorded)

    async def test_no_framing_protection_is_vulnerable(self):
        recorded, _ = await self._run({"Content-Security-Policy": "default-src 'self'"})
        self.assertTrue(recorded)  # framing 保護なし＝finding

    async def test_no_response_records_transport_error(self):
        engine, scanner = self._scanner()

        async def _empty(url):
            return {}

        scanner._response_pair = _empty
        # 完全な取得失敗（response 証拠なし）は transport_error を刻んだ上で
        # PageDocumentUnavailable を送出し、engine の error 経路（checkpoint 未完了→
        # resume 再試行）へ載せる（Codex #145 P2 round15）。[] 返しだと tested 完了で恒久 skip。
        with self.assertRaises(PageDocumentUnavailable):
            await scanner.scan_page("http://x/portal/embed")
        self.assertTrue(
            any(e.startswith("transport_error:clickjacking:") for e in engine.wave_errors),
            engine.wave_errors,
        )

    async def test_statusless_pair_returns_empty_without_raising(self):
        # response は非空だが status 欠落（未消費の 3xx 等 legitimate NOT_REACHED）は
        # transport_error を刻みつつ [] を返す（例外にしない）。完全失敗（raise）と
        # 区別し続けることを固定する（Codex #145 P2 round15）。
        engine, scanner = self._scanner()

        async def _statusless(url):
            return {"request": {"url": url}, "response": {"headers": {}}}

        scanner._response_pair = _statusless
        out = await scanner.scan_page("http://x/portal/embed")
        self.assertEqual(out, [])
        self.assertTrue(
            any(e.startswith("transport_error:clickjacking:") for e in engine.wave_errors),
            engine.wave_errors,
        )


class SecurityHeadersFetchEvidenceTests(unittest.IsolatedAsyncioTestCase):
    """security_headers は「レスポンス証拠の欠如」で観測失敗を判定し、空ヘッダは監査する
    （Codex #142 P1/P2）。空レスポンス→transport_error、valid だが空ヘッダ→監査（note なし）。
    """

    def _scanner(self):
        engine = _FakeEngine()
        engine.browser.network = None
        scanner = SCANNERS["security_headers"](engine)
        return engine, scanner

    async def test_no_response_records_transport_error(self):
        engine, scanner = self._scanner()

        async def _empty(url):
            return {}  # レスポンス証拠なし（fetch 失敗）

        scanner._response_pair = _empty
        # 完全な取得失敗は transport_error を刻んだ上で PageDocumentUnavailable を送出する
        # （Codex #145 P2 round15。[] 返しだと checkpoint tested 完了で resume 再試行されない）。
        with self.assertRaises(PageDocumentUnavailable):
            await scanner.scan_page("http://x/legacy/status")
        self.assertTrue(
            any(e.startswith("transport_error:security_headers:") for e in engine.wave_errors),
            engine.wave_errors,
        )

    async def test_valid_empty_headers_is_audited_not_degraded(self):
        engine, scanner = self._scanner()

        async def _valid_empty(url):
            # 正常なレスポンスだがセキュリティヘッダ皆無（＝最大級の脆弱ケース）。
            return {"request": {"url": url}, "response": {"status": 200, "headers": {}}}

        scanner._response_pair = _valid_empty
        recorded = []

        async def _rec(**kw):
            recorded.append(kw)
            return object()

        scanner.record_finding = _rec
        out = await scanner.scan_page("http://x/legacy/status")
        # 空ヘッダは失敗扱いせず監査する＝欠落ヘッダの finding を出し、transport_error は刻まない。
        self.assertTrue(recorded, "empty-header valid response should be audited")
        self.assertFalse(
            any(e.startswith("transport_error:security_headers:") for e in engine.wave_errors),
            engine.wave_errors,
        )


class FollowableRedirectTests(unittest.IsolatedAsyncioTestCase):
    """_get の redirect 追従判定（Codex #145 P1）。same-host のみ・http→https upgrade は許可。"""

    def _cls(self):
        return SCANNERS["clickjacking"]

    def test_same_host_same_scheme_follows(self):
        f = self._cls()._followable_redirect
        self.assertTrue(f("http://h/a", "http://h/b"))

    def test_default_port_equals_explicit(self):
        # http://h → http://h:80 は同一（P2d：canonical redirect を cross-origin 誤判定しない）。
        f = self._cls()._followable_redirect
        self.assertTrue(f("http://h/a", "http://h:80/a"))
        self.assertTrue(f("https://h/a", "https://h:443/a"))

    def test_http_to_https_upgrade_follows(self):
        # 攻撃対象が canonical HTTPS へ 301 する通常ケースを追従する（P1）。
        f = self._cls()._followable_redirect
        self.assertTrue(f("http://h/page", "https://h/page"))
        # 既定ポート明示（80→443）も canonical upgrade として追従。
        self.assertTrue(f("http://h:80/page", "https://h:443/page"))

    def test_non_default_port_upgrade_blocked(self):
        # http://h:8080 → https://h:8443 は別サービスの可能性があり追従しない（P1 round5）。
        f = self._cls()._followable_redirect
        self.assertFalse(f("http://h:8080/page", "https://h:8443/page"))
        self.assertFalse(f("http://h:8080/page", "https://h/page"))
        self.assertFalse(f("http://h/page", "https://h:8443/page"))

    def test_https_to_http_downgrade_blocked(self):
        f = self._cls()._followable_redirect
        self.assertFalse(f("https://h/page", "http://h/page"))

    def test_different_host_blocked(self):
        # 別ホストへは追従しない（認証情報の漏洩防止）。
        f = self._cls()._followable_redirect
        self.assertFalse(f("http://h/a", "http://evil/a"))
        self.assertFalse(f("http://h/a", "https://evil/a"))

    def test_different_port_same_scheme_blocked(self):
        f = self._cls()._followable_redirect
        self.assertFalse(f("http://h:8000/a", "http://h:9000/a"))


class RejectRedirectPairTests(unittest.TestCase):
    """_response_pair の fallback（current_page_pair）が返す 3xx を document 扱いしない（P2 round6）。"""

    def _cls(self):
        return SCANNERS["clickjacking"]

    def test_redirect_pair_status_stripped(self):
        f = self._cls()._reject_redirect_pair
        pair = {"request": {"url": "http://x/"},
                "response": {"status": 302, "url": "http://x/", "headers": {"location": "/y"}}}
        out = f(pair, "http://x/")
        # status が消え headers も空＝観測系は NOT_REACHED 扱い。
        self.assertNotIn("status", out["response"])
        self.assertEqual(out["response"]["headers"], {})

    def test_non_redirect_pair_unchanged(self):
        f = self._cls()._reject_redirect_pair
        pair = {"request": {"url": "http://x/"},
                "response": {"status": 200, "url": "http://x/", "headers": {"x-frame-options": "DENY"}}}
        self.assertIs(f(pair, "http://x/"), pair)

    def test_missing_status_unchanged(self):
        f = self._cls()._reject_redirect_pair
        pair = {"response": {"headers": {}}}
        self.assertIs(f(pair, "http://x/"), pair)

    def test_empty_pair_unchanged(self):
        f = self._cls()._reject_redirect_pair
        self.assertEqual(f({}, "http://x/"), {})


class CaptureStatusPolicyTests(unittest.TestCase):
    """_apply_capture_status_policy は fallback の captured pair にも direct-GET と同じ
    document status 方針を適用する（2xx=監査/transient=空/その他非2xx=NOT_REACHED・Codex #145 P2 round19）。"""

    def _f(self):
        return SCANNERS["clickjacking"]._apply_capture_status_policy

    def test_2xx_capture_unchanged(self):
        pair = {"request": {"url": "http://x/"},
                "response": {"status": 200, "url": "http://x/", "headers": {"x-frame-options": "DENY"}}}
        self.assertIs(self._f()(pair, "http://x/"), pair)

    def test_permanent_non_2xx_capture_becomes_not_reached(self):
        for status in (301, 401, 403, 404, 410):
            with self.subTest(status=status):
                pair = {"request": {"url": "http://x/"},
                        "response": {"status": status, "url": "http://x/", "headers": {"a": "b"}}}
                out = self._f()(pair, "http://x/")
                self.assertNotIn("status", out["response"])
                self.assertEqual(out["response"]["headers"], {})

    def test_transient_capture_becomes_empty(self):
        for status in (408, 429, 500, 502, 503, 504):
            with self.subTest(status=status):
                pair = {"request": {"url": "http://x/"},
                        "response": {"status": status, "url": "http://x/", "headers": {}}}
                self.assertEqual(self._f()(pair, "http://x/"), {})

    def test_statusless_capture_unchanged(self):
        pair = {"response": {"headers": {}}}
        self.assertIs(self._f()(pair, "http://x/"), pair)


class ResponsePairDocumentGuardTests(unittest.IsolatedAsyncioTestCase):
    """_response_pair は直接 GET(replay)が **2xx（描画された document）** のときだけ status/headers を
    載せる。恒久的な非 2xx（3xx・401/404/410 等の「この document ではない」）は status を落として
    NOT_REACHED（[] 返し）。ただし transient（408/429/5xx）は空 pair を返して scanner に
    PageDocumentUnavailable を投げさせ resume 再試行可能にする（Codex #145 P2 round17/18）。"""

    def _scanner(self, response):
        engine = _FakeEngine()
        engine.browser = _APIBrowser(_FakeRequestCtx(response))
        return engine, SCANNERS["clickjacking"](engine)

    async def _pair_for(self, status, headers=None):
        engine, scanner = self._scanner(
            _FakeAPIResponse(status, headers or {"X-Frame-Options": "DENY"})
        )
        return await scanner._response_pair("http://app.test/doc")

    async def test_2xx_is_audited(self):
        pair = await self._pair_for(200)
        self.assertEqual(pair["response"].get("status"), 200)
        self.assertIn("x-frame-options", {k.lower() for k in pair["response"]["headers"]})

    async def test_401_replay_is_not_reached(self):
        pair = await self._pair_for(401)
        self.assertNotIn("status", pair["response"])  # NOT_REACHED
        self.assertEqual(pair["response"]["headers"], {})

    async def test_404_replay_is_not_reached(self):
        pair = await self._pair_for(404)
        self.assertNotIn("status", pair["response"])
        self.assertEqual(pair["response"]["headers"], {})

    async def test_410_replay_is_not_reached(self):
        pair = await self._pair_for(410)
        self.assertNotIn("status", pair["response"])

    async def test_transient_5xx_returns_empty_pair(self):
        # 503/429/408 は transient＝空 pair（→ scanner が PageDocumentUnavailable→resume 再試行）。
        for status in (503, 502, 500, 429, 408, 504):
            with self.subTest(status=status):
                pair = await self._pair_for(status)
                self.assertEqual(pair, {})

    async def test_clickjacking_does_not_flag_401_replay(self):
        # 401 replay の欠落 XFO/CSP を framing 保護なしと誤報しない（回帰）。
        engine, scanner = self._scanner(_FakeAPIResponse(401, {}))
        findings = await scanner.scan_page("http://app.test/one-time")
        self.assertEqual(findings, [])

    async def test_clickjacking_raises_on_transient_replay(self):
        # transient(503)は tested 完了にせず PageDocumentUnavailable で error 経路→resume 再試行。
        engine, scanner = self._scanner(_FakeAPIResponse(503, {}))
        with self.assertRaises(PageDocumentUnavailable):
            await scanner.scan_page("http://app.test/flaky")

    async def test_header_scanners_share_one_replay_per_url(self):
        """clickjacking と security_headers が同一 engine・同一 URL で GET を 1 回だけ共有する
        （副作用のある GET を read-only ヘッダ検査で二重に叩かない・Codex #145 P2 round18）。"""
        engine = _FakeEngine()
        ctx = _FakeRequestCtx(_FakeAPIResponse(200, {"X-Frame-Options": "DENY"}))
        engine.browser = _APIBrowser(ctx)
        cj = SCANNERS["clickjacking"](engine)
        sh = SCANNERS["security_headers"](engine)
        url = "http://app.test/logout"
        pair_cj = await cj._response_pair(url)
        pair_sh = await sh._response_pair(url)
        # 2 スキャナが同一 URL を監査しても直接 GET は 1 回だけ（キャッシュ共有）。
        self.assertEqual(len(ctx.calls), 1, ctx.calls)
        self.assertEqual(pair_cj, pair_sh)
        self.assertEqual(pair_cj["response"].get("status"), 200)
        # 別 URL は別途 1 回 GET する。
        await cj._response_pair("http://app.test/other")
        self.assertEqual(len(ctx.calls), 2)


class CurrentPagePairWorkerAwareTests(unittest.TestCase):
    """current_page_pair は __init__ 捕捉の self.browser でなく worker-aware な
    self.engine.browser の network から pair を読む（Codex #145 round9 の fallback 経路）。"""

    class _Net:
        def __init__(self, pair):
            self._pair = pair

        def latest_for_url(self, url, match_query=False):
            return self._pair

        def latest(self):
            return self._pair

    class _Browser:
        def __init__(self, pair):
            self.network = CurrentPagePairWorkerAwareTests._Net(pair)

    def test_reads_from_current_worker_browser(self):
        engine = _FakeEngine()
        engine.browser = self._Browser({"response": {"status": 200, "url": "m"}})
        scanner = SCANNERS["clickjacking"](engine)
        # 構築後に engine.browser を worker のもの（別 capture）へ差し替える。
        engine.browser = self._Browser({"response": {"status": 200, "url": "worker"}})
        pair = scanner.current_page_pair("http://x/")
        self.assertEqual(pair["response"]["url"], "worker")  # worker の capture を読む


class _FakeAPIResponse:
    """Playwright APIResponse の最小ダブル（status/headers/text/url + dispose 記録）。"""

    def __init__(self, status, headers=None, text="<html>"):
        self.status = status
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self._text = text
        self.url = ""
        self.disposed = 0

    async def text(self):
        return self._text

    async def dispose(self):
        self.disposed += 1


class _FakeRequestCtx:
    """context.request の最小ダブル。get() の (url, headers, kwargs) を記録し、順に応答を返す。"""

    def __init__(self, responses):
        self._responses = responses if isinstance(responses, list) else [responses]
        self.calls: list = []
        self._i = 0

    async def get(self, url, headers=None, **kw):
        self.calls.append((url, dict(headers or {}), kw))
        r = self._responses[min(self._i, len(self._responses) - 1)]
        self._i += 1
        r.url = url
        return r


class _APIBrowser:
    DEFAULT_USER_AGENT = "Mozilla/5.0 TestUA"

    def __init__(self, request_ctx):
        class _Ctx:
            pass

        self._context = _Ctx()
        self._context.request = request_ctx


class DirectGetAPIRequestContextTests(unittest.IsolatedAsyncioTestCase):
    """_get は Playwright browser context の APIRequestContext（context.request）で取得する
    （Codex #145 round12）。Cookie は Playwright が native 管理するため httpx jar 自作を撤去。"""

    def _scanner(self, responses, *, auth=None):
        engine = _FakeEngine()
        engine.browser = _APIBrowser(_FakeRequestCtx(responses))
        if auth is not None:
            engine.auth_headers = auth
        scanner = SCANNERS["clickjacking"](engine)
        return engine, scanner

    async def test_returns_direct_response_from_api_context(self):
        resp = _FakeAPIResponse(200, {"X-Frame-Options": "DENY"}, text="<html>ok</html>")
        engine, scanner = self._scanner(resp)
        out = await scanner._get("http://app.test/p")
        self.assertEqual(out.status_code, 200)
        self.assertEqual(out.headers.get("x-frame-options"), "DENY")
        self.assertEqual(out.text, "<html>ok</html>")

    async def test_sends_fetch_metadata_and_ua(self):
        engine, scanner = self._scanner(_FakeAPIResponse(200))
        await scanner._get("http://app.test/p")
        _url, headers, kw = engine.browser._context.request.calls[0]
        h = {k.lower(): v for k, v in headers.items()}
        self.assertEqual(h.get("sec-fetch-site"), "none")
        self.assertEqual(h.get("sec-fetch-mode"), "navigate")
        self.assertEqual(h.get("sec-fetch-user"), "?1")
        self.assertEqual(h.get("sec-fetch-dest"), "document")
        self.assertEqual(h.get("user-agent"), "Mozilla/5.0 TestUA")
        self.assertEqual(kw.get("max_redirects"), 0)  # 自動追従は無効

    async def test_honors_configured_timeout_in_ms(self):
        """engine.timeout（秒）を Playwright の ms として毎 hop 渡す（Codex #145 round13）。"""
        engine, scanner = self._scanner(_FakeAPIResponse(200))
        engine.timeout = 5  # 秒
        await scanner._get("http://app.test/p")
        _url, _h, kw = engine.browser._context.request.calls[0]
        self.assertEqual(kw.get("timeout"), 5000.0)

    async def test_resyncs_engine_cookies_after_get(self):
        """監査 GET 後に engine._sync_cookies_from_browser で engine.cookies を再同期する
        （httpx ベースの CORS 等が stale セッションを送らない・Codex #145 P1 round14）。"""
        engine, scanner = self._scanner(_FakeAPIResponse(200))
        called = {}

        async def _sync(browser, for_url=""):
            called["browser"] = browser
            called["url"] = for_url

        engine._sync_cookies_from_browser = _sync
        await scanner._get("http://app.test/p")
        self.assertEqual(called.get("url"), "http://app.test/p")
        self.assertIs(called.get("browser"), engine.browser)

    async def test_resyncs_engine_cookies_even_when_redirect_hop_raises(self):
        """中間 redirect hop が cookie を rotation/削除した後に次 hop が例外を投げても、
        engine.cookies を再同期する（finally 経路）。成功パスだけの同期では無効トークンが
        残り CORS 等が未認証応答に走る（Codex #145 P2 round16）。"""

        class _RaiseOnSecondGet:
            def __init__(self):
                self.calls = 0

            async def get(self, url, headers=None, **kw):
                self.calls += 1
                if self.calls == 1:
                    r = _FakeAPIResponse(302, {"location": "/landing"})
                    r.url = url
                    return r  # 承認された同一ホスト redirect（cookie を変異させ得る）
                raise RuntimeError("hop timeout")  # 次 hop の取得が失敗

        engine = _FakeEngine()
        engine.browser = _APIBrowser(_RaiseOnSecondGet())
        scanner = SCANNERS["clickjacking"](engine)
        called = {}

        async def _sync(browser, for_url=""):
            called["url"] = for_url

        engine._sync_cookies_from_browser = _sync
        with self.assertRaises(RuntimeError):
            await scanner._get("http://app.test/start")
        # 例外が伝播しても、直列なので再同期は必ず実行される。
        self.assertEqual(called.get("url"), "http://app.test/start")

    async def test_no_cookie_resync_under_concurrency(self):
        """並列(--concurrency>1)では共有 engine.cookies を書き換えないよう再同期をスキップ
        （別 worker の検査中の競合防止・Codex #145 P1 round15）。"""
        engine, scanner = self._scanner(_FakeAPIResponse(200))
        engine.concurrency = 2
        called = {"n": 0}

        async def _sync(browser, for_url=""):
            called["n"] += 1

        engine._sync_cookies_from_browser = _sync
        await scanner._get("http://app.test/p")
        self.assertEqual(called["n"], 0)

    async def test_disposes_responses(self):
        """最終 response を dispose して body を解放する（Codex #145 round13）。"""
        resp = _FakeAPIResponse(200, {"X-Frame-Options": "DENY"})
        engine, scanner = self._scanner(resp)
        await scanner._get("http://app.test/p")
        self.assertGreaterEqual(resp.disposed, 1)

    async def test_disposes_intermediate_redirect_responses(self):
        r1 = _FakeAPIResponse(302, {"location": "/landing"})
        r2 = _FakeAPIResponse(200, {"X-Frame-Options": "DENY"})
        engine, scanner = self._scanner([r1, r2])
        await scanner._get("http://app.test/start")
        self.assertGreaterEqual(r1.disposed, 1)  # 中間 redirect も解放
        self.assertGreaterEqual(r2.disposed, 1)

    async def test_scope_approved_cross_host_redirect_followed(self):
        """engine の明示 scope（_header_scope_origins）に含まれる別ホストへの redirect は追従し、
        その host の scoped auth を再計算する（Codex #145 round13）。"""
        r1 = _FakeAPIResponse(302, {"location": "https://www.app.test/"})
        r2 = _FakeAPIResponse(200, {"X-Frame-Options": "DENY"})
        engine, scanner = self._scanner([r1, r2])
        engine._header_scope_origins = {"https://www.app.test", "http://app.test"}
        out = await scanner._get("http://app.test/start")
        self.assertEqual(out.status_code, 200)
        self.assertEqual(
            engine.browser._context.request.calls[1][0], "https://www.app.test/"
        )

    async def test_user_header_replaces_generated_case_insensitively(self):
        auth = lambda extra=None, include_cookie=True, url=None: {
            "user-agent": "CustomUA", "accept-language": "ja"
        }
        engine, scanner = self._scanner(_FakeAPIResponse(200), auth=auth)
        await scanner._get("http://app.test/p")
        _url, headers, _mr = engine.browser._context.request.calls[0]
        h = {k.lower(): v for k, v in headers.items()}
        self.assertEqual(h.get("user-agent"), "CustomUA")
        self.assertNotIn("Mozilla", h.get("user-agent", ""))
        # 生成 User-Agent（大文字）が重複して残っていないこと。
        self.assertNotIn("User-Agent", headers)
        self.assertEqual(h.get("accept-language"), "ja")

    async def test_missing_api_context_raises_for_fallback(self):
        """APIRequestContext が無い（テストダブル等）なら例外→_response_pair が network fallback。"""
        engine = _FakeEngine()
        engine.browser = object()  # _context 無し
        scanner = SCANNERS["clickjacking"](engine)
        with self.assertRaises(Exception):
            await scanner._get("http://app.test/p")

    async def test_same_host_redirect_followed(self):
        responses = [
            _FakeAPIResponse(302, {"location": "/landing"}),
            _FakeAPIResponse(200, {"X-Frame-Options": "DENY"}),
        ]
        engine, scanner = self._scanner(responses)
        out = await scanner._get("http://app.test/start")
        self.assertEqual(out.status_code, 200)
        # 2 hop 目が same-host の /landing を叩いている。
        self.assertEqual(engine.browser._context.request.calls[1][0], "http://app.test/landing")

    async def test_cross_host_redirect_not_followed(self):
        responses = [_FakeAPIResponse(302, {"location": "https://evil.test/x"})]
        engine, scanner = self._scanner(responses)
        out = await scanner._get("http://app.test/start")
        # 別ホストは追従せず 3xx のまま返す（_response_pair が status を落として NOT_REACHED）。
        self.assertEqual(out.status_code, 302)
        self.assertEqual(len(engine.browser._context.request.calls), 1)

    async def test_uses_worker_aware_engine_browser(self):
        """__init__ 捕捉のメイン self.browser でなく呼び出し時の self.engine.browser を使う。"""
        engine = _FakeEngine()
        engine.browser = object()  # 構築時のメインは APIRequestContext 無し
        scanner = SCANNERS["clickjacking"](engine)
        # 構築後に worker の browser（APIRequestContext あり）へ差し替える。
        engine.browser = _APIBrowser(_FakeRequestCtx(_FakeAPIResponse(200, {"X-Frame-Options": "DENY"})))
        out = await scanner._get("http://app.test/p")
        self.assertEqual(out.status_code, 200)  # worker の context で取得できる


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
