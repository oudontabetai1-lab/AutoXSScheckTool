"""SPA 収穫 JSON body の攻撃ループと再開キーのテスト。"""
import unittest

from wscan.engine import ScanEngine, _stable_json_template_id
from wscan.intervention import SkipPage
from wscan.injection_point import InjectionPoint
from wscan.scanners.base import finding_dedup_key_for, refresh_idempotency_headers
from wscan.report import Finding


class _Controller:
    """checkpoint() の N 回目（0-indexed）で一度だけ SkipPage を送る操作卓の double。

    JSON 注入ループは 1 注入点あたり checkpoint を 1 回呼ぶ（対象チェックは sqli のみ）
    ので、call index ＝ 注入点 index に対応し、特定の注入点で skip_page を再現できる。
    """

    def __init__(self, skip_at=None):
        self._skip_at = skip_at
        self._calls = 0

    async def checkpoint(self):
        idx = self._calls
        self._calls += 1
        if self._skip_at is not None and idx == self._skip_at:
            raise SkipPage()
        return None


class _Scanner:
    SUPPORTS_JSON_BODY = True

    def __init__(self):
        self.calls = []
        self._engine = None

    async def scan_injection_point(self, ip, field):
        self.calls.append((ip, field))
        # 実 transport が応答を受けた＝送信成功、をモデルする。
        if self._engine is not None:
            self._engine._json_probe_sent = True
        return []


class _Engine:
    _run_json_injection_checks = ScanEngine._run_json_injection_checks

    def __init__(self, points, templates, *, expired=False, relogin_ok=True,
                 controller=None, scanner=None):
        self.json_injection_points = list(points)
        self.injection_templates = dict(templates)
        self.controller = controller or _Controller()
        self.browser = object()
        self.scanner = scanner or _Scanner()
        # transport double が送信成功フラグを立てられるよう engine 参照を配線する。
        if getattr(self.scanner, "_engine", "missing") is None:
            self.scanner._engine = self
        self.scanners = {"sqli": self.scanner}
        self.done = set()
        self.marked = []
        self.saved = 0
        self._expired = expired
        self._relogin_ok = relogin_ok
        self._api_auth_failed = False
        self._json_probe_sent = False

    async def _maybe_relogin_for_page(self, url):
        return None

    async def _sync_cookies_from_browser(self, browser, *, for_url):
        return None

    async def _api_session_looks_expired(self, url):
        return self._expired

    async def _force_relogin(self, *, for_url):
        return self._relogin_ok

    def _checkpoint_is_done_ip(self, ip, check):
        return (ip.stable_key_parts(), check) in self.done

    def _checkpoint_mark_done_ip(self, ip, check):
        key = (ip.stable_key_parts(), check)
        self.done.add(key)
        self.marked.append(key)

    def _record_finding(self, finding, source=""):
        raise AssertionError("このテストでは Finding を返さない")

    def _save_checkpoint(self):
        self.saved += 1


class JsonInjectionCheckTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_template_is_not_marked_done(self):
        ip = InjectionPoint.for_json_body(
            "POST", "http://h/api/login", "/email", template_id="missing"
        )
        engine = _Engine([ip], {})

        await engine._run_json_injection_checks()

        self.assertEqual(len(engine.scanner.calls), 1)
        self.assertEqual(engine.marked, [])
        self.assertEqual(engine.saved, 1)

    async def test_registered_template_is_marked_done(self):
        ip = InjectionPoint.for_json_body(
            "POST", "http://h/api/login", "/email", template_id="login"
        )
        engine = _Engine([ip], {"login": {}})

        await engine._run_json_injection_checks()

        self.assertEqual(len(engine.scanner.calls), 1)
        self.assertEqual(len(engine.marked), 1)

    async def test_distinct_templates_with_same_pointer_are_both_scanned(self):
        first = InjectionPoint.for_json_body(
            "POST", "http://h/api/rpc", "/params/name", template_id="op-a"
        )
        second = InjectionPoint.for_json_body(
            "POST", "http://h/api/rpc", "/params/name", template_id="op-b"
        )
        self.assertNotEqual(first.stable_key_parts(), second.stable_key_parts())
        engine = _Engine([first, second], {"op-a": {}, "op-b": {}})

        await engine._run_json_injection_checks()

        self.assertEqual(
            [call[0].template_id for call in engine.scanner.calls],
            ["op-a", "op-b"],
        )
        self.assertEqual(len(engine.marked), 2)

    async def test_failed_reauth_does_not_mark_done(self):
        # 再認証に失敗（relogin_ok=False）したら、probe は送っても完了記録しない
        # （401 空振りを陰性と誤記録→resume 恒久スキップする偽陰性を防ぐ）。
        ip = InjectionPoint.for_json_body(
            "POST", "http://h/api/login", "/email", template_id="login"
        )
        engine = _Engine([ip], {"login": {}}, expired=True, relogin_ok=False)

        await engine._run_json_injection_checks()

        self.assertEqual(len(engine.scanner.calls), 1)  # probe は走る
        self.assertEqual(engine.marked, [])             # が「済み」にはしない

    async def test_successful_reauth_marks_done(self):
        ip = InjectionPoint.for_json_body(
            "POST", "http://h/api/login", "/email", template_id="login"
        )
        engine = _Engine([ip], {"login": {}}, expired=True, relogin_ok=True)

        await engine._run_json_injection_checks()

        self.assertEqual(len(engine.marked), 1)

    async def test_transport_detected_auth_failure_does_not_mark_done(self):
        # GET プレフライトでは失効を検知できない（expired=False）が、実 POST 中に
        # transport が logout を検知して engine._api_auth_failed を立てたケース。
        # 未認証空振りを「済み」記録して resume 恒久スキップする偽陰性を防ぐ。
        class _AuthFailScanner:
            SUPPORTS_JSON_BODY = True

            def __init__(self, engine):
                self._engine = engine
                self.calls = []

            async def scan_injection_point(self, ip, field):
                self.calls.append((ip, field))
                # 401 は「送信成功だが未認証」＝sent=True かつ auth_failed=True。
                self._engine._json_probe_sent = True
                self._engine._api_auth_failed = True
                return []

        engine = _Engine.__new__(_Engine)
        scanner = _AuthFailScanner(engine)
        ip = InjectionPoint.for_json_body(
            "POST", "http://h/api/orders", "/note", template_id="orders"
        )
        _Engine.__init__(
            engine, [ip], {"orders": {}}, expired=False, scanner=scanner
        )

        await engine._run_json_injection_checks()

        self.assertEqual(len(scanner.calls), 1)   # probe は走る
        self.assertEqual(engine.marked, [])       # が「済み」にはしない

    async def test_transport_failure_does_not_mark_done(self):
        # transport 失敗（timeout/TLS/DNS/proxy）で 1 度も送れなかったケース。
        # scan は正常終了するが _json_probe_sent が立たない＝送信成功の証拠なし。
        # 送れなかった probe を「済み」記録して resume 恒久スキップする偽陰性を防ぐ。
        class _NoSendScanner:
            SUPPORTS_JSON_BODY = True

            def __init__(self):
                self.calls = []
                self._engine = None  # engine 参照は配線されるが sent は立てない

            async def scan_injection_point(self, ip, field):
                self.calls.append((ip, field))
                return []  # _json_probe_sent を立てない＝送信不成立

        ip = InjectionPoint.for_json_body(
            "POST", "http://h/api/login", "/email", template_id="login"
        )
        engine = _Engine([ip], {"login": {}}, scanner=_NoSendScanner())

        await engine._run_json_injection_checks()

        self.assertEqual(len(engine.scanner.calls), 1)  # scan は走る
        self.assertEqual(engine.marked, [])             # が「済み」にはしない

    async def test_skip_page_skips_remaining_points_of_same_url(self):
        # 同一 URL に 2 pointer、別 URL に 1 pointer。1つ目(url A)で skip_page すると
        # url A の残り pointer も飛ばし、url B は通常どおり scan される。
        a1 = InjectionPoint.for_json_body(
            "POST", "http://h/api/a", "/email", template_id="a1"
        )
        a2 = InjectionPoint.for_json_body(
            "POST", "http://h/api/a", "/name", template_id="a2"
        )
        b1 = InjectionPoint.for_json_body(
            "POST", "http://h/api/b", "/email", template_id="b1"
        )
        controller = _Controller(skip_at=0)  # 最初の注入点(a1)で skip_page
        engine = _Engine([a1, a2, b1], {"a1": {}, "a2": {}, "b1": {}}, controller=controller)

        await engine._run_json_injection_checks()

        scanned = [call[0].url for call in engine.scanner.calls]
        self.assertEqual(scanned, ["http://h/api/b"])  # a1/a2 は飛び、b1 のみ

    def test_json_finding_dedup_key_includes_template_id(self):
        # 同一 (check,url,field,evidence,method,pointer) でも別 operation(別 template)は
        # 別脆弱性。finding dedup キーが template_id を含み、2件目が捨てられないこと。
        def _f(template_id):
            return Finding(
                check_type="sqli", severity="high", url="http://h/api/rpc",
                field_name="name", payload="'", evidence="e", evidence_type="sqli_error",
                injection_location="json_body", injection_pointer="/params/name",
                injection_method="POST", injection_template_id=template_id,
            )

        self.assertNotEqual(
            finding_dedup_key_for(_f("op-a")),
            finding_dedup_key_for(_f("op-b")),
        )
        # 同一 template なら同一キー（正しく dedup される）。
        self.assertEqual(
            finding_dedup_key_for(_f("op-a")),
            finding_dedup_key_for(_f("op-a")),
        )

    def test_stable_template_id_is_deterministic_and_operation_scoped(self):
        # 同一 dedup_key（method,url,body_signature,content_type）→ 同一 ID（resume 安定）。
        key_a = ("POST", "http://h/api/rpc", ("sig-a",), "application/json")
        key_b = ("POST", "http://h/api/rpc", ("sig-b",), "application/json")
        self.assertEqual(_stable_json_template_id(key_a), _stable_json_template_id(key_a))
        # 別 operation（body_signature 違い）→ 別 ID（衝突による偽陰性/誤 executable を防ぐ）。
        self.assertNotEqual(_stable_json_template_id(key_a), _stable_json_template_id(key_b))
        # 連番と違い観測順に依存しない（値だけで決まる）。
        self.assertTrue(_stable_json_template_id(key_a).startswith("jb-"))

    def test_refresh_idempotency_headers_regenerates_value_preserves_name(self):
        headers = {
            "Content-Type": "application/json",
            "Idempotency-Key": "captured-123",
            "X-Idempotency-Token": "captured-456",
            "Authorization": "Bearer t",
        }
        out1 = refresh_idempotency_headers(headers)
        out2 = refresh_idempotency_headers(headers)
        # 値は毎回 fresh（連投で冪等 API がキャッシュ応答を返さない）。
        self.assertNotEqual(out1["Idempotency-Key"], "captured-123")
        self.assertNotEqual(out1["Idempotency-Key"], out2["Idempotency-Key"])
        self.assertNotEqual(out1["X-Idempotency-Token"], "captured-456")
        # ヘッダ名（表記含む）は温存、非 idempotency ヘッダは不変。
        self.assertIn("Idempotency-Key", out1)
        self.assertEqual(out1["Content-Type"], "application/json")
        self.assertEqual(out1["Authorization"], "Bearer t")
        # 入力 dict は破壊しない（純粋）。
        self.assertEqual(headers["Idempotency-Key"], "captured-123")

    def test_form_finding_dedup_key_unchanged_by_json_augmentation(self):
        # form/url_param の dedup キーは json 拡張の影響を受けない（4-tuple のまま）。
        form_finding = Finding(
            check_type="sqli", severity="high", url="http://h/login",
            field_name="email", payload="'", evidence="e", evidence_type="sqli_error",
            injection_location="form", injection_form_index=0,
        )
        key = finding_dedup_key_for(form_finding)
        self.assertEqual(len(key), 4)

    def test_legacy_keys_and_empty_template_json_key_are_unchanged(self):
        form = InjectionPoint.for_form("http://h/form/", "email", 2)
        url_param = InjectionPoint.for_url_param("http://h/search/", "q")
        json_ip = InjectionPoint.for_json_body(
            "POST", "http://h/api/login/", "/email"
        )

        self.assertEqual(
            form.stable_key_parts(),
            ("http://h/form", "email", "2", "f", ""),
        )
        self.assertEqual(
            url_param.stable_key_parts(),
            ("http://h/search", "q", "0", "u", ""),
        )
        self.assertEqual(
            json_ip.stable_key_parts(),
            ("http://h/api/login", "email", "0", "j:POST", "/email"),
        )


if __name__ == "__main__":
    unittest.main()
