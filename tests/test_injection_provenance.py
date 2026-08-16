"""Finding の注入点 provenance に関する加算的テスト。"""
import json
import unittest

from wscan.injection_point import InjectionPoint
from wscan.engine import ScanEngine
from wscan.scanners.base import (
    BaseScanner,
    Finding,
    ProvenanceError,
    finding_dedup_key_for,
    injection_point_from_finding,
)


class _Browser:
    async def screenshot_b64(self, label=""):
        return ""


class _Engine:
    def __init__(self):
        self.browser = _Browser()
        self.monitor = None
        self.payload_gen = None
        self._finding_dedup = set()
        self.all_findings = []


class _Scanner(BaseScanner):
    CHECK_TYPE = "sqli"

    async def scan_field(self, url, form_index, field, is_url_param=False):
        return []


class _VerifyBrowser:
    def __init__(self):
        self.navigate_calls = []

    async def navigate(self, url, retries=0):
        self.navigate_calls.append((url, retries))

    def reset_dialog(self):
        pass


class _VerifyScanner:
    def __init__(self):
        self.applied_ips = []

    async def verify_finding(self, finding):
        return None

    async def _apply_ip(self, ip, payload):
        self.applied_ips.append((ip, payload))
        return "", {}


class _VerifyEngine:
    _verify_one = ScanEngine._verify_one

    def __init__(self, scanner):
        self.scanners = {"path_traversal": scanner}
        self.browser = _VerifyBrowser()
        self.navigation_retries = 2
        self._effective_delay = 0


class FindingInjectionProvenanceTests(unittest.IsolatedAsyncioTestCase):
    def test_finding_roundtrip_preserves_injection_fields(self):
        finding = Finding(
            check_type="sqli",
            severity="high",
            url="http://h/login",
            field_name="email",
            payload="'",
            evidence="error",
            injection_location="json_body",
            injection_pointer="/profile/email",
            injection_method="POST",
            injection_template_id="login-1",
        )
        restored = Finding.from_dict(finding.to_dict())
        self.assertEqual(restored.injection_location, "json_body")
        self.assertEqual(restored.injection_pointer, "/profile/email")
        self.assertEqual(restored.injection_method, "POST")
        self.assertEqual(restored.injection_template_id, "login-1")

    async def test_record_finding_stamps_form_without_pointer_or_method(self):
        scanner = _Scanner(_Engine())
        ip = InjectionPoint.for_form("http://h/form", "email")
        finding = await scanner.record_finding(
            "http://h/form",
            "email",
            "payload",
            "evidence",
            {"request": {}, "response": {}},
            screenshot_b64="",
            injection_point=ip,
        )
        self.assertEqual(finding.injection_location, "form")
        self.assertEqual(finding.injection_pointer, "")
        self.assertEqual(finding.injection_method, "")

    async def test_record_finding_stamps_json_body(self):
        scanner = _Scanner(_Engine())
        ip = InjectionPoint.for_json_body(
            "post",
            "http://h/login",
            "/email",
            template_id="login-1",
        )
        finding = await scanner.record_finding(
            "http://h/login",
            "email",
            "payload",
            "evidence",
            {"request": {}, "response": {}},
            screenshot_b64="",
            injection_point=ip,
        )
        self.assertEqual(finding.injection_location, "json_body")
        self.assertEqual(finding.injection_pointer, "/email")
        self.assertEqual(finding.injection_method, "POST")
        self.assertEqual(finding.injection_template_id, "login-1")

    async def test_json_body_dedup_distinguishes_same_leaf_pointers(self):
        scanner = _Scanner(_Engine())
        pair = {"request": {}, "response": {}}
        ip1 = InjectionPoint.for_json_body(
            "POST", "http://h/u", "/profile/id", template_id="t"
        )
        ip2 = InjectionPoint.for_json_body(
            "POST", "http://h/u", "/billing/id", template_id="t"
        )
        f1 = await scanner.record_finding(
            "http://h/u", "id", "'", "err", pair, screenshot_b64="",
            evidence_type="sqli_error", injection_point=ip1,
        )
        f2 = await scanner.record_finding(
            "http://h/u", "id", "'", "err", pair, screenshot_b64="",
            evidence_type="sqli_error", injection_point=ip2,
        )
        # 別ポインタは別入力として両方残る（leaf 名の衝突で捨てない）。
        self.assertIsNotNone(f1)
        self.assertIsNotNone(f2)

    async def test_form_dedup_identity_unchanged(self):
        scanner = _Scanner(_Engine())
        pair = {"request": {}, "response": {}}
        ip = InjectionPoint.for_form("http://h/form", "id")
        f1 = await scanner.record_finding(
            "http://h/form", "id", "'", "err", pair, screenshot_b64="",
            evidence_type="sqli_error", injection_point=ip,
        )
        f2 = await scanner.record_finding(
            "http://h/form", "id", "'", "err", pair, screenshot_b64="",
            evidence_type="sqli_error", injection_point=ip,
        )
        # form の dedup は従来通り（同一入力・同一 evidence の2件目は重複扱い）。
        self.assertIsNotNone(f1)
        self.assertIsNone(f2)

    async def test_record_finding_redacts_json_evidence(self):
        # 検出用 transport は生 pair を返し、伏字はこの永続境界で行う。
        scanner = _Scanner(_Engine())
        ip = InjectionPoint.for_json_body(
            "POST", "http://h/login", "/profile/email", template_id="t"
        )
        sent_body = {
            "profile": {"email": "PAYLOAD", "name": "Alice"},
            "password": "observed-secret",
        }
        pair = {
            "request": {
                "url": "http://h/login",
                "method": "POST",
                "headers": {
                    "Authorization": "Bearer x",
                    "X-Access-Token": "tok-123",  # テンプレ由来の認証ヘッダ
                    "X-Tenant": "t1",
                },
                "post_data": json.dumps(sent_body),
            },
            "response": {
                "status": 200,
                "headers": {"X-Access-Token": "resp-tok", "Content-Type": "application/json"},
                "body": json.dumps({"received": sent_body}),
            },
        }
        finding = await scanner.record_finding(
            "http://h/login", "email", "PAYLOAD", "evidence", pair,
            screenshot_b64="", evidence_type="sqli_error", injection_point=ip,
        )
        # request body: 兄弟マスク・注入 pointer の値は残る。
        req_body = json.loads(finding.request["post_data"])
        self.assertEqual(req_body["profile"]["email"], "PAYLOAD")
        self.assertEqual(req_body["profile"]["name"], "***")
        self.assertEqual(req_body["password"], "***")
        # 認証ヘッダ(テンプレ由来の X-Access-Token 含む)はマスク、非認証は残る。
        self.assertEqual(finding.request["headers"]["Authorization"], "***")
        self.assertEqual(finding.request["headers"]["X-Access-Token"], "***")
        self.assertEqual(finding.request["headers"]["X-Tenant"], "t1")
        # response ヘッダの認証情報(サーバ発行の X-Access-Token 等)もマスク、非認証は残る。
        self.assertEqual(finding.response["headers"]["X-Access-Token"], "***")
        self.assertEqual(finding.response["headers"]["Content-Type"], "application/json")
        # response 本文: エコーされた兄弟秘匿はマスク、注入値は残る。
        self.assertNotIn("observed-secret", finding.response["body"])
        self.assertIn("PAYLOAD", finding.response["body"])

    def test_shared_dedup_helper_distinguishes_pointers(self):
        # resume 復元(_init_checkpoint)や engine._record_finding が使う共有ヘルパーも
        # pointer を区別する（記録時 6-tuple・復元時 4-tuple の食い違いを防ぐ）。
        base_kwargs = dict(
            check_type="sqli", severity="high", url="http://h/u",
            field_name="id", payload="'", evidence="err", evidence_type="sqli_error",
        )
        f1 = Finding(**base_kwargs, injection_location="json_body",
                     injection_method="POST", injection_pointer="/profile/id")
        f2 = Finding(**base_kwargs, injection_location="json_body",
                     injection_method="POST", injection_pointer="/billing/id")
        self.assertNotEqual(finding_dedup_key_for(f1), finding_dedup_key_for(f2))

    def test_shared_dedup_helper_form_unchanged(self):
        # form/url_param は従来の4部品キーのまま（回帰ゼロ）。
        f = Finding(
            check_type="sqli", severity="high", url="http://h/u",
            field_name="id", payload="'", evidence="err", evidence_type="sqli_error",
        )
        self.assertEqual(finding_dedup_key_for(f), ("http://h/u", "id", "sqli", "sqli_error"))

    def test_verify_injection_point_prefers_provenance_for_json(self):
        scanner = _Scanner(_Engine())
        json_finding = Finding(
            check_type="sqli", severity="high", url="http://h/login",
            field_name="email", payload="'", evidence="e",
            injection_location="json_body", injection_pointer="/email",
            injection_method="POST", injection_template_id="t",
        )
        # 推測は form(False) だが provenance が json_body を復元する。
        ip = scanner._verify_injection_point(json_finding, is_url_param=False)
        self.assertEqual(ip.location, "json_body")
        self.assertEqual(ip.parameter_id, "/email")
        self.assertEqual(ip.template_id, "t")

    def test_verify_injection_point_form_uses_form_index(self):
        scanner = _Scanner(_Engine())
        finding = Finding(
            check_type="sqli", severity="high", url="http://h/form",
            field_name="email", payload="'", evidence="e",
            injection_location="form", injection_form_index=3,
        )
        ip = scanner._verify_injection_point(finding, is_url_param=False)
        self.assertIsNotNone(ip)
        self.assertEqual(ip.location, "form")
        self.assertEqual(ip.form_index, 3)

    def test_verify_injection_point_url_param_from_provenance(self):
        scanner = _Scanner(_Engine())
        finding = Finding(
            check_type="sqli", severity="high", url="http://h/x",
            field_name="q", payload="'", evidence="e",
            injection_location="url_param",
        )
        ip = scanner._verify_injection_point(finding, is_url_param=False)
        self.assertIsNotNone(ip)
        self.assertEqual(ip.location, "url_param")

    def test_verify_injection_point_falls_back_to_guess_for_legacy(self):
        scanner = _Scanner(_Engine())
        legacy = Finding(
            check_type="sqli", severity="high", url="http://h/x?q=1",
            field_name="q", payload="'", evidence="e",  # provenance 無し
        )
        self.assertEqual(
            scanner._verify_injection_point(legacy, is_url_param=True).location, "url_param"
        )
        self.assertEqual(
            scanner._verify_injection_point(legacy, is_url_param=False).location, "form"
        )

    def test_verify_injection_point_unexecutable_on_invalid(self):
        # malformed = 非空だが '/' 始まりでない pointer（parse_pointer が ValueError）。
        scanner = _Scanner(_Engine())
        finding = Finding(
            check_type="sqli", severity="high", url="http://h/api",
            field_name="email", payload="'", evidence="e",
            injection_location="json_body", injection_pointer="not-a-pointer",
            injection_method="POST",
        )
        self.assertIsNone(
            scanner._verify_injection_point(finding, is_url_param=False)
        )

    def test_verify_injection_point_json_root_pointer_valid(self):
        # 空文字は RFC 6901 ルート pointer（whole-body 注入）で valid。unexecutable にしない。
        scanner = _Scanner(_Engine())
        finding = Finding(
            check_type="sqli", severity="high", url="http://h/api",
            field_name="body", payload="'", evidence="e",
            injection_location="json_body", injection_pointer="",
            injection_method="POST",
        )
        ip = scanner._verify_injection_point(finding, is_url_param=False)
        self.assertIsNotNone(ip)
        self.assertEqual(ip.location, "json_body")
        self.assertEqual(ip.parameter_id, "")

    async def test_engine_verify_uses_provenance_form_index(self):
        scanner = _VerifyScanner()
        engine = _VerifyEngine(scanner)
        finding = Finding(
            check_type="path_traversal", severity="high", url="http://h/form",
            field_name="path", payload="../etc/passwd", evidence="e",
            injection_location="form", injection_form_index=4,
        )

        self.assertTrue(await engine._verify_one(finding))
        self.assertEqual(len(scanner.applied_ips), 1)
        ip, payload = scanner.applied_ips[0]
        self.assertEqual(ip.location, "form")
        self.assertEqual(ip.form_index, 4)
        self.assertEqual(payload, finding.payload)

    async def test_engine_verify_does_not_resend_invalid_provenance(self):
        scanner = _VerifyScanner()
        engine = _VerifyEngine(scanner)
        finding = Finding(
            check_type="path_traversal", severity="high", url="http://h/form",
            field_name="path", payload="../etc/passwd", evidence="e",
            injection_location="bogus",
        )

        self.assertTrue(await engine._verify_one(finding))
        self.assertEqual(scanner.applied_ips, [])
        self.assertEqual(engine.browser.navigate_calls, [])

    def test_rebuilds_all_locations(self):
        json_finding = Finding(
            check_type="sqli",
            severity="high",
            url="http://h/login",
            field_name="email",
            payload="'",
            evidence="error",
            injection_location="json_body",
            injection_pointer="/email",
            injection_method="POST",
            injection_template_id="login-1",
        )
        ip = injection_point_from_finding(json_finding)
        self.assertIsNotNone(ip)
        self.assertEqual(ip.location, "json_body")
        self.assertEqual(ip.parameter_id, "/email")
        self.assertEqual(ip.template_id, "login-1")

        form_finding = Finding(
            check_type="sqli", severity="high", url="http://h/form",
            field_name="email", payload="'", evidence="error",
            injection_location="form", injection_form_index=2,
        )
        form_ip = injection_point_from_finding(form_finding)
        self.assertIsNotNone(form_ip)
        self.assertEqual(form_ip.location, "form")
        self.assertEqual(form_ip.form_index, 2)

        url_finding = Finding(
            check_type="sqli", severity="high", url="http://h/x?q=1",
            field_name="q", payload="'", evidence="error",
            injection_location="url_param",
        )
        url_ip = injection_point_from_finding(url_finding)
        self.assertIsNotNone(url_ip)
        self.assertEqual(url_ip.location, "url_param")

        legacy = Finding(
            check_type="sqli", severity="high", url="http://h/x",
            field_name="q", payload="'", evidence="error",
        )
        self.assertIsNone(injection_point_from_finding(legacy))

        legacy.injection_location = "bogus"
        with self.assertRaises(ProvenanceError):
            injection_point_from_finding(legacy)

        # 空文字 pointer = RFC 6901 ルート（whole-body 注入）で valid。復元できる。
        legacy.injection_location = "json_body"
        legacy.injection_pointer = ""
        root_ip = injection_point_from_finding(legacy)
        self.assertIsNotNone(root_ip)
        self.assertEqual(root_ip.location, "json_body")
        self.assertEqual(root_ip.parameter_id, "")

        legacy.injection_pointer = "not-a-pointer"
        with self.assertRaises(ProvenanceError):
            injection_point_from_finding(legacy)


if __name__ == "__main__":
    unittest.main()
