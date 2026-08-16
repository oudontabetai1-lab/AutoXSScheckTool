"""Finding の注入点 provenance に関する加算的テスト。"""
import unittest

from wscan.injection_point import InjectionPoint
from wscan.scanners.base import (
    BaseScanner,
    Finding,
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

    def test_rebuilds_json_body_only(self):
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
        self.assertEqual(ip.parameter_id, "/email")
        self.assertEqual(ip.template_id, "login-1")

        for location in ("", "form", "url_param"):
            json_finding.injection_location = location
            self.assertIsNone(injection_point_from_finding(json_finding))


if __name__ == "__main__":
    unittest.main()
