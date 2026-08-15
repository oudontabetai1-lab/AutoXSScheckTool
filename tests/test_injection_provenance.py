"""Finding の注入点 provenance に関する加算的テスト。"""
import unittest

from wscan.injection_point import InjectionPoint
from wscan.scanners.base import (
    BaseScanner,
    Finding,
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
