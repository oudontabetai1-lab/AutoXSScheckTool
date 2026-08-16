"""段階5b-1 サーバ応答型スキャナ移行の安全ツインテスト。"""
import inspect
import json
import unittest

import httpx

from wscan.injection_point import InjectionPoint
from wscan.scanners.base import BaseScanner
from wscan.scanners.deserialization import DeserializationScanner
from wscan.scanners.header_injection import CRLF_PAYLOADS, HeaderInjectionScanner
from wscan.scanners.ldap_injection import LDAPScanner
from wscan.scanners.os_injection import OSInjectionScanner
from wscan.scanners.path_traversal import PathTraversalScanner
from wscan.scanners.ssrf import SSRFScanner, _SSRF_PROBES
from wscan.scanners.ssti import SSTIScanner


_MIGRATED_SCANNERS = (
    HeaderInjectionScanner,
    LDAPScanner,
    PathTraversalScanner,
    OSInjectionScanner,
    SSTIScanner,
    SSRFScanner,
    DeserializationScanner,
)


class _PayloadGenerator:
    async def generate(self, **_kwargs):
        return ["../stage5b1-probe"]


class _RecordingBrowser:
    def __init__(self, response_headers=None):
        self.calls = []
        self.response_headers = response_headers or {}

    def _result(self):
        return "", {"response": {"headers": dict(self.response_headers)}}

    async def test_url_param(self, url, field_name, payload):
        self.calls.append(("test_url_param", url, field_name, payload))
        return self._result()

    async def navigate(self, url):
        self.calls.append(("navigate", url))
        return True

    async def fill_and_submit_form(self, form_index, field_name, payload):
        self.calls.append(
            ("fill_and_submit_form", form_index, field_name, payload)
        )
        return self._result()

    async def screenshot_b64(self, label=""):
        return ""


class _Engine:
    def __init__(self, browser=None, transport=None):
        self.browser = browser or _RecordingBrowser()
        self.monitor = None
        self.payload_gen = _PayloadGenerator()
        self.request_logger = None
        self.custom_payloads = {}
        self.sleep_factor = 0
        self.max_payloads = 0
        self.enable_payload_evolution = False
        self.enable_payload_mutation = False
        self._finding_dedup = set()
        self.all_findings = []
        self.injection_templates = {}
        self.timeout = 5
        self._transport = transport

    def httpx_client_kwargs(self, **kwargs):
        if self._transport is not None:
            kwargs["transport"] = self._transport
        return kwargs


class _UnsupportedScanner(BaseScanner):
    async def scan_field(self, url, form_index, field, is_url_param=False):
        return []

    async def _apply_payload(
        self, url, form_index, field_name, payload, is_url_param
    ):
        raise AssertionError("未対応 JSON を form/url_param へ落としてはならない")


class JsonBodyDoesNotCrashTests(unittest.IsolatedAsyncioTestCase):
    async def test_json_scan_does_not_hit_legacy_predicate(self):
        # SUPPORTS_JSON_BODY のスキャナに json_body ip を流しても、evolution wave の
        # ip.legacy_is_url_param() や ssrf の url-param 判定で ValueError にならない。
        # template 不在で _apply_json_payload は ("",{}) を返す → 検出なし → 例外なく [] を返す。
        for scanner_cls in (
            LDAPScanner,
            PathTraversalScanner,
            OSInjectionScanner,
            SSTIScanner,
            SSRFScanner,
        ):
            with self.subTest(scanner=scanner_cls.__name__):
                scanner = scanner_cls(_Engine())
                ip = InjectionPoint.for_json_body(
                    "POST", "http://h/api", "/url", template_id="missing"
                )
                findings = await scanner.scan_injection_point(
                    ip, {"name": "url", "type": "text"}
                )
                self.assertEqual(findings, [])


def _legacy_calls(ip: InjectionPoint, payloads: list[str]) -> list[tuple]:
    """移行前の uniform ``_apply_payload`` が作る呼出し列。"""
    if ip.legacy_is_url_param():
        return [
            ("test_url_param", ip.url, ip.parameter_id, payload)
            for payload in payloads
        ]

    calls = []
    for payload in payloads:
        calls.extend(
            [
                ("navigate", ip.url),
                (
                    "fill_and_submit_form",
                    ip.form_index,
                    ip.parameter_id,
                    payload,
                ),
            ]
        )
    return calls


class BrowserCallParityTests(unittest.IsolatedAsyncioTestCase):
    async def _assert_parity(self, scanner_cls, payloads):
        field = {"name": "target", "type": "text"}
        cases = (
            InjectionPoint.for_form("https://example.test/form", "target", 3),
            InjectionPoint.for_url_param(
                "https://example.test/search?target=old", "target"
            ),
        )

        for ip in cases:
            with self.subTest(scanner=scanner_cls.__name__, location=ip.location):
                browser = _RecordingBrowser()
                scanner = scanner_cls(_Engine(browser))

                findings = await scanner.scan_injection_point(ip, field)

                self.assertEqual(findings, [])
                self.assertEqual(browser.calls, _legacy_calls(ip, payloads))

    async def test_path_traversal_form_and_url_param_calls_match_legacy(self):
        await self._assert_parity(
            PathTraversalScanner,
            ["baseline_test_value", "../stage5b1-probe"],
        )

    async def test_ssrf_form_and_url_param_calls_match_legacy(self):
        await self._assert_parity(
            SSRFScanner,
            ["http://wscan-baseline-test.invalid/"]
            + [payload for _label, payload, _pattern in _SSRF_PROBES],
        )

    async def test_header_injection_form_and_url_param_calls_match_legacy(self):
        await self._assert_parity(HeaderInjectionScanner, list(CRLF_PAYLOADS))


class InjectionPointRoutingTests(unittest.IsolatedAsyncioTestCase):
    def test_all_seven_scanners_opt_in_to_json_body(self):
        for scanner_cls in _MIGRATED_SCANNERS:
            with self.subTest(scanner=scanner_cls.__name__):
                self.assertIs(scanner_cls.SUPPORTS_JSON_BODY, True)

    async def test_supported_json_body_uses_shared_transport(self):
        received = []

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            received.append(body)
            return httpx.Response(200, json={"received": body})

        engine = _Engine(transport=httpx.MockTransport(handler))
        engine.injection_templates["stage5b1"] = {
            "method": "POST",
            "url": "https://example.test/api/profile",
            "json_body": {"profile": {"name": "before"}},
            "content_type": "application/json",
        }
        scanner = HeaderInjectionScanner(engine)
        ip = InjectionPoint.for_json_body(
            "POST",
            "https://example.test/api/profile",
            "/profile/name",
            template_id="stage5b1",
        )

        source, pair = await scanner._apply_ip(ip, "stage5b1-marker")

        self.assertEqual(received, [{"profile": {"name": "stage5b1-marker"}}])
        self.assertEqual(json.loads(source)["received"], received[0])
        self.assertEqual(pair["request"]["method"], "POST")
        self.assertEqual(engine.browser.calls, [])

    async def test_unsupported_json_body_does_not_fall_through_to_form(self):
        scanner = _UnsupportedScanner(_Engine())
        ip = InjectionPoint.for_json_body(
            "POST", "https://example.test/api", "/name", template_id="unused"
        )

        self.assertEqual(await scanner._apply_ip(ip, "marker"), ("", {}))
        self.assertEqual(scanner.browser.calls, [])


class ProvenanceAndCompatibilityTests(unittest.IsolatedAsyncioTestCase):
    async def test_form_finding_stamps_location_and_form_index(self):
        browser = _RecordingBrowser(
            {"X-WscanHdrInject": "1"}
        )
        scanner = HeaderInjectionScanner(_Engine(browser))
        ip = InjectionPoint.for_form(
            "https://example.test/profile", "display_name", 4
        )

        findings = await scanner.scan_injection_point(
            ip, {"name": "display_name", "type": "text"}
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].injection_location, "form")
        self.assertEqual(findings[0].injection_form_index, 4)

    def test_apply_payload_signatures_remain_engine_verify_compatible(self):
        expected = [
            "self",
            "url",
            "form_index",
            "field_name",
            "payload",
            "is_url_param",
        ]
        for scanner_cls in _MIGRATED_SCANNERS:
            with self.subTest(scanner=scanner_cls.__name__):
                self.assertEqual(
                    list(inspect.signature(scanner_cls._apply_payload).parameters),
                    expected,
                )


if __name__ == "__main__":
    unittest.main()
