"""段階5b-2 特殊 transport/判定型スキャナ移行の安全ツインテスト。"""
import inspect
import unittest
from unittest.mock import AsyncMock

from wscan.injection_point import InjectionPoint
from wscan.scanners.base import Finding
from wscan.scanners.mail_header import MailHeaderInjectionScanner
from wscan.scanners.nosql_injection import (
    NoSQLInjectionScanner,
    _PARAM_PAYLOADS,
)
from wscan.scanners.open_redirect import (
    OpenRedirectScanner,
    REDIRECT_PAYLOADS,
    _CANARY_HOST,
)
from wscan.scanners.sqli import SQLiScanner


class _PayloadGenerator:
    async def generate(self, **_kwargs):
        # partner 再送も含めて SQLi の dispatch を確認できる payload。
        return ["1 AND 1=1"]


class _Page:
    def __init__(self):
        self.url = "https://example.test/current"


class _RecordingBrowser:
    def __init__(self, response_headers=None):
        self.calls = []
        self.response_headers = response_headers or {}
        self.page = _Page()

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
    def __init__(self, browser=None):
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


def _legacy_calls(
    ip: InjectionPoint,
    payloads: list[str],
    *,
    sqli_baseline_count: int = 0,
) -> list[tuple]:
    """移行前の ``_apply_payload`` / SQLi baseline が作る呼出し列。"""
    calls = []
    for index, payload in enumerate(payloads):
        if ip.location == "url_param":
            calls.append(
                ("test_url_param", ip.url, ip.parameter_id, payload)
            )
        elif index < sqli_baseline_count:
            # SQLi の旧 form baseline は再 navigate せず直接 submit する。
            calls.append(
                (
                    "fill_and_submit_form",
                    ip.form_index,
                    ip.parameter_id,
                    payload,
                )
            )
        else:
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
    async def test_sqli_form_and_url_param_calls_match_legacy(self):
        field = {"name": "target", "type": "text"}
        payloads = [
            "baseline_test",
            "baseline_test",
            "1 AND 1=1",
            "1 AND 1=2",
        ]
        cases = (
            InjectionPoint.for_form("https://example.test/form", "target", 3),
            InjectionPoint.for_url_param(
                "https://example.test/search?target=old", "target"
            ),
        )

        for ip in cases:
            with self.subTest(location=ip.location):
                browser = _RecordingBrowser()
                scanner = SQLiScanner(_Engine(browser))
                scanner.evolved_payloads = AsyncMock(return_value=[])
                scanner.mutated_payloads = AsyncMock(return_value=[])
                scanner.run_equivalence_probe = AsyncMock(return_value=None)

                findings = await scanner.scan_injection_point(ip, field)

                self.assertEqual(findings, [])
                self.assertEqual(
                    browser.calls,
                    _legacy_calls(ip, payloads, sqli_baseline_count=2),
                )

    async def test_nosql_form_and_url_param_calls_match_legacy(self):
        field = {"name": "target", "type": "text"}
        cases = (
            InjectionPoint.for_form("https://example.test/form", "target", 3),
            InjectionPoint.for_url_param(
                "https://example.test/search?target=old", "target"
            ),
        )

        for ip in cases:
            with self.subTest(location=ip.location):
                browser = _RecordingBrowser()
                scanner = NoSQLInjectionScanner(_Engine(browser))
                scanner.evolved_payloads = AsyncMock(return_value=[])
                scanner._test_json_body = AsyncMock(return_value=[])

                findings = await scanner.scan_injection_point(ip, field)

                self.assertEqual(findings, [])
                if ip.location == "url_param":
                    expected = _legacy_calls(
                        ip,
                        ["baseline_value_wscan", "baseline_value_wscan_2"],
                    )
                    expected.extend(
                        [
                            (
                                "test_url_param",
                                ip.url,
                                "target[$ne]",
                                "wscan_invalid",
                            )
                            for _payload in _PARAM_PAYLOADS
                        ]
                    )
                else:
                    expected = _legacy_calls(
                        ip,
                        [
                            "baseline_value_wscan",
                            "baseline_value_wscan_2",
                            *_PARAM_PAYLOADS,
                        ],
                    )
                self.assertEqual(browser.calls, expected)

    async def test_open_redirect_form_and_url_param_calls_match_legacy(self):
        field = {"name": "next", "type": "text"}
        cases = (
            InjectionPoint.for_form("https://example.test/form", "next", 3),
            InjectionPoint.for_url_param(
                "https://example.test/login?next=old", "next"
            ),
        )

        for ip in cases:
            with self.subTest(location=ip.location):
                browser = _RecordingBrowser()
                scanner = OpenRedirectScanner(_Engine(browser))

                findings = await scanner.scan_injection_point(ip, field)

                self.assertEqual(findings, [])
                self.assertEqual(
                    browser.calls,
                    _legacy_calls(ip, list(REDIRECT_PAYLOADS)),
                )


class InjectionPointRoutingTests(unittest.IsolatedAsyncioTestCase):
    def test_json_body_capability_matrix(self):
        self.assertIs(SQLiScanner.SUPPORTS_JSON_BODY, True)
        # nosql は構造化オペレータ戦略(PR-b)が要るため 5b では json 未対応。
        self.assertIs(NoSQLInjectionScanner.SUPPORTS_JSON_BODY, False)
        self.assertIs(MailHeaderInjectionScanner.SUPPORTS_JSON_BODY, False)
        self.assertIs(OpenRedirectScanner.SUPPORTS_JSON_BODY, False)

    async def test_supported_json_body_uses_shared_transport(self):
        ip = InjectionPoint.for_json_body(
            "POST",
            "https://example.test/api",
            "/target",
            template_id="stage5b2",
        )
        for scanner_cls in (SQLiScanner,):
            with self.subTest(scanner=scanner_cls.__name__):
                scanner = scanner_cls(_Engine())
                scanner._apply_json_payload = AsyncMock(
                    return_value=("json-response", {"request": {"method": "POST"}})
                )

                result = await scanner._apply_ip(ip, "stage5b2-marker")

                self.assertEqual(
                    result,
                    ("json-response", {"request": {"method": "POST"}}),
                )
                scanner._apply_json_payload.assert_awaited_once_with(
                    ip, "stage5b2-marker"
                )

    async def test_unsupported_json_body_is_guarded(self):
        ip = InjectionPoint.for_json_body(
            "POST",
            "https://example.test/api",
            "/email",
            template_id="unused",
        )
        cases = (
            (MailHeaderInjectionScanner, {"name": "email", "type": "email"}),
            (OpenRedirectScanner, {"name": "next", "type": "text"}),
            (NoSQLInjectionScanner, {"name": "target", "type": "text"}),
        )
        for scanner_cls, field in cases:
            with self.subTest(scanner=scanner_cls.__name__):
                scanner = scanner_cls(_Engine())
                scanner._apply_payload = AsyncMock(
                    side_effect=AssertionError("JSON を browser transport へ落とした")
                )
                if isinstance(scanner, MailHeaderInjectionScanner):
                    scanner._apply_payload_raw = AsyncMock(
                        side_effect=AssertionError("JSON で raw HTTP を送信した")
                    )

                self.assertEqual(await scanner._apply_ip(ip, "marker"), ("", {}))
                self.assertEqual(
                    await scanner.scan_injection_point(ip, field),
                    [],
                )
                scanner._apply_payload.assert_not_awaited()
                if isinstance(scanner, MailHeaderInjectionScanner):
                    scanner._apply_payload_raw.assert_not_awaited()

    async def test_supported_json_scan_does_not_crash(self):
        ip = InjectionPoint.for_json_body(
            "POST",
            "https://example.test/api",
            "/target",
            template_id="missing",
        )
        for scanner_cls in (SQLiScanner,):
            with self.subTest(scanner=scanner_cls.__name__):
                scanner = scanner_cls(_Engine())
                findings = await scanner.scan_injection_point(
                    ip, {"name": "target", "type": "text"}
                )
                self.assertEqual(findings, [])

    async def test_supported_json_verify_restores_provenance(self):
        finding_kwargs = {
            "severity": "high",
            "url": "https://example.test/api",
            "field_name": "target",
            "payload": "stage5b2-probe",
            "evidence": "test",
            "injection_location": "json_body",
            "injection_pointer": "/profile/target",
            "injection_method": "POST",
            "injection_template_id": "stage5b2",
        }

        sqli = SQLiScanner(_Engine())
        sqli._apply_json_payload = AsyncMock(
            return_value=(
                "You have an error in your SQL syntax",
                {"response": {"body": "You have an error in your SQL syntax"}},
            )
        )
        sqli_finding = Finding(
            check_type="sqli",
            evidence_type="sqli_error",
            **finding_kwargs,
        )
        self.assertTrue(await sqli.verify_finding(sqli_finding))
        restored_ip = sqli._apply_json_payload.await_args.args[0]
        self.assertEqual(restored_ip.parameter_id, "/profile/target")


class ProvenanceAndCompatibilityTests(unittest.IsolatedAsyncioTestCase):
    def test_transport_signatures_remain_engine_verify_compatible(self):
        expected = [
            "self",
            "url",
            "form_index",
            "field_name",
            "payload",
            "is_url_param",
        ]
        for scanner_cls in (
            SQLiScanner,
            NoSQLInjectionScanner,
            MailHeaderInjectionScanner,
            OpenRedirectScanner,
        ):
            with self.subTest(scanner=scanner_cls.__name__):
                self.assertEqual(
                    list(inspect.signature(scanner_cls._apply_payload).parameters),
                    expected,
                )
        self.assertEqual(
            list(
                inspect.signature(
                    MailHeaderInjectionScanner._apply_payload_raw
                ).parameters
            ),
            expected,
        )

    async def test_form_finding_stamps_location_and_form_index(self):
        browser = _RecordingBrowser(
            {"Location": f"https://{_CANARY_HOST}/landing"}
        )
        scanner = OpenRedirectScanner(_Engine(browser))
        ip = InjectionPoint.for_form(
            "https://example.test/login", "next", 4
        )

        findings = await scanner.scan_injection_point(
            ip, {"name": "next", "type": "text"}
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].injection_location, "form")
        self.assertEqual(findings[0].injection_form_index, 4)


if __name__ == "__main__":
    unittest.main()
