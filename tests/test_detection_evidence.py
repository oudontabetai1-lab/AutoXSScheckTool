import unittest
from unittest.mock import AsyncMock, patch

import httpx

from wscan.browser import NetworkCapture
from wscan.ctf_flag_finder import FlagFinder
from wscan.engine import ScanEngine
from wscan.payload_gen import PayloadGenerator, _format_prompt_template
from wscan.scanners.base import BaseScanner, Finding, finding_dedup_key_for
from wscan.scanners.cors import CORSScanner
from wscan.scanners.deserialization import DeserializationScanner
from wscan.scanners.dom_xss import DOMXSSScanner
from wscan.scanners.file_upload import FileUploadScanner
from wscan.scanners.graphql import GraphQLScanner
from wscan.scanners.header_injection import HeaderInjectionScanner
from wscan.scanners.host_header import HostHeaderScanner
from wscan.scanners.info_disclosure import InfoDisclosureScanner
from wscan.scanners.jwt_scanner import JWTScanner, _build_jwt
from wscan.scanners.ldap_injection import LDAPScanner
from wscan.scanners.nosql_injection import NoSQLInjectionScanner
from wscan.scanners.open_redirect import OpenRedirectScanner
from wscan.scanners.os_injection import OSInjectionScanner
from wscan.scanners.path_traversal import PathTraversalScanner
from wscan.scanners.race_condition import RaceConditionScanner
from wscan.scanners.request_smuggling import RequestSmugglingScanner
from wscan.scanners.security_headers import SecurityHeadersScanner
from wscan.scanners.session import SessionScanner
from wscan.scanners.sqli import SQLiScanner
from wscan.scanners.ssrf import SSRFScanner
from wscan.scanners.ssti import SSTIScanner
from wscan.scanners.stored_xss import StoredXSSScanner
from wscan.scanners.websocket import WebSocketScanner
from wscan.scanners.xss import XSSScanner
from wscan.scanners.xxe import XXEScanner


class _DummyBrowser:
    async def screenshot_b64(self, label=""):
        return ""


class _DummyEngine:
    def __init__(self):
        self.browser = _DummyBrowser()
        self.monitor = None
        self.payload_gen = None
        self._finding_dedup = set()
        self.all_findings = []
        self.checks = []


class _DummyScanner(BaseScanner):
    CHECK_TYPE = "xss"

    async def scan_field(self, url, form_index, field, is_url_param=False):
        return []


class _VerifierBrowser:
    def __init__(self, baseline_html=""):
        self.dialog_fired = False
        self.page = type(
            "Page",
            (),
            {"content": AsyncMock(return_value=baseline_html)},
        )()
        self.navigate = AsyncMock(return_value=True)

    def reset_dialog(self):
        self.dialog_fired = False


class _DomVerifierPage:
    def __init__(self, log):
        self._log = log
        self.add_init_script = AsyncMock()
        self.evaluate = AsyncMock(return_value=log)


class _DomVerifierBrowser:
    def __init__(self, log=None, dialog_message=""):
        self.dialog_fired = bool(dialog_message)
        self.dialog_message = dialog_message
        self.page = _DomVerifierPage(log or [])
        self.test_url_param = AsyncMock(return_value=("", {}))
        self.navigate = AsyncMock(return_value=True)
        self.fill_and_submit_form = AsyncMock(return_value=("", {}))

    def reset_dialog(self):
        self.dialog_fired = bool(self.dialog_message)


class _StoredVerifierPage:
    def __init__(self, title="", url=""):
        self.url = url
        self.title = AsyncMock(return_value=title)


class _StoredVerifierBrowser:
    def __init__(self, html="", title="", dialog_message="", url=""):
        self._html = html
        self.dialog_fired = bool(dialog_message)
        self.dialog_message = dialog_message
        self.page = _StoredVerifierPage(title, url)
        self.test_url_param = AsyncMock(return_value=("", {}))
        self.navigate = AsyncMock(return_value=True)
        self.fill_and_submit_form = AsyncMock(return_value=("", {}))
        self.get_page_source = AsyncMock(return_value=html)

    def reset_dialog(self):
        self.dialog_fired = bool(self.dialog_message)


class _StoredScanPage:
    def __init__(self, url="", html=""):
        self.url = url
        self._html = html
        self.content = AsyncMock(side_effect=lambda: self._html)


class _StoredScanBrowser:
    def __init__(self, url="", html=""):
        self.page = _StoredScanPage(url, html)
        self.navigate = AsyncMock(side_effect=self._navigate)
        self.screenshot_b64 = AsyncMock(return_value="")

    async def _navigate(self, url):
        self.page.url = url
        self.page._html = "<html><body>safe target page</body></html>"
        return True


class _CookieContext:
    def __init__(self, cookies):
        self.cookies = AsyncMock(return_value=cookies)


class _CookieBrowser:
    def __init__(self, cookies):
        self._context = _CookieContext(cookies)


class DetectionEvidenceTests(unittest.TestCase):
    def test_finding_serializes_structured_evidence(self):
        finding = Finding(
            check_type="xss",
            severity="high",
            url="http://example.test/search?q=x",
            field_name="q",
            payload="<svg onload=alert(1)>",
            evidence="reflected in script context",
            confidence="likely",
            evidence_type="xss_reflection",
            evidence_details={"context": "script", "raw_payload_present": True},
            reproduction_steps=["Open page", "Submit payload"],
        )

        data = finding.to_dict()

        self.assertEqual(data["evidence_type"], "xss_reflection")
        self.assertEqual(data["evidence_details"]["context"], "script")
        self.assertEqual(data["reproduction_steps"], ["Open page", "Submit payload"])

    def test_finding_source_defaults_and_round_trips_backwards_compatibly(self):
        legacy = Finding.from_dict({
            "check_type": "xss",
            "severity": "high",
            "url": "http://example.test/",
            "field_name": "q",
            "payload": "<svg/onload=alert(1)>",
            "evidence": "legacy finding",
        })
        self.assertEqual(legacy.source, "scanner")
        self.assertFalse(legacy.agent_verified)
        self.assertEqual(legacy.verification_state, "")

        agent = Finding(
            check_type="xss",
            severity="high",
            url="http://example.test/",
            field_name="q",
            payload="<svg/onload=alert(1)>",
            evidence="agent finding",
            source="agent",
            agent_verified=True,
        )
        restored = Finding.from_dict(agent.to_dict())
        self.assertEqual(restored.source, "agent")
        self.assertTrue(restored.agent_verified)

    def test_finding_verification_state_round_trips(self):
        finding = Finding(
            check_type="sqli",
            severity="critical",
            url="http://example.test/login",
            field_name="username",
            payload="'",
            evidence="SQL error",
            verification_state="assumed",
        )

        data = finding.to_dict()
        restored = Finding.from_dict(data)

        self.assertEqual(data["verification_state"], "assumed")
        self.assertEqual(restored.verification_state, "assumed")

    def test_dedup_key_preserves_distinct_evidence_types_on_same_input(self):
        finding = Finding(
            check_type="sqli",
            severity="critical",
            url="http://fixture.test/login",
            field_name="username",
            payload="'",
            evidence="SQL error",
            evidence_type="sqli_error",
        )
        auth_finding = Finding(
            check_type="sqli",
            severity="critical",
            url="http://fixture.test/login",
            field_name="username",
            payload="' OR '1'='1",
            evidence="Auth bypass",
            evidence_type="sqli_auth_bypass",
        )

        self.assertNotEqual(
            finding_dedup_key_for(finding),
            finding_dedup_key_for(auth_finding),
        )

    def test_record_finding_dedups_exact_evidence_only(self):
        async def run():
            engine = _DummyEngine()
            scanner = _DummyScanner(engine)
            pair = {"request": {}, "response": {"body": "payload"}}

            first = await scanner.record_finding(
                "http://fixture.test/search",
                "q",
                "<script>alert(1)</script>",
                "Dialog fired",
                pair,
                evidence_type="xss_dialog",
            )
            duplicate = await scanner.record_finding(
                "http://fixture.test/search",
                "q",
                "<script>alert(1)</script>",
                "Dialog fired again",
                pair,
                evidence_type="xss_dialog",
            )
            reflected = await scanner.record_finding(
                "http://fixture.test/search",
                "q",
                "<b>wscan</b>",
                "Reflected text",
                pair,
                evidence_type="xss_reflection",
            )

            self.assertIsNotNone(first)
            self.assertIsNone(duplicate)
            self.assertIsNotNone(reflected)
            self.assertEqual(len(engine.all_findings), 2)

        self.run_async(run())

    def test_xss_reflection_context_marks_script_as_likely(self):
        scanner = object.__new__(XSSScanner)
        payload = '";alert(1);//'
        source = f"<html><script>const q = \"{payload}\";</script></html>"

        reflection = scanner._analyze_reflection(source, payload)

        self.assertEqual(reflection["context"], "script")
        self.assertEqual(reflection["confidence"], "likely")
        self.assertTrue(reflection["raw_payload_present"])

    def test_xss_reflection_context_marks_text_as_tentative(self):
        scanner = object.__new__(XSSScanner)
        payload = "<b>wscan</b>"
        source = f"<html><body>Search: {payload}</body></html>"

        reflection = scanner._analyze_reflection(source, payload)

        self.assertEqual(reflection["context"], "html_text")
        self.assertEqual(reflection["confidence"], "tentative")

    def test_xss_verifier_resets_stale_dialog_state(self):
        async def run():
            scanner = XSSScanner(_DummyEngine())
            scanner.browser = _VerifierBrowser("<html>baseline</html>")
            scanner.browser.dialog_fired = True
            scanner._apply_payload = AsyncMock(return_value=("<html>no payload</html>", {}))
            finding = Finding(
                check_type="xss",
                severity="critical",
                url="http://fixture.test/search?q=x",
                field_name="q",
                payload="<script>alert(1)</script>",
                evidence="dialog fired",
                evidence_type="xss_dialog",
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_xss_verifier_uses_baseline_for_reflection(self):
        async def run():
            payload = "<svg onload=alert(1)>"
            html = f"<html><body>{payload}</body></html>"
            scanner = XSSScanner(_DummyEngine())
            scanner.browser = _VerifierBrowser(html)
            scanner._apply_payload = AsyncMock(return_value=(html, {}))
            finding = Finding(
                check_type="xss",
                severity="high",
                url="http://fixture.test/search?q=x",
                field_name="q",
                payload=payload,
                evidence="reflected",
                evidence_type="xss_reflection",
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_nosql_boolean_verifier_requires_baseline_delta(self):
        async def run():
            scanner = NoSQLInjectionScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(side_effect=[
                ("A" * 1000, {}),
                ("A" * 1000, {}),
                ("A" * 1200, {}),
            ])
            finding = Finding(
                check_type="nosql",
                severity="high",
                url="http://fixture.test/nosql-login",
                field_name="username",
                payload='{"$ne": ""}',
                evidence="NoSQL boolean",
                evidence_type="nosql_boolean",
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_nosql_boolean_verifier_confirms_large_replay_delta(self):
        async def run():
            scanner = NoSQLInjectionScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(side_effect=[
                ("A" * 1000, {}),
                ("A" * 1005, {}),
                ("B" * 1800, {}),
            ])
            finding = Finding(
                check_type="nosql",
                severity="high",
                url="http://fixture.test/nosql-login",
                field_name="username",
                payload='{"$ne": ""}',
                evidence="NoSQL boolean",
                evidence_type="nosql_boolean",
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)

        self.run_async(run())

    def test_nosql_error_verifier_rejects_preexisting_error(self):
        async def run():
            scanner = NoSQLInjectionScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(side_effect=[
                ("MongoServerError: preexisting", {}),
                ("MongoServerError: preexisting", {}),
                ("MongoServerError: preexisting", {}),
            ])
            finding = Finding(
                check_type="nosql",
                severity="high",
                url="http://fixture.test/nosql-login",
                field_name="username",
                payload='{"$ne": ""}',
                evidence="NoSQL error",
                evidence_type="nosql_error",
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_ssrf_verifier_rejects_preexisting_marker(self):
        async def run():
            scanner = SSRFScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(side_effect=[
                ("instance-id already present", {}),
                ("instance-id already present", {}),
            ])
            finding = Finding(
                check_type="ssrf",
                severity="critical",
                url="http://fixture.test/fetch?url=http://example.test/",
                field_name="url",
                payload="http://169.254.169.254/latest/meta-data/",
                evidence="SSRF marker",
                evidence_type="ssrf_internal_marker",
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_ssrf_verifier_confirms_probe_only_marker(self):
        async def run():
            scanner = SSRFScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(side_effect=[
                ("Fetched public resource", {}),
                ("instance-id\ni-1234567890abcdef0", {}),
            ])
            finding = Finding(
                check_type="ssrf",
                severity="critical",
                url="http://fixture.test/fetch?url=http://example.test/",
                field_name="url",
                payload="http://169.254.169.254/latest/meta-data/",
                evidence="SSRF marker",
                evidence_type="ssrf_internal_marker",
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)

        self.run_async(run())

    def test_ssrf_verifier_rejects_reflected_probe_url(self):
        # プローブURL自体に含まれるマーカー語（GCP の computeMetadata 等）を
        # そのまま反射するだけの無害なページを SSRF と確証しないこと。
        async def run():
            scanner = SSRFScanner(_DummyEngine())
            gcp = "http://metadata.google.internal/computeMetadata/v1/"
            scanner._apply_payload = AsyncMock(side_effect=[
                ("You searched for: http://wscan-baseline-test.invalid/", {}),
                (f"<p>You searched for: {gcp}</p>", {}),  # ペイロードの純粋反射
            ])
            finding = Finding(
                check_type="ssrf",
                severity="critical",
                url="http://fixture.test/search?q=x",
                field_name="q",
                payload=gcp,
                evidence="SSRF marker",
                evidence_type="ssrf_internal_marker",
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_deserialization_verifier_rejects_preexisting_error(self):
        async def run():
            scanner = DeserializationScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(side_effect=[
                ("unserialize() already failing", {}),
                ("unserialize() already failing", {}),
            ])
            finding = Finding(
                check_type="deserialization",
                severity="critical",
                url="http://fixture.test/deserialize",
                field_name="data",
                payload='O:1:"A":1:{s:1:"a";R:99999999;}',
                evidence="deserialization error",
                evidence_type="deserialization_error",
                evidence_details={
                    "probe_id": "php_serialize_malformed",
                    "transport": "field",
                },
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_deserialization_verifier_confirms_probe_only_error(self):
        async def run():
            scanner = DeserializationScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(side_effect=[
                ("Loaded safe serialized value", {}),
                ("PHP Warning: unserialize(): Error at offset 12", {}),
            ])
            finding = Finding(
                check_type="deserialization",
                severity="critical",
                url="http://fixture.test/deserialize",
                field_name="data",
                payload='O:1:"A":1:{s:1:"a";R:99999999;}',
                evidence="deserialization error",
                evidence_type="deserialization_error",
                evidence_details={
                    "probe_id": "php_serialize_malformed",
                    "transport": "field",
                },
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)

        self.run_async(run())

    def test_ldap_verifier_rejects_preexisting_error(self):
        async def run():
            scanner = LDAPScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(side_effect=[
                ("javax.naming.NamingException: bad search filter", {}),
                ("javax.naming.NamingException: bad search filter", {}),
            ])
            finding = Finding(
                check_type="ldap",
                severity="high",
                url="http://fixture.test/ldap-login",
                field_name="username",
                payload=")(invalid",
                evidence="LDAP error",
                evidence_type="ldap_error",
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_ldap_verifier_confirms_probe_only_bypass(self):
        async def run():
            scanner = LDAPScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(side_effect=[
                ("invalid login", {}),
                ("Authenticated admin panel", {}),
            ])
            finding = Finding(
                check_type="ldap",
                severity="high",
                url="http://fixture.test/ldap-login",
                field_name="username",
                payload="*))(|(objectClass=*",
                evidence="LDAP auth bypass",
                evidence_type="ldap_auth_bypass",
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)

        self.run_async(run())

    def test_xxe_verifier_rejects_preexisting_file_marker(self):
        async def run():
            payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
            scanner = XXEScanner(_DummyEngine())
            scanner._post_xml = AsyncMock(side_effect=[
                ("root:x:0:0:root:/root:/bin/bash", 200, 0.01),
                ("root:x:0:0:root:/root:/bin/bash", 200, 0.01),
            ])
            finding = Finding(
                check_type="xxe",
                severity="high",
                url="http://fixture.test/xml",
                field_name="xml",
                payload=payload,
                evidence="XXE file read",
                evidence_type="xxe_file_read",
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_xxe_verifier_confirms_probe_only_file_marker(self):
        async def run():
            payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
            scanner = XXEScanner(_DummyEngine())
            scanner._post_xml = AsyncMock(side_effect=[
                ("XML import accepted", 200, 0.01),
                ("root:x:0:0:root:/root:/bin/bash", 200, 0.01),
            ])
            finding = Finding(
                check_type="xxe",
                severity="high",
                url="http://fixture.test/xml",
                field_name="xml",
                payload=payload,
                evidence="XXE file read",
                evidence_type="xxe_file_read",
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)

        self.run_async(run())

    def test_file_upload_verifier_replays_dangerous_filename(self):
        async def run():
            scanner = FileUploadScanner(_DummyEngine())
            scanner._upload_file = AsyncMock(
                return_value=(
                    "uploaded and executed: wscan-probe-8.2",
                    200,
                    {"request": {}, "response": {}},
                )
            )
            finding = Finding(
                check_type="file_upload",
                severity="critical",
                url="http://fixture.test/upload",
                field_name="file",
                payload="wscan_probe.php",
                evidence="upload executed",
                evidence_type="file_upload_executable",
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)

        self.run_async(run())

    def test_file_upload_verifier_rejects_changed_response(self):
        async def run():
            scanner = FileUploadScanner(_DummyEngine())
            scanner._upload_file = AsyncMock(
                return_value=(
                    "rejected extension",
                    400,
                    {"request": {}, "response": {}},
                )
            )
            finding = Finding(
                check_type="file_upload",
                severity="critical",
                url="http://fixture.test/upload",
                field_name="file",
                payload="wscan_probe.php",
                evidence="upload executed",
                evidence_type="file_upload_executable",
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_race_condition_verifier_replays_burst(self):
        async def run():
            class Resp:
                def __init__(self, text):
                    self.text = text

            scanner = RaceConditionScanner(_DummyEngine())
            scanner._send_burst = AsyncMock(return_value=[
                Resp("success coupon accepted"),
                Resp("success coupon accepted"),
                Resp("already redeemed"),
            ])
            finding = Finding(
                check_type="race_condition",
                severity="high",
                url="http://fixture.test/coupon/apply",
                field_name="coupon",
                payload="8x simultaneous POST requests",
                evidence="race",
                evidence_type="race_condition_burst",
                evidence_details={
                    "method": "POST",
                    "body": "coupon=SAVE100",
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                },
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)

        self.run_async(run())

    def test_race_condition_verifier_rejects_no_success(self):
        async def run():
            class Resp:
                def __init__(self, text):
                    self.text = text

            scanner = RaceConditionScanner(_DummyEngine())
            scanner._send_burst = AsyncMock(return_value=[
                Resp("already redeemed"),
                Resp("already redeemed"),
                Resp("already redeemed"),
            ])
            finding = Finding(
                check_type="race_condition",
                severity="high",
                url="http://fixture.test/coupon/apply",
                field_name="coupon",
                payload="8x simultaneous POST requests",
                evidence="race",
                evidence_type="race_condition_burst",
                evidence_details={
                    "method": "POST",
                    "body": "coupon=SAVE100",
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                },
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_race_condition_verifier_rejects_single_success_with_duplicates(self):
        async def run():
            class Resp:
                def __init__(self, text):
                    self.text = text

            scanner = RaceConditionScanner(_DummyEngine())
            scanner._send_burst = AsyncMock(return_value=[
                Resp("success coupon accepted"),
                Resp("already redeemed"),
                Resp("already redeemed"),
            ])
            finding = Finding(
                check_type="race_condition",
                severity="high",
                url="http://fixture.test/coupon/apply",
                field_name="coupon",
                payload="8x simultaneous POST requests",
                evidence="race",
                evidence_type="race_condition_burst",
                evidence_details={
                    "method": "POST",
                    "body": "coupon=SAVE100",
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                },
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_request_smuggling_verifier_replays_timing_indicator(self):
        async def run():
            scanner = RequestSmugglingScanner(_DummyEngine())
            scanner._measure_normal = AsyncMock(return_value=0.1)
            scanner._send_probe = AsyncMock(return_value=(10.0, "", 0))
            finding = Finding(
                check_type="request_smuggling",
                severity="high",
                url="http://fixture.test/",
                field_name="(HTTP request headers)",
                payload="CL.TE",
                evidence="timing",
                evidence_type="request_smuggling_timing",
                evidence_details={"probe_name": "CL.TE"},
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)

        self.run_async(run())

    def test_request_smuggling_verifier_rejects_unreproduced_indicator(self):
        async def run():
            scanner = RequestSmugglingScanner(_DummyEngine())
            scanner._measure_normal = AsyncMock(return_value=0.1)
            scanner._send_probe = AsyncMock(return_value=(0.2, "OK", 200))
            finding = Finding(
                check_type="request_smuggling",
                severity="high",
                url="http://fixture.test/",
                field_name="(HTTP request headers)",
                payload="CL.TE",
                evidence="timing",
                evidence_type="request_smuggling_timing",
                evidence_details={"probe_name": "CL.TE"},
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_request_smuggling_parser_error_records_tentative_evidence(self):
        scanner = RequestSmugglingScanner(_DummyEngine())

        classified = scanner._classify_probe(
            "http://fixture.test/",
            {"Transfer-Encoding": "chunked"},
            "CL.TE",
            0.1,
            0.2,
            "400 Bad Request: invalid chunk",
            400,
        )

        self.assertEqual(classified[0], "request_smuggling_parser_error")
        self.assertEqual(classified[1], "medium")

    def test_websocket_check_enables_websocket_payloads(self):
        engine = _DummyEngine()
        engine.checks = ["websocket"]
        scanner = WebSocketScanner(engine)

        payloads = scanner._active_payloads()

        self.assertGreaterEqual(len(payloads), 4)
        self.assertIn("xss", {entry[0] for entry in payloads})
        self.assertIn("ssti", {entry[0] for entry in payloads})

    def test_websocket_verifier_replays_ws_probe(self):
        async def run():
            engine = _DummyEngine()
            engine.checks = ["websocket"]
            scanner = WebSocketScanner(engine)
            scanner._send_ws_message = AsyncMock(return_value=["template result: 49"])
            finding = Finding(
                check_type="websocket",
                severity="high",
                url="http://fixture.test/ws-lab",
                field_name="ws:message",
                payload='{"message": "{{7*7}}"}',
                evidence="ws ssti",
                evidence_type="websocket_ssti_eval",
                evidence_details={
                    "ws_url": "ws://fixture.test/ws/echo",
                    "pattern": "49",
                    "sent": '{"message": "{{7*7}}"}',
                },
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)

        self.run_async(run())

    def test_websocket_verifier_rejects_unmatched_replay(self):
        async def run():
            engine = _DummyEngine()
            engine.checks = ["websocket"]
            scanner = WebSocketScanner(engine)
            scanner._send_ws_message = AsyncMock(return_value=["unchanged"])
            finding = Finding(
                check_type="websocket",
                severity="high",
                url="http://fixture.test/ws-lab",
                field_name="ws:message",
                payload='{"message": "{{7*7}}"}',
                evidence="ws ssti",
                evidence_type="websocket_ssti_eval",
                evidence_details={
                    "ws_url": "ws://fixture.test/ws/echo",
                    "pattern": "49",
                    "sent": '{"message": "{{7*7}}"}',
                },
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_graphql_verifier_confirms_introspection(self):
        async def run():
            scanner = GraphQLScanner(_DummyEngine())
            scanner._fetch_schema = AsyncMock(return_value={"types": [{"name": "Query"}]})
            finding = Finding(
                check_type="graphql_introspection",
                severity="medium",
                url="http://fixture.test/graphql",
                field_name="(GraphQL introspection)",
                payload="introspection",
                evidence="schema",
                evidence_type="graphql_introspection",
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)

        self.run_async(run())

    def test_graphql_verifier_rejects_unmatched_injection_replay(self):
        async def run():
            scanner = GraphQLScanner(_DummyEngine())
            scanner._post_json = AsyncMock(return_value=(200, '{"data":{"search":"clean"}}'))
            finding = Finding(
                check_type="graphql_injection",
                severity="high",
                url="http://fixture.test/graphql",
                field_name="Query.search(query)",
                payload="{{7*7}}",
                evidence="ssti",
                request={
                    "url": "http://fixture.test/graphql",
                    "method": "POST",
                    "body": '{"query":"{ search(query: \\"{{7*7}}\\") }"}',
                },
                evidence_type="graphql_injection_ssti",
                evidence_details={"vuln_type": "ssti", "expected": "49"},
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_graphql_injection_classifier_detects_sqli_errors(self):
        scanner = GraphQLScanner(_DummyEngine())

        matched, expected = scanner._classify_injection_response(
            "sqli",
            "' OR 1=1--",
            '{"errors":[{"message":"sqlite syntax error near injected query"}]}',
        )

        self.assertTrue(matched)
        self.assertIn(expected.lower(), {"sqlite", "syntax", "sql"})

    def test_engine_routes_graphql_subtype_to_graphql_verifier(self):
        async def run():
            engine = ScanEngine(
                "http://fixture.test/",
                checks=["graphql"],
                llm_provider="none",
                open_report=False,
                enable_waf_detection=False,
                enable_ai_analysis=False,
                enable_payload_learning=False,
                enable_adaptive_payloads=False,
            )
            scanner = engine.scanners["graphql"]
            scanner.verify_finding = AsyncMock(return_value=True)
            finding = Finding(
                check_type="graphql_batch",
                severity="low",
                url="http://fixture.test/graphql",
                field_name="(GraphQL batch)",
                payload="[]",
                evidence="batch",
            )

            result = await engine._verify_one(finding)

            self.assertEqual(result, "reproduced")
            scanner.verify_finding.assert_awaited_once()

        self.run_async(run())

    def test_jwt_verifier_confirms_no_expiry_and_sensitive_claims(self):
        async def run():
            token = _build_jwt(
                {"alg": "HS256", "typ": "JWT"},
                {"sub": "user", "api_key": "secret-value"},
                secret="secret",
            )
            scanner = JWTScanner(_DummyEngine())
            no_exp = Finding(
                check_type="jwt_no_expiry",
                severity="medium",
                url="http://fixture.test/jwt-lab",
                field_name="JWT",
                payload=token,
                evidence="no exp",
                evidence_details={"token": token},
            )
            sensitive = Finding(
                check_type="jwt_sensitive_data",
                severity="medium",
                url="http://fixture.test/jwt-lab",
                field_name="JWT payload",
                payload=token,
                evidence="api_key",
                evidence_details={"token": token, "sensitive_keys": ["api_key"]},
            )

            self.assertTrue(await scanner.verify_finding(no_exp))
            self.assertTrue(await scanner.verify_finding(sensitive))

        self.run_async(run())

    def test_jwt_verifier_rejects_expiring_token_for_no_expiry(self):
        async def run():
            token = _build_jwt(
                {"alg": "HS256", "typ": "JWT"},
                {"sub": "user", "exp": 2000000000},
                secret="secret",
            )
            scanner = JWTScanner(_DummyEngine())
            finding = Finding(
                check_type="jwt_no_expiry",
                severity="medium",
                url="http://fixture.test/jwt-lab",
                field_name="JWT",
                payload=token,
                evidence="no exp",
                evidence_details={"token": token},
            )

            self.assertFalse(await scanner.verify_finding(finding))

        self.run_async(run())

    def test_jwt_weak_secret_verifier_checks_signature(self):
        async def run():
            token = _build_jwt(
                {"alg": "HS256", "typ": "JWT"},
                {"sub": "user"},
                secret="secret",
            )
            scanner = JWTScanner(_DummyEngine())
            finding = Finding(
                check_type="jwt_weak_secret",
                severity="high",
                url="http://fixture.test/jwt-lab",
                field_name="JWT",
                payload="secret='secret'",
                evidence="weak",
                evidence_details={"token": token, "secret": "secret"},
            )

            self.assertTrue(await scanner.verify_finding(finding))

        self.run_async(run())

    def test_cors_verifier_replays_origin_reflection(self):
        async def run():
            scanner = CORSScanner(_DummyEngine())
            response = type(
                "Resp",
                (),
                {"headers": {
                    "access-control-allow-origin": "https://evil.wscan-test.example.com",
                    "access-control-allow-credentials": "true",
                }},
            )()
            scanner._get_with_origin = AsyncMock(return_value=response)
            finding = Finding(
                check_type="cors",
                severity="critical",
                url="http://fixture.test/cors-reflect",
                field_name="(CORS: Origin header)",
                payload="Origin: https://evil.wscan-test.example.com",
                evidence="origin reflected",
                evidence_type="cors_origin_reflection",
                evidence_details={
                    "origin": "https://evil.wscan-test.example.com",
                    "acac": "true",
                },
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)

        self.run_async(run())

    def test_cors_verifier_rejects_missing_reflection(self):
        async def run():
            scanner = CORSScanner(_DummyEngine())
            response = type("Resp", (), {"headers": {}})()
            scanner._get_with_origin = AsyncMock(return_value=response)
            finding = Finding(
                check_type="cors",
                severity="critical",
                url="http://fixture.test/cors-reflect",
                field_name="(CORS: Origin header)",
                payload="Origin: https://evil.wscan-test.example.com",
                evidence="origin reflected",
                evidence_type="cors_origin_reflection",
                evidence_details={
                    "origin": "https://evil.wscan-test.example.com",
                    "acac": "true",
                },
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_host_header_verifier_replays_reflected_header(self):
        async def run():
            scanner = HostHeaderScanner(_DummyEngine())
            response = type(
                "Resp",
                (),
                {"text": '<a href="https://evil.wscan-test.example.com/reset">reset</a>'},
            )()
            scanner._get_with_headers = AsyncMock(return_value=response)
            finding = Finding(
                check_type="host_header",
                severity="medium",
                url="http://fixture.test/host-reset",
                field_name="(HTTP X-Forwarded-Host)",
                payload="{'X-Forwarded-Host': 'evil.wscan-test.example.com'}",
                evidence="host reflected",
                evidence_type="host_header_reflection",
                evidence_details={
                    "header": "X-Forwarded-Host",
                    "value": "evil.wscan-test.example.com",
                },
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)
            scanner._get_with_headers.assert_awaited_once_with(
                "http://fixture.test/host-reset",
                {"X-Forwarded-Host": "evil.wscan-test.example.com"},
            )

        self.run_async(run())

    def test_host_header_verifier_rejects_missing_reflection(self):
        async def run():
            scanner = HostHeaderScanner(_DummyEngine())
            response = type("Resp", (), {"text": "<p>reset link unavailable</p>"})()
            scanner._get_with_headers = AsyncMock(return_value=response)
            finding = Finding(
                check_type="host_header",
                severity="medium",
                url="http://fixture.test/host-reset",
                field_name="(HTTP Host)",
                payload="{'Host': 'evil.wscan-test.example.com'}",
                evidence="host reflected",
                evidence_type="host_header_reflection",
                evidence_details={
                    "header": "Host",
                    "value": "evil.wscan-test.example.com",
                },
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_dom_xss_verifier_replays_sink_marker(self):
        async def run():
            marker = "__WSCAN_DOMXSS__abc12345"
            engine = _DummyEngine()
            engine.browser = _DomVerifierBrowser(
                log=[{"sink": "innerHTML", "data": f"<div>{marker}</div>"}]
            )
            scanner = DOMXSSScanner(engine)
            finding = Finding(
                check_type="dom_xss",
                severity="critical",
                url="http://fixture.test/dom?next=hello",
                field_name="next",
                payload=f"{marker}<img src=x onerror=alert(1)>",
                evidence="marker reached innerHTML",
                evidence_type="dom_xss_sink",
                evidence_details={"marker": marker, "sink": "innerHTML"},
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)
            engine.browser.test_url_param.assert_awaited_once_with(
                "http://fixture.test/dom?next=hello",
                "next",
                f"{marker}<img src=x onerror=alert(1)>",
            )

        self.run_async(run())

    def test_dom_xss_verifier_rejects_missing_marker(self):
        async def run():
            marker = "__WSCAN_DOMXSS__abc12345"
            engine = _DummyEngine()
            engine.browser = _DomVerifierBrowser(
                log=[{"sink": "innerHTML", "data": "<div>safe</div>"}]
            )
            scanner = DOMXSSScanner(engine)
            finding = Finding(
                check_type="dom_xss",
                severity="critical",
                url="http://fixture.test/dom?next=hello",
                field_name="next",
                payload=f"{marker}<img src=x onerror=alert(1)>",
                evidence="marker reached innerHTML",
                evidence_type="dom_xss_sink",
                evidence_details={"marker": marker, "sink": "innerHTML"},
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_stored_xss_verifier_replays_payload_and_checks_sink(self):
        async def run():
            marker = "wsxssabc12345"
            payload = f'<script id="{marker}">/*{marker}*/</script>'
            engine = _DummyEngine()
            engine.browser = _StoredVerifierBrowser(
                html=f"<article>{payload}</article>",
            )
            scanner = StoredXSSScanner(engine)
            finding = Finding(
                check_type="stored_xss",
                severity="critical",
                url="http://fixture.test/comments",
                field_name="message",
                payload=payload,
                evidence="marker persisted",
                evidence_type="stored_xss_marker",
                evidence_details={
                    "marker": marker,
                    "injection_url": "http://fixture.test/feedback",
                    "sink_url": "http://fixture.test/comments",
                },
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)
            engine.browser.navigate.assert_any_await("http://fixture.test/feedback")
            engine.browser.fill_and_submit_form.assert_awaited_once_with(
                0,
                "message",
                payload,
            )
            engine.browser.navigate.assert_any_await("http://fixture.test/comments")

        self.run_async(run())

    def test_stored_xss_verifier_rejects_missing_marker(self):
        async def run():
            marker = "wsxssabc12345"
            payload = f'<script id="{marker}">/*{marker}*/</script>'
            engine = _DummyEngine()
            engine.browser = _StoredVerifierBrowser(html="<article>safe</article>")
            scanner = StoredXSSScanner(engine)
            finding = Finding(
                check_type="stored_xss",
                severity="critical",
                url="http://fixture.test/comments",
                field_name="message",
                payload=payload,
                evidence="marker persisted",
                evidence_type="stored_xss_marker",
                evidence_details={
                    "marker": marker,
                    "injection_url": "http://fixture.test/feedback",
                    "sink_url": "http://fixture.test/comments",
                },
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_stored_xss_scan_page_navigates_before_checking_marker(self):
        async def run():
            marker = "wsxssabc12345"
            engine = _DummyEngine()
            engine.browser = _StoredScanBrowser(
                url="http://fixture.test/comments",
                html=f"<article>{marker}</article>",
            )
            scanner = StoredXSSScanner(engine)
            scanner._injected[marker] = {
                "url": "http://fixture.test/feedback",
                "field": "message",
                "payload": f'<script id="{marker}">/*{marker}*/</script>',
            }

            findings = await scanner.scan_page("http://fixture.test/search")

            self.assertEqual(findings, [])
            engine.browser.navigate.assert_awaited_once_with("http://fixture.test/search")

        self.run_async(run())

    def test_info_disclosure_verifier_replays_sensitive_resource(self):
        async def run():
            scanner = InfoDisclosureScanner(_DummyEngine())
            response = type(
                "Resp",
                (),
                {
                    "status_code": 200,
                    "text": "APP_KEY=fixture\nDB_PASSWORD=secret\n",
                    "headers": {"content-type": "text/plain"},
                },
            )()
            scanner._get = AsyncMock(return_value=response)
            finding = Finding(
                check_type="info_disclosure",
                severity="critical",
                url="http://fixture.test/.env",
                field_name="(sensitive file/directory)",
                payload="(GET request — no payload)",
                evidence="Sensitive resource accessible",
                evidence_type="info_sensitive_resource",
                evidence_details={"path": "/.env"},
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)
            scanner._get.assert_awaited_once_with(
                "http://fixture.test/.env",
                follow_redirects=False,
            )

        self.run_async(run())

    def test_info_disclosure_verifier_rejects_missing_sensitive_resource(self):
        async def run():
            scanner = InfoDisclosureScanner(_DummyEngine())
            response = type(
                "Resp",
                (),
                {
                    "status_code": 404,
                    "text": "<html>not found</html>",
                    "headers": {"content-type": "text/html"},
                },
            )()
            scanner._get = AsyncMock(return_value=response)
            finding = Finding(
                check_type="info_disclosure",
                severity="critical",
                url="http://fixture.test/.env",
                field_name="(sensitive file/directory)",
                payload="(GET request — no payload)",
                evidence="Sensitive resource accessible",
                evidence_type="info_sensitive_resource",
                evidence_details={"path": "/.env"},
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_session_verifier_rechecks_cookie_attributes(self):
        async def run():
            engine = _DummyEngine()
            engine.browser = _CookieBrowser([
                {
                    "name": "token",
                    "secure": False,
                    "httpOnly": True,
                    "sameSite": "Lax",
                    "domain": "fixture.test",
                    "path": "/",
                }
            ])
            scanner = SessionScanner(engine)
            finding = Finding(
                check_type="session",
                severity="medium",
                url="http://fixture.test/jwt-lab",
                field_name="Cookie: token",
                payload="(no payload — cookie attribute analysis)",
                evidence="Secure flag missing",
                evidence_type="session_cookie_attributes",
                evidence_details={
                    "cookie_name": "token",
                    "issues": [
                        "Secure flag missing — cookie transmitted over unencrypted HTTP"
                    ],
                },
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)

        self.run_async(run())

    def test_session_verifier_rejects_fixed_cookie(self):
        async def run():
            engine = _DummyEngine()
            engine.browser = _CookieBrowser([
                {
                    "name": "token",
                    "secure": True,
                    "httpOnly": True,
                    "sameSite": "Lax",
                    "domain": "fixture.test",
                    "path": "/",
                }
            ])
            scanner = SessionScanner(engine)
            finding = Finding(
                check_type="session",
                severity="medium",
                url="http://fixture.test/jwt-lab",
                field_name="Cookie: token",
                payload="(no payload — cookie attribute analysis)",
                evidence="Secure flag missing",
                evidence_type="session_cookie_attributes",
                evidence_details={
                    "cookie_name": "token",
                    "issues": [
                        "Secure flag missing — cookie transmitted over unencrypted HTTP"
                    ],
                },
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_engine_routes_jwt_subtype_to_jwt_verifier(self):
        async def run():
            engine = ScanEngine(
                "http://fixture.test/",
                checks=["jwt"],
                llm_provider="none",
                open_report=False,
                enable_waf_detection=False,
                enable_ai_analysis=False,
                enable_payload_learning=False,
                enable_adaptive_payloads=False,
            )
            scanner = engine.scanners["jwt"]
            scanner.verify_finding = AsyncMock(return_value=True)
            finding = Finding(
                check_type="jwt_no_expiry",
                severity="medium",
                url="http://fixture.test/jwt-lab",
                field_name="JWT",
                payload="token",
                evidence="no exp",
            )

            result = await engine._verify_one(finding)

            self.assertEqual(result, "reproduced")
            scanner.verify_finding.assert_awaited_once()

        self.run_async(run())

    def test_sqli_similarity_ignores_dynamic_noise(self):
        scanner = object.__new__(SQLiScanner)
        baseline = "<html><script>var ts=1778469492;</script><body>Welcome user 1234567890</body></html>"
        equivalent = "<html><script>var ts=1778469500;</script><body>Welcome user 9999999999</body></html>"
        different = "<html><body>Invalid credentials</body></html>"

        self.assertGreater(scanner._body_similarity(baseline, equivalent), 0.90)
        self.assertLess(scanner._body_similarity(baseline, different), 0.80)

    def test_sqli_prioritizes_auth_bypass_payloads_for_login_fields_under_cap(self):
        scanner = object.__new__(SQLiScanner)
        scanner.engine = type("Engine", (), {"max_payloads": 3})()
        payloads = ["'", "''", '"', "1 AND 1=1"]

        prioritized = scanner._prioritize_login_payloads("username", payloads)

        self.assertEqual(prioritized[0], "' OR '1'='1")
        self.assertEqual(len(prioritized), 3)
        self.assertNotIn("'", prioritized)

    def test_sqli_keeps_generic_payload_order_for_non_login_fields(self):
        scanner = object.__new__(SQLiScanner)
        scanner.engine = type("Engine", (), {"max_payloads": 3})()
        payloads = ["'", "''", '"', "1 AND 1=1"]

        prioritized = scanner._prioritize_login_payloads("search", payloads)

        self.assertEqual(prioritized, payloads)

    def test_sqli_boolean_verifier_requires_true_response_to_stay_near_baseline(self):
        async def run():
            scanner = SQLiScanner(_DummyEngine())
            baseline = "Y" * 1000
            true_src = "Y" * 1500
            false_src = "Z" * 1500
            scanner._get_baseline = AsyncMock(return_value=(baseline, {}))
            scanner._apply_payload = AsyncMock(side_effect=[
                (true_src, {}),
                (true_src, {}),
                (false_src, {}),
            ])
            finding = Finding(
                check_type="sqli",
                severity="high",
                url="http://fixture.test/item?id=1",
                field_name="id",
                payload="1 AND 1=1",
                evidence="boolean sqli",
                evidence_type="sqli_boolean",
                evidence_details={
                    "true_payload": "1 AND 1=1",
                    "false_payload": "1 AND 1=2",
                    "baseline_variance": 0,
                },
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_sqli_boolean_verifier_accepts_detection_thresholds(self):
        async def run():
            scanner = SQLiScanner(_DummyEngine())
            baseline = "Y" * 1000
            true_src = "Y" * 990
            false_src = "Z" * 1500
            scanner._get_baseline = AsyncMock(return_value=(baseline, {}))
            scanner._apply_payload = AsyncMock(side_effect=[
                (true_src, {}),
                (true_src, {}),
                (false_src, {}),
            ])
            finding = Finding(
                check_type="sqli",
                severity="high",
                url="http://fixture.test/item?id=1",
                field_name="id",
                payload="1 AND 1=1",
                evidence="boolean sqli",
                evidence_type="sqli_boolean",
                evidence_details={
                    "true_payload": "1 AND 1=1",
                    "false_payload": "1 AND 1=2",
                    "baseline_variance": 0,
                },
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)

        self.run_async(run())

    def test_prompt_template_formatting_preserves_payload_braces(self):
        template = (
            'Generate for "{field_name}" at "{url}". '
            "Keep ;${IFS}id and ;{cat,/etc/passwd} examples."
        )

        rendered = _format_prompt_template(
            template,
            field_name="host",
            url="http://fixture.test/tools",
        )

        self.assertIn('"host"', rendered)
        self.assertIn('"http://fixture.test/tools"', rendered)
        self.assertIn(";${IFS}id", rendered)
        self.assertIn(";{cat,/etc/passwd}", rendered)

    def test_ctf_flag_finder_ignores_lowercase_js_function_blocks(self):
        finder = FlagFinder()
        text = "try{alert('x')} FLAG{real_flag} CTF{also_real} ACSC{UPPER_PREFIX}"

        found = finder.find(text)

        self.assertNotIn("try{alert('x')}", found)
        self.assertIn("FLAG{real_flag}", found)
        self.assertIn("CTF{also_real}", found)
        self.assertIn("ACSC{UPPER_PREFIX}", found)

    def test_page_fingerprint_preserves_distinct_form_actions(self):
        base = "<html><body><h1>Panel</h1><form method='post' action='/admin/users/role'><input name='role'></form></body></html>"
        same_layout_other_action = "<html><body><h1>Panel</h1><form method='post' action='/support'><input name='role'></form></body></html>"

        self.assertNotEqual(
            ScanEngine._page_fingerprint(base),
            ScanEngine._page_fingerprint(same_layout_other_action),
        )

    def test_page_fingerprint_preserves_distinct_url_inputs(self):
        html = "<html><body><h1>Lookup</h1><p>missing token</p></body></html>"

        self.assertNotEqual(
            ScanEngine._page_fingerprint(html, "http://fixture.test/ctf/js-hidden?token=from-script"),
            ScanEngine._page_fingerprint(html, "http://fixture.test/ctf/bundle-hidden?token=from-bundle"),
        )

    def test_page_fingerprint_preserves_distinct_paths_for_page_level_checks(self):
        html = "<html><body><h1>Same Layout</h1><p>static copy</p></body></html>"

        self.assertNotEqual(
            ScanEngine._page_fingerprint(html, "http://fixture.test/safe"),
            ScanEngine._page_fingerprint(html, "http://fixture.test/short-hsts"),
        )

    def test_merge_url_params_preserves_redirect_source_query_inputs(self):
        params = ScanEngine._merge_url_params([], "http://fixture.test/go?next=/catalog")

        self.assertEqual(params, ["next"])

    def test_merge_url_params_keeps_current_and_queued_query_inputs(self):
        params = ScanEngine._merge_url_params(
            ["page"],
            "http://fixture.test/go?next=/catalog&page=1",
        )

        self.assertEqual(params, ["page", "next"])

    def test_ssti_verifier_uses_detected_probe_expected_value(self):
        async def run():
            scanner = SSTIScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(side_effect=[
                ("<html>baseline</html>", {}),
                ("<html>7045744422742119121</html>", {}),
            ])
            finding = Finding(
                check_type="ssti",
                severity="critical",
                url="http://fixture.test/template?name=guest",
                field_name="name",
                payload="{{2654435761*2654435761}}",
                evidence="SSTI detected",
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)
            scanner._apply_payload.assert_any_await(
                finding.url,
                0,
                "name",
                "{{2654435761*2654435761}}",
                True,
            )

        import asyncio
        asyncio.run(run())

    def test_current_page_pair_does_not_fall_back_to_unrelated_latest_response(self):
        scanner = _DummyScanner(_DummyEngine())

        class Network:
            def latest_for_url(self, url, *, match_query=True):
                return None

            def latest(self):
                return {
                    "request": {"url": "http://fixture.test/short-hsts"},
                    "response": {
                        "url": "http://fixture.test/short-hsts",
                        "headers": {"strict-transport-security": "max-age=60"},
                    },
                }

        scanner.browser = type("Browser", (), {"network": Network()})()

        self.assertEqual(scanner.current_page_pair("http://fixture.test/"), {})

    def test_header_injection_verifier_replays_payload_and_checks_header(self):
        async def run():
            scanner = HeaderInjectionScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(return_value=(
                "ok",
                {"response": {"headers": {"x-wscanhdrinject": "1"}}},
            ))
            finding = Finding(
                check_type="header_injection",
                severity="high",
                url="http://fixture.test/header-echo?ref=safe",
                field_name="ref",
                payload="\r\nX-WscanHdrInject: 1",
                evidence="header injected",
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)
            scanner._apply_payload.assert_awaited_with(
                finding.url,
                0,
                "ref",
                "\r\nX-WscanHdrInject: 1",
                True,
            )

        self.run_async(run())

    def test_security_headers_scan_records_structured_missing_header_evidence(self):
        async def run():
            scanner = SecurityHeadersScanner(_DummyEngine())
            scanner.current_page_pair = lambda url: {
                "request": {"url": url},
                "response": {
                    "status": 200,
                    "headers": {"server": "fixture"},
                    "body": "<html>ok</html>",
                },
            }

            findings = await scanner.scan_page("http://fixture.test/")
            hsts = next(
                f for f in findings
                if f.field_name == "(Header: strict-transport-security)"
            )

            self.assertEqual(hsts.evidence_type, "security_header_missing")
            self.assertEqual(
                hsts.evidence_details["header"],
                "strict-transport-security",
            )
            self.assertIn("Confirm response header", hsts.reproduction_steps[1])

        self.run_async(run())

    def test_security_headers_verifier_confirms_missing_header(self):
        async def run():
            scanner = SecurityHeadersScanner(_DummyEngine())
            scanner._get = AsyncMock(
                return_value=httpx.Response(
                    200,
                    headers={"content-security-policy": "default-src 'self'"},
                )
            )
            finding = Finding(
                check_type="security_headers",
                severity="medium",
                url="http://fixture.test/",
                field_name="(Header: strict-transport-security)",
                payload="(no payload)",
                evidence="HSTS missing",
                evidence_type="security_header_missing",
                evidence_details={"header": "strict-transport-security"},
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)

        self.run_async(run())

    def test_security_headers_verifier_rejects_present_header(self):
        async def run():
            scanner = SecurityHeadersScanner(_DummyEngine())
            scanner._get = AsyncMock(
                return_value=httpx.Response(
                    200,
                    headers={"strict-transport-security": "max-age=31536000"},
                )
            )
            finding = Finding(
                check_type="security_headers",
                severity="medium",
                url="http://fixture.test/",
                field_name="(Header: strict-transport-security)",
                payload="(no payload)",
                evidence="HSTS missing",
                evidence_type="security_header_missing",
                evidence_details={"header": "strict-transport-security"},
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_security_headers_scan_uses_direct_response_headers_to_avoid_browser_header_gaps(self):
        async def run():
            scanner = SecurityHeadersScanner(_DummyEngine())
            scanner.current_page_pair = lambda url: {
                "request": {"url": "http://fixture.test/unrelated"},
                "response": {"headers": {}},
            }
            scanner._get = AsyncMock(
                return_value=httpx.Response(
                    200,
                    headers={
                        "strict-transport-security": "max-age=31536000; includeSubDomains",
                        "content-security-policy": "default-src 'self'",
                        "x-content-type-options": "nosniff",
                        "referrer-policy": "strict-origin-when-cross-origin",
                        "permissions-policy": "geolocation=()",
                        "cross-origin-opener-policy": "same-origin",
                    },
                    text="<html>safe</html>",
                )
            )

            findings = await scanner.scan_page("http://fixture.test/safe")

            self.assertEqual(findings, [])

        self.run_async(run())

    def test_security_headers_is_in_phase_45_verification_gate(self):
        self.assertIn("security_headers", ScanEngine._VERIFIABLE_CHECKS)

    def test_open_redirect_verifier_replays_payload_and_checks_location(self):
        async def run():
            scanner = OpenRedirectScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(return_value=(
                "",
                {
                    "response": {
                        "headers": {"Location": "https://evil.wscan-test.example.com"}
                    }
                },
            ))
            finding = Finding(
                check_type="open_redirect",
                severity="medium",
                url="http://fixture.test/go?next=/catalog",
                field_name="next",
                payload="https://evil.wscan-test.example.com",
                evidence="redirected",
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)
            scanner._apply_payload.assert_awaited_with(
                finding.url,
                0,
                "next",
                "https://evil.wscan-test.example.com",
                True,
            )

        self.run_async(run())

    def test_path_traversal_verifier_replays_baseline_and_payload(self):
        async def run():
            scanner = PathTraversalScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(side_effect=[
                ("Documentation for baseline_test_value", {}),
                ("root:x:0:0:root:/root:/bin/bash", {}),
            ])
            finding = Finding(
                check_type="path_traversal",
                severity="high",
                url="http://fixture.test/download?file=readme.txt",
                field_name="file",
                payload="../../../../etc/passwd",
                evidence="passwd leaked",
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)
            scanner._apply_payload.assert_any_await(
                finding.url,
                0,
                "file",
                "baseline_test_value",
                True,
            )
            scanner._apply_payload.assert_any_await(
                finding.url,
                0,
                "file",
                "../../../../etc/passwd",
                True,
            )

        self.run_async(run())

    def test_path_traversal_verifier_rejects_baseline_pattern(self):
        async def run():
            scanner = PathTraversalScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(side_effect=[
                ("root:x:0:0:root:/root:/bin/bash", {}),
                ("root:x:0:0:root:/root:/bin/bash", {}),
            ])
            finding = Finding(
                check_type="path_traversal",
                severity="high",
                url="http://fixture.test/download?file=readme.txt",
                field_name="file",
                payload="../../../../etc/passwd",
                evidence="passwd leaked",
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_path_traversal_php_source_leak_not_suppressed_by_php_in_baseline(self):
        # Regression: r"<?php" (broken) matched the bare word "php" anywhere, so a
        # baseline response like "Running PHP 8.2" would set baseline_match=True and
        # suppress the real finding when <?php source code was leaked.
        # The fix changes the pattern to r"<\?php" which only matches the literal tag.
        async def run():
            scanner = PathTraversalScanner(_DummyEngine())
            scanner.get_payloads = AsyncMock(return_value=["../../var/www/html/config.php"])
            scanner._apply_payload = AsyncMock(side_effect=[
                # baseline: 成功（pair に response あり）。PHP バージョン文字列を含むが
                # <\?php には該当しない通常ページ。
                ("<html><body>Powered by PHP 8.2</body></html>",
                 {"response": {"body": "<html><body>Powered by PHP 8.2</body></html>"}}),
                # payload: path traversal leaks PHP source starting with <?php
                ("<?php\n$db_pass = 'secret';\n?>", {}),
            ])

            findings = await scanner.scan_field(
                "http://fixture.test/page?file=about.txt",
                0,
                {"name": "file"},
                is_url_param=True,
            )

            self.assertEqual(len(findings), 1)
            self.assertIn("<?php", findings[0].evidence)

        self.run_async(run())

    def test_path_traversal_php_pattern_matches_opening_tag_not_bare_word(self):
        import re
        from wscan.scanners.path_traversal import PATH_TRAVERSAL_PATTERNS

        php_pattern = next(p for p in PATH_TRAVERSAL_PATTERNS if "php" in p.lower())

        # Must NOT match plain "PHP" (version strings, error messages, etc.)
        self.assertIsNone(re.search(php_pattern, "Running PHP 8.2", re.IGNORECASE))
        self.assertIsNone(re.search(php_pattern, "PHP Notice: Undefined variable", re.IGNORECASE))
        # Must match the actual PHP source opening tag
        self.assertIsNotNone(re.search(php_pattern, "<?php\n$x=1;", re.IGNORECASE))
        self.assertIsNotNone(re.search(php_pattern, "<?PHP echo 'hi'; ?>", re.IGNORECASE))

    def test_os_verifier_replays_baseline_and_payload_body(self):
        async def run():
            scanner = OSInjectionScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(side_effect=[
                ("PING baseline_os_test", {"response": {"body": "PING baseline_os_test"}}),
                ("", {"response": {"body": "uid=1000(wscan) gid=1000(wscan)"}}),
            ])
            finding = Finding(
                check_type="os",
                severity="critical",
                url="http://fixture.test/ping?host=127.0.0.1",
                field_name="host",
                payload="; id",
                evidence="command output",
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)
            scanner._apply_payload.assert_any_await(
                finding.url,
                0,
                "host",
                "baseline_os_test",
                True,
            )
            scanner._apply_payload.assert_any_await(
                finding.url,
                0,
                "host",
                "; id",
                True,
            )

        self.run_async(run())

    def test_os_verifier_rejects_preexisting_command_output(self):
        async def run():
            scanner = OSInjectionScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(side_effect=[
                ("uid=1000(wscan)", {"response": {"body": "uid=1000(wscan)"}}),
                ("uid=1000(wscan)", {"response": {"body": "uid=1000(wscan)"}}),
            ])
            finding = Finding(
                check_type="os",
                severity="critical",
                url="http://fixture.test/ping?host=127.0.0.1",
                field_name="host",
                payload="; id",
                evidence="command output",
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_network_capture_prefers_target_url_over_later_assets(self):
        capture = NetworkCapture()
        capture.pairs = [
            {
                "request": {"url": "http://fixture.test/template?name=%7B%7B2654435761%2A2654435761%7D%7D"},
                "response": {"url": "http://fixture.test/template?name=%7B%7B2654435761%2A2654435761%7D%7D"},
            },
            {
                "request": {"url": "http://fixture.test/static/app.js"},
                "response": {"url": "http://fixture.test/static/app.js"},
            },
        ]

        pair = capture.latest_for_url(
            "http://fixture.test/template?name=%7B%7B2654435761%2A2654435761%7D%7D"
        )

        self.assertEqual(
            pair["request"]["url"],
            "http://fixture.test/template?name=%7B%7B2654435761%2A2654435761%7D%7D",
        )

    def test_network_capture_can_match_form_action_without_query(self):
        capture = NetworkCapture()
        capture.pairs = [
            {
                "request": {"url": "http://fixture.test/search?q=%3Cscript%3E"},
                "response": {"url": "http://fixture.test/search?q=%3Cscript%3E"},
            },
            {
                "request": {"url": "http://fixture.test/static/app.js"},
                "response": {"url": "http://fixture.test/static/app.js"},
            },
        ]

        pair = capture.latest_for_url("http://fixture.test/search", match_query=False)

        self.assertEqual(pair["request"]["url"], "http://fixture.test/search?q=%3Cscript%3E")

    def test_network_capture_matches_empty_root_path_to_slash(self):
        capture = NetworkCapture()
        capture.pairs = [
            {
                "request": {"url": "http://fixture.test/"},
                "response": {"url": "http://fixture.test/"},
            },
            {
                "request": {"url": "http://fixture.test/static/app.js"},
                "response": {"url": "http://fixture.test/static/app.js"},
            },
        ]

        pair = capture.latest_for_url("http://fixture.test", match_query=False)

        self.assertEqual(pair["request"]["url"], "http://fixture.test/")

    def test_page_level_scanner_uses_document_pair_over_later_asset(self):
        async def run():
            engine = _DummyEngine()
            engine.browser.network = NetworkCapture()
            engine.browser.network.pairs = [
                {
                    "request": {"url": "http://fixture.test/"},
                    "response": {
                        "url": "http://fixture.test/",
                        "headers": {
                            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                            "Content-Security-Policy": "default-src 'self'",
                            "X-Content-Type-Options": "nosniff",
                            "Referrer-Policy": "strict-origin-when-cross-origin",
                            "Permissions-Policy": "geolocation=()",
                            "Cross-Origin-Opener-Policy": "same-origin",
                        },
                    },
                },
                {
                    "request": {"url": "http://fixture.test/static/app.js"},
                    "response": {
                        "url": "http://fixture.test/static/app.js",
                        "headers": {},
                    },
                },
            ]
            scanner = SecurityHeadersScanner(engine)

            findings = await scanner.scan_page("http://fixture.test/")

            self.assertEqual(findings, [])

        self.run_async(run())

    def test_payload_generator_returns_role_specific_models(self):
        gen = PayloadGenerator(
            provider="ollama",
            ollama_model="qwen2.5-coder:latest",
            role_models={"planner": "qwen3:8b", "report": "llama3.1:8b"},
        )

        self.assertEqual(gen.get_model("planner"), "qwen3:8b")
        self.assertEqual(gen.get_model("payload"), "qwen2.5-coder:latest")
        self.assertEqual(gen.get_model("report"), "llama3.1:8b")

    def test_payload_generator_role_context_restores_default_model(self):
        gen = PayloadGenerator(
            provider="ollama",
            ollama_model="qwen2.5-coder:latest",
            role_models={"adaptive": "qwen3:8b"},
        )

        with gen.use_role("adaptive"):
            self.assertEqual(gen.ollama_model, "qwen3:8b")

        self.assertEqual(gen.ollama_model, "qwen2.5-coder:latest")

    def test_sqli_auth_bypass_fresh_verifier_restores_original_browser(self):
        async def run():
            scanner = object.__new__(SQLiScanner)
            original_browser = type(
                "Browser",
                (),
                {
                    "timeout": 10000,
                    "headless": True,
                    "auth_user": "",
                    "auth_pass": "",
                    "proxy": "",
                    "sleep_factor": 1.0,
                },
            )()
            fresh_browser = type(
                "FreshBrowser",
                (),
                {"init": AsyncMock(), "close": AsyncMock()},
            )()
            scanner.browser = original_browser
            scanner._apply_payload = AsyncMock(return_value=("<html>admin</html>", {}))
            scanner._detect_auth_bypass = lambda url, source: (scanner.browser is fresh_browser, "http://fixture/admin")
            finding = Finding(
                check_type="sqli",
                severity="critical",
                url="http://fixture/login",
                field_name="username",
                payload="' OR '1'='1",
                evidence="auth bypass",
                evidence_type="sqli_auth_bypass",
            )

            with patch("wscan.browser.BrowserManager", return_value=fresh_browser):
                result = await scanner._verify_auth_bypass_fresh_context(finding)

            self.assertTrue(result)
            self.assertIs(scanner.browser, original_browser)
            fresh_browser.close.assert_awaited()

        self.run_async(run())

    def run_async(self, coro):
        import asyncio
        return asyncio.run(coro)


if __name__ == "__main__":
    unittest.main()
