import unittest
from unittest.mock import AsyncMock

from wscan.monitor import MonitorServer
from wscan.scanners.ldap_injection import LDAPScanner
from wscan.scanners.xxe import XXEScanner


class _Monitor:
    def __init__(self):
        self.payload_tests = []
        self.statuses = []

    async def emit_payload_test(self, field, payload, check_type, url=""):
        self.payload_tests.append({
            "field": field,
            "payload": payload,
            "check_type": check_type,
            "url": url,
        })

    async def emit_status(self, message, state="running"):
        self.statuses.append((message, state))


class _Engine:
    def __init__(self):
        self.browser = object()
        self.monitor = _Monitor()
        self.payload_gen = object()
        self.all_findings = []
        self._finding_dedup = set()
        self.timeout = 3
        self.proxy = ""

    def auth_headers(self, extra=None, include_cookie=True):
        headers = {"Authorization": "Bearer test"}
        headers.update(extra or {})
        return headers


class MonitorPayloadEventTests(unittest.IsolatedAsyncioTestCase):
    async def test_dashboard_start_scan_resets_api_state(self):
        monitor = MonitorServer()
        monitor.api_findings = [{"stale": True}]
        monitor.api_report_path = "output/old/report.html"

        monitor._handle_client_message(
            '{"action":"start_scan","config":{"url":"http://fixture.test/"}}'
        )

        self.assertEqual(monitor.scan_request_data["url"], "http://fixture.test/")
        self.assertEqual(monitor.api_scan_status, "scanning")
        self.assertTrue(monitor.api_scan_id)
        self.assertEqual(monitor.api_findings, [])
        self.assertIsNone(monitor.api_report_path)
        self.assertTrue(monitor.scan_request_event.is_set())

    async def test_ldap_payload_event_uses_field_payload_check_url_order(self):
        engine = _Engine()
        scanner = LDAPScanner(engine)
        scanner._apply_payload = AsyncMock(return_value=("invalid login", {}))

        await scanner.scan_field(
            "http://fixture.test/ldap-login",
            0,
            {"name": "username", "type": "text"},
            False,
        )

        event = engine.monitor.payload_tests[0]
        self.assertEqual(event["field"], "username")
        self.assertEqual(event["check_type"], "ldap")
        self.assertEqual(event["url"], "http://fixture.test/ldap-login")
        self.assertNotEqual(event["payload"], "username")

    async def test_xxe_payload_event_uses_field_payload_check_url_order(self):
        engine = _Engine()
        scanner = XXEScanner(engine)
        scanner._post_xml = AsyncMock(return_value=("<root>safe</root>", 200, 0.01))

        await scanner.scan_field(
            "http://fixture.test/xml",
            0,
            {"name": "xml_body", "type": "textarea"},
            False,
        )

        event = engine.monitor.payload_tests[0]
        self.assertEqual(event["field"], "xml_body")
        self.assertEqual(event["check_type"], "xxe")
        self.assertEqual(event["url"], "http://fixture.test/xml")
        self.assertTrue(event["payload"].startswith("<?xml"))


if __name__ == "__main__":
    unittest.main()
