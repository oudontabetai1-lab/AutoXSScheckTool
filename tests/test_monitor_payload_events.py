import unittest
from unittest.mock import AsyncMock

from wscan.monitor import MonitorServer
from wscan.scanners.base import Finding
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
    async def test_finding_payload_includes_verification_state(self):
        monitor = MonitorServer()
        finding = Finding(
            check_type="xss",
            severity="high",
            url="http://fixture.test/search?q=x",
            field_name="q",
            payload="<svg/onload=alert(1)>",
            evidence="reflected",
            verification_state="assumed",
        )

        await monitor.emit_finding(finding.to_dict())

        self.assertEqual(monitor.api_findings[0]["verification_state"], "assumed")
        self.assertEqual(
            monitor.event_history[-1]["data"]["verification_state"],
            "assumed",
        )

    async def test_emit_finding_update_replaces_snapshot_and_broadcasts(self):
        # 検証で state が変わった際、蓄積済み snapshot を安定キーで差し替え update を配信する
        # （初期 assumed のまま /api・ダッシュボードに残さない）。
        monitor = MonitorServer()
        f = Finding(
            check_type="sqli", severity="high", url="http://h/a", field_name="q",
            payload="'", evidence="err", evidence_type="sqli_error",
        )
        await monitor.emit_finding(f.to_dict())
        self.assertEqual(monitor.api_findings[0]["verification_state"], "assumed")

        f.verification_state = "reproduced"
        self.assertTrue(f.to_dict()["verified"])
        await monitor.emit_finding_update(f.to_dict())

        # 蓄積は増えず（重複しない）、同一 finding の state が更新される。
        self.assertEqual(len(monitor.api_findings), 1)
        self.assertEqual(monitor.api_findings[0]["verification_state"], "reproduced")
        # finding_update イベントが配信される。
        self.assertEqual(monitor.event_history[-1]["type"], "finding_update")
        self.assertEqual(
            monitor.event_history[-1]["data"]["verification_state"], "reproduced"
        )

    async def test_emit_finding_update_distinguishes_json_pointers(self):
        # 同一 URL/leaf/evidence/payload で pointer だけ違う 2 つの json_body finding を
        # update 時に取り違えない（canonical dedup と同じ identity）。
        monitor = MonitorServer()

        def jf(pointer):
            return {
                "url": "http://h/login", "field_name": "id", "check_type": "sqli",
                "evidence_type": "sqli_error", "payload": "'",
                "injection_location": "json_body", "injection_method": "POST",
                "injection_pointer": pointer, "verification_state": "assumed",
            }

        await monitor.emit_finding(jf("/profile/id"))
        await monitor.emit_finding(jf("/billing/id"))
        self.assertEqual(len(monitor.api_findings), 2)

        updated = jf("/billing/id")
        updated["verification_state"] = "reproduced"
        await monitor.emit_finding_update(updated)

        # 2件のまま。/billing/id だけ reproduced、/profile/id は assumed のまま。
        self.assertEqual(len(monitor.api_findings), 2)
        by_ptr = {f["injection_pointer"]: f["verification_state"] for f in monitor.api_findings}
        self.assertEqual(by_ptr["/billing/id"], "reproduced")
        self.assertEqual(by_ptr["/profile/id"], "assumed")

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

        # baseline 投入も log_payload_test を通すため、先頭は ldap_baseline。
        self.assertEqual(engine.monitor.payload_tests[0]["check_type"], "ldap_baseline")
        # 実ペイロードイベント（check_type == "ldap"）で引数順を検証する。
        event = next(
            e for e in engine.monitor.payload_tests if e["check_type"] == "ldap"
        )
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
