"""Tests for the token-based access control used when hosting the dashboard
on a server / intranet (`serve` mode)."""
import unittest

from fastapi.testclient import TestClient

from wscan.monitor import MonitorServer, SESSION_COOKIE, _session_value


class AuthEnabledTests(unittest.TestCase):
    TOKEN = "s3cret-token"

    def setUp(self):
        self.srv = MonitorServer(port=9999, auth_token=self.TOKEN)
        self.client = TestClient(self.srv.app)

    def test_health_is_public(self):
        self.assertEqual(self.client.get("/health").status_code, 200)

    def test_unauthenticated_html_redirects_to_login(self):
        r = self.client.get(
            "/", headers={"accept": "text/html"}, follow_redirects=False
        )
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/login")

    def test_unauthenticated_api_returns_401(self):
        self.assertEqual(self.client.get("/api/config/defaults").status_code, 401)

    def test_bearer_token_grants_api_access(self):
        ok = self.client.get(
            "/api/config/defaults",
            headers={"authorization": f"Bearer {self.TOKEN}"},
        )
        self.assertEqual(ok.status_code, 200)
        bad = self.client.get(
            "/api/config/defaults",
            headers={"authorization": "Bearer wrong"},
        )
        self.assertEqual(bad.status_code, 401)

    def test_x_auth_token_header(self):
        ok = self.client.get(
            "/api/config/defaults", headers={"x-auth-token": self.TOKEN}
        )
        self.assertEqual(ok.status_code, 200)

    def test_login_page_renders(self):
        r = self.client.get("/login")
        self.assertEqual(r.status_code, 200)
        self.assertIn("アクセストークン", r.text)

    def test_login_wrong_token_rejected(self):
        r = self.client.post(
            "/login", data={"token": "nope"}, follow_redirects=False
        )
        self.assertEqual(r.status_code, 401)

    def test_login_sets_hashed_cookie_not_raw_token(self):
        r = self.client.post(
            "/login", data={"token": self.TOKEN}, follow_redirects=False
        )
        self.assertEqual(r.status_code, 303)
        self.assertIn(SESSION_COOKIE, r.cookies)
        # The raw token must never be stored in the browser cookie.
        self.assertNotEqual(r.cookies[SESSION_COOKIE], self.TOKEN)
        self.assertEqual(r.cookies[SESSION_COOKIE], _session_value(self.TOKEN))

    def test_session_cookie_grants_access(self):
        self.client.post("/login", data={"token": self.TOKEN})
        self.assertEqual(
            self.client.get("/", headers={"accept": "text/html"}).status_code, 200
        )
        self.assertEqual(self.client.get("/api/config/defaults").status_code, 200)

    def test_auth_status_reports_enabled(self):
        self.client.post("/login", data={"token": self.TOKEN})
        r = self.client.get("/api/auth-status")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["auth_enabled"])

    def test_websocket_rejected_without_token(self):
        with self.assertRaises(Exception):
            with self.client.websocket_connect("/ws"):
                pass

    def test_websocket_allowed_with_cookie(self):
        self.client.post("/login", data={"token": self.TOKEN})
        with self.client.websocket_connect("/ws") as ws:
            # Server keeps the connection open; a ping/history frame is fine.
            ws.send_text("{}")


class ConcurrentScanRejectionTests(unittest.TestCase):
    """A second scan submitted while one is running must be rejected, not
    silently dropped (regression for persistent serve mode)."""

    def setUp(self):
        self.srv = MonitorServer(port=9997, auth_token="")
        self.client = TestClient(self.srv.app)

    def test_http_scan_rejected_while_busy(self):
        self.srv.scan_in_progress = True
        r = self.client.post("/api/v1/scan", json={"url": "https://example.com"})
        self.assertEqual(r.status_code, 409)
        # The pending event must NOT be set, so the loop will not pick up a
        # request the API just refused.
        self.assertFalse(self.srv.scan_request_event.is_set())

    def test_http_scan_rejected_when_event_already_set(self):
        self.srv.scan_request_event.set()
        r = self.client.post("/api/v1/scan", json={"url": "https://example.com"})
        self.assertEqual(r.status_code, 409)

    def test_http_scan_accepted_when_idle(self):
        r = self.client.post("/api/v1/scan", json={"url": "https://example.com"})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(self.srv.scan_request_event.is_set())

    def test_ws_start_scan_ignored_while_busy(self):
        self.srv.scan_in_progress = True
        # Direct call to the message handler avoids needing a live event loop
        # wired to the scan runner.
        self.srv._handle_client_message(
            '{"action": "start_scan", "config": {"url": "https://example.com"}}'
        )
        self.assertFalse(self.srv.scan_request_event.is_set())

    def test_completed_scan_state_is_queryable_while_idle(self):
        # Simulate a finished scan that published its results.
        self.srv.api_scan_id = "123"
        self.srv.api_scan_status = "done"
        self.srv.api_findings = [{"severity": "high"}, {"severity": "critical"}]
        self.srv.api_report_path = "/tmp/report.html"
        # The completed results must remain queryable after completion.
        results = self.client.get("/api/v1/scan/results").json()
        self.assertEqual(results["status"], "done")
        self.assertEqual(results["findings_count"], 2)
        self.assertEqual(results["critical_count"], 1)
        status = self.client.get("/api/v1/scan/status").json()
        self.assertEqual(status["status"], "done")

    def test_accepting_new_scan_resets_previous_state(self):
        self.srv.api_scan_status = "done"
        self.srv.api_findings = [{"severity": "high"}]
        self.srv.api_report_path = "/tmp/old.html"
        r = self.client.post("/api/v1/scan", json={"url": "https://example.com"})
        self.assertEqual(r.status_code, 200)
        # A freshly accepted scan starts from a clean slate.
        self.assertEqual(self.srv.api_scan_status, "scanning")
        self.assertEqual(self.srv.api_findings, [])
        self.assertIsNone(self.srv.api_report_path)


class AuthDisabledTests(unittest.TestCase):
    def setUp(self):
        self.srv = MonitorServer(port=9998, auth_token="")
        self.client = TestClient(self.srv.app)

    def test_open_access_when_no_token(self):
        self.assertEqual(self.client.get("/api/config/defaults").status_code, 200)
        self.assertEqual(
            self.client.get("/", headers={"accept": "text/html"}).status_code, 200
        )

    def test_auth_status_reports_disabled(self):
        self.assertFalse(self.client.get("/api/auth-status").json()["auth_enabled"])

    def test_websocket_open_when_no_token(self):
        with self.client.websocket_connect("/ws") as ws:
            ws.send_text("{}")


if __name__ == "__main__":
    unittest.main()
