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
