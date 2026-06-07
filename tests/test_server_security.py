"""サーバーモードのセキュリティガードのテスト。

- 対象スコープ(allow/deny)による誤爆・悪用防止。
- ログイン総当たりのレート制限(ロックアウト)。
"""
import tempfile
import unittest
from pathlib import Path

import wscan.monitor as monitor_mod
from wscan.monitor import MonitorServer, target_in_scope
from fastapi.testclient import TestClient


class TargetScopeTests(unittest.TestCase):
    def test_allowed_matches_host_and_subdomain(self):
        self.assertTrue(target_in_scope("http://example.com/x", ["example.com"], []))
        self.assertTrue(target_in_scope("https://a.b.example.com/x", ["example.com"], []))

    def test_allowed_rejects_others(self):
        self.assertFalse(target_in_scope("http://evil.com/x", ["example.com"], []))

    def test_denied_takes_precedence(self):
        self.assertFalse(target_in_scope("http://example.com", ["example.com"], ["example.com"]))
        self.assertFalse(target_in_scope("http://sub.example.com", [], ["example.com"]))

    def test_empty_allow_means_unrestricted(self):
        self.assertTrue(target_in_scope("http://anything.test", [], []))

    def test_invalid_url_is_out_of_scope(self):
        self.assertFalse(target_in_scope("not a url", ["example.com"], []))


class ServerGuardEndpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig = monitor_mod.OUTPUT_BASE
        monitor_mod.OUTPUT_BASE = self.tmp

    def tearDown(self):
        monitor_mod.OUTPUT_BASE = self._orig

    def test_scan_start_rejects_out_of_scope(self):
        srv = MonitorServer(port=0, auth_token="")
        srv.allowed_target_hosts = ["example.com"]
        c = TestClient(srv.app)
        self.assertEqual(c.post("/api/v1/scan", json={"url": "http://evil.com"}).status_code, 403)
        # 許可スコープ内は受理（409=実行中ではなく 202/accepted 系）
        self.assertNotEqual(
            c.post("/api/v1/scan", json={"url": "http://example.com"}).status_code, 403
        )

    def test_schedule_out_of_scope_is_skipped_but_advances(self):
        srv = MonitorServer(port=0, auth_token="")
        srv.allowed_target_hosts = ["example.com"]
        srv.add_schedule("http://evil.com", [], 2, 1)
        self.assertIsNone(srv.trigger_due_schedules())
        self.assertFalse(srv.scan_request_event.is_set())
        self.assertGreater(srv.list_schedules()[0]["next_run"], 0)

    def test_websocket_start_scan_enforces_scope(self):
        # Codex指摘(High): WS 経由の start_scan もスコープ検査を通すこと。
        import json
        srv = MonitorServer(port=0, auth_token="")
        srv.allowed_target_hosts = ["example.com"]
        srv._handle_client_message(json.dumps({"action": "start_scan", "config": {"url": "http://evil.com"}}))
        self.assertFalse(srv.scan_request_event.is_set())
        srv._handle_client_message(json.dumps({"action": "start_scan", "config": {"url": "http://example.com"}}))
        self.assertTrue(srv.scan_request_event.is_set())

    def test_scope_covers_all_target_urls(self):
        # Codex指摘(High): url だけでなく target_urls / login_url 等も検査。
        srv = MonitorServer(port=0, auth_token="")
        srv.allowed_target_hosts = ["example.com"]
        self.assertIsNotNone(srv._config_scope_error({"url": "http://example.com", "target_urls": "http://evil.com"}))
        self.assertIsNotNone(srv._config_scope_error({"url": "http://example.com", "login_url": "http://evil.com/login"}))
        self.assertIsNone(srv._config_scope_error({"url": "http://example.com", "target_urls": ["http://a.example.com"]}))

    def test_manual_crawl_enforces_scope(self):
        srv = MonitorServer(port=0, auth_token="")
        srv.allowed_target_hosts = ["example.com"]
        c = TestClient(srv.app)
        self.assertEqual(c.post("/api/v1/manual-crawl/start", json={"url": "http://evil.com"}).status_code, 403)

    def test_trust_proxy_uses_forwarded_for(self):
        srv = MonitorServer(port=0, auth_token="")

        class _Req:
            def __init__(self, xff, host):
                self.headers = {"x-forwarded-for": xff} if xff else {}
                self.client = type("C", (), {"host": host})()

        srv.trust_proxy = False
        self.assertEqual(srv._client_ip(_Req("1.2.3.4", "10.0.0.1")), "10.0.0.1")
        srv.trust_proxy = True
        self.assertEqual(srv._client_ip(_Req("1.2.3.4, 10.0.0.1", "10.0.0.1")), "1.2.3.4")

    def test_login_lockout_after_repeated_failures(self):
        srv = MonitorServer(port=0, auth_token="secret")
        c = TestClient(srv.app)
        codes = [
            c.post("/login", data={"token": "wrong"}, follow_redirects=False).status_code
            for _ in range(MonitorServer._LOGIN_MAX_FAILS + 1)
        ]
        self.assertEqual(codes[-1], 429)  # 上限超過でロックアウト
        self.assertTrue(all(x == 401 for x in codes[:-1]))


if __name__ == "__main__":
    unittest.main()
