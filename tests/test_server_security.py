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


class IntranetBindTests(unittest.TestCase):
    """無認証起動を許可してよい bind 先（イントラネット）の判定。"""

    def test_loopback_is_intranet(self):
        from main import _bind_is_intranet
        self.assertTrue(_bind_is_intranet("127.0.0.1"))
        self.assertTrue(_bind_is_intranet("localhost"))
        self.assertTrue(_bind_is_intranet("::1"))

    def test_private_ranges_are_intranet(self):
        from main import _bind_is_intranet
        self.assertTrue(_bind_is_intranet("192.168.1.10"))
        self.assertTrue(_bind_is_intranet("10.0.0.5"))
        self.assertTrue(_bind_is_intranet("172.16.3.4"))

    def test_public_ip_is_not_intranet(self):
        from main import _bind_is_intranet
        self.assertFalse(_bind_is_intranet("8.8.8.8"))

    def test_unresolvable_host_is_not_intranet(self):
        from main import _bind_is_intranet
        self.assertFalse(_bind_is_intranet("not-an-ip"))


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

    def test_trailing_dot_does_not_bypass_deny(self):
        # Codex指摘(P2): "example.com." は example.com と同一ホスト → deny を回避させない。
        self.assertFalse(target_in_scope("http://example.com.", [], ["example.com"]))
        self.assertTrue(target_in_scope("http://example.com.", ["example.com"], []))

    def test_flow_navigate_urls_are_scoped(self):
        # Codex指摘(P1): フローの navigate 先もスコープ検査する。
        srv = MonitorServer(port=0, auth_token="")
        srv.allowed_target_hosts = ["example.com"]
        bad = {"url": "http://example.com",
               "flows": [{"name": "f", "steps": [{"action": "navigate", "url": "http://evil.com"}]}]}
        good = {"url": "http://example.com",
                "flows": [{"name": "f", "steps": [{"action": "navigate", "url": "http://a.example.com"}]}]}
        self.assertIsNotNone(srv._config_scope_error(bad))
        self.assertIsNone(srv._config_scope_error(good))

    def test_websocket_scan_start_is_audited(self):
        # Codex指摘(P2): WS 経由の開始も監査ログに残す。
        import json
        srv = MonitorServer(port=0, auth_token="")
        srv._handle_client_message(
            json.dumps({"action": "start_scan", "config": {"url": "http://t"}}), "9.9.9.9")
        aud = srv.read_audit()
        self.assertTrue(any(a["action"] == "scan_start" and a["ip"] == "9.9.9.9" for a in aud))

    def test_crawl_review_filters_out_of_scope(self):
        # Codex指摘(P1の補足): レビュー時追加の extra_urls / flows もスコープ外を除外。
        import json
        srv = MonitorServer(port=0, auth_token="")
        srv.allowed_target_hosts = ["example.com"]
        srv._handle_client_message(json.dumps({
            "action": "crawl_review", "command": "continue",
            "extra_urls": ["http://evil.com", "http://x.example.com"],
            "flows": [
                {"name": "bad", "steps": [{"action": "navigate", "url": "http://evil.com"}]},
                {"name": "ok", "steps": [{"action": "navigate", "url": "http://example.com/p"}]},
            ],
        }), "1.1.1.1")
        cra = srv.crawl_review_action
        self.assertEqual(cra["extra_urls"], ["http://x.example.com"])
        self.assertEqual([f["name"] for f in cra["flows"]], ["ok"])

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


class UploadEndpointTests(unittest.TestCase):
    """認証済みアップロードの拡張子・容量・保存先ガードを検証する。"""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self._orig = monitor_mod.OUTPUT_BASE
        monitor_mod.OUTPUT_BASE = self.tmp
        self.srv = MonitorServer(port=0, auth_token="upload-test-token")
        self.client = TestClient(self.srv.app)
        self.auth = {"Authorization": "Bearer upload-test-token"}

    def tearDown(self):
        monitor_mod.OUTPUT_BASE = self._orig
        self._tmpdir.cleanup()

    def test_upload_requires_auth_and_rejects_extension(self):
        files = {"file": ("payload.exe", b"not executable", "application/octet-stream")}
        self.assertEqual(self.client.post("/api/v1/upload", files=files).status_code, 401)
        response = self.client.post("/api/v1/upload", files=files, headers=self.auth)
        self.assertEqual(response.status_code, 400)
        self.assertIn("許可されない拡張子", response.json()["error"])
        self.assertFalse((self.tmp / "uploads").exists())

    def test_upload_rejects_over_8mb(self):
        files = {
            "file": (
                "too-large.json",
                b"x" * (monitor_mod._UPLOAD_MAX_BYTES + 1),
                "application/json",
            )
        }
        response = self.client.post("/api/v1/upload", files=files, headers=self.auth)
        self.assertEqual(response.status_code, 413)
        self.assertIn("最大8MB", response.json()["error"])

    def test_upload_sanitizes_name_and_stays_under_uploads(self):
        response = self.client.post(
            "/api/v1/upload",
            files={"file": ("../認証 cert.pem", b"certificate", "application/x-pem-file")},
            headers=self.auth,
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["name"], "___cert.pem")
        dest = Path(body["path"]).resolve()
        dest.relative_to((self.tmp / "uploads").resolve())
        self.assertEqual(dest.read_bytes(), b"certificate")
        self.assertNotIn("uploads", [scan["id"] for scan in self.srv._list_scans()])
        audit = self.srv.read_audit(1)[0]
        self.assertEqual(audit["detail"], body["name"])
        self.assertNotIn(str(dest), audit["detail"])

    def test_uploaded_secrets_not_reachable_via_scan_routes(self):
        # アップロードした秘匿ファイル(TLS秘密鍵/TOTP QR)は uploads/ に保存されるが、
        # scan_id=uploads として artifact ルート(download/reports/delete)から
        # 取得・削除できてはならない。一覧から隠すだけでなく解決口 _scan_dir で拒否する。
        up = self.client.post(
            "/api/v1/upload",
            files={
                "file": (
                    "client.key",
                    b"-----BEGIN PRIVATE KEY-----",
                    "application/octet-stream",
                )
            },
            headers=self.auth,
        )
        self.assertEqual(up.status_code, 200)
        fname = Path(up.json()["path"]).name

        # 中央リゾルバが予約名を拒否（大文字・前後空白のゆらぎも）。
        self.assertIsNone(self.srv._scan_dir("uploads"))
        self.assertIsNone(self.srv._scan_dir("UPLOADS"))
        self.assertIsNone(self.srv._scan_dir(" uploads "))

        # zip 一括DL・個別レポート取得・削除がいずれも 404。
        self.assertEqual(
            self.client.get("/api/v1/scans/uploads/download", headers=self.auth).status_code,
            404,
        )
        self.assertEqual(
            self.client.get(f"/reports/uploads/{fname}", headers=self.auth).status_code,
            404,
        )
        self.assertEqual(
            self.client.delete("/api/v1/scans/uploads", headers=self.auth).status_code,
            404,
        )
        # サーバ側の実体はエンジンが読むため残っている（アクセス経路だけを塞ぐ）。
        self.assertTrue((self.tmp / "uploads" / fname).exists())


if __name__ == "__main__":
    unittest.main()
