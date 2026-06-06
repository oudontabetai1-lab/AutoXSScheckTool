"""サーバー設定(通知/スケジュール)の永続化と API のテスト。

Codex レビュー指摘の回帰防止:
- 設定ファイルの atomic write と破損時の退避（データ消失防止）。
- 通知設定のマスク返却・既存値維持。
"""
import tempfile
import unittest
from pathlib import Path

import wscan.monitor as monitor_mod
from wscan.monitor import MonitorServer
from fastapi.testclient import TestClient


class ServerSettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig_base = monitor_mod.OUTPUT_BASE
        monitor_mod.OUTPUT_BASE = self.tmp
        self.srv = MonitorServer(port=0, auth_token="")
        self.client = TestClient(self.srv.app)

    def tearDown(self):
        monitor_mod.OUTPUT_BASE = self._orig_base

    def test_atomic_save_leaves_no_tmp_and_roundtrips(self):
        self.srv._save_settings({"notifications": {"webhook_url": "u"}, "schedules": [{"id": "x"}]})
        self.assertFalse((self.tmp / "wscan_settings.json.tmp").exists())
        self.assertEqual(self.srv._load_settings()["schedules"][0]["id"], "x")

    def test_corrupt_file_is_quarantined_not_swallowed(self):
        (self.tmp / "wscan_settings.json").write_text("{ broken json")
        self.assertEqual(self.srv._load_settings(), {})
        self.assertTrue((self.tmp / "wscan_settings.json.corrupt").exists())

    def test_settings_webhook_masked_and_preserved(self):
        self.client.post("/api/v1/settings", json={"notifications": {
            "webhook_url": "https://hooks.slack.com/services/AAA/BBB/secret", "enabled": True}})
        got = self.client.get("/api/v1/settings").json()["notifications"]
        self.assertTrue(got["webhook_set"])
        self.assertNotIn("secret", got["webhook_hint"])  # マスクされている
        # webhook_url 未指定の更新は既存値を維持
        self.client.post("/api/v1/settings", json={"notifications": {"enabled": False}})
        self.assertTrue(self.client.get("/api/v1/settings").json()["notifications"]["webhook_set"])

    def test_schedule_crud(self):
        r = self.client.post("/api/v1/schedules", json={"url": "http://t", "interval_hours": 6})
        sid = r.json()["schedule"]["id"]
        self.assertEqual(len(self.client.get("/api/v1/schedules").json()["schedules"]), 1)
        self.client.post(f"/api/v1/schedules/{sid}/toggle")
        self.assertFalse(self.srv.list_schedules()[0]["enabled"])
        self.assertEqual(
            self.client.request("DELETE", f"/api/v1/schedules/{sid}").status_code, 200
        )
        self.assertEqual(self.client.get("/api/v1/schedules").json()["schedules"], [])

    def test_settings_file_not_listed_as_scan(self):
        self.srv._save_settings({"notifications": {"webhook_url": "u"}})
        self.assertEqual(self.client.get("/api/v1/scans").json()["scans"], [])


if __name__ == "__main__":
    unittest.main()
