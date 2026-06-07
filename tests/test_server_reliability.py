"""サーバーモードの信頼性機能のテスト。

- スキャン成果物 zip ダウンロードの正当性と一時ファイルの後始末。
- スキャン watchdog（上限時間超過で一度だけ abort を要求）。
"""
import glob
import io
import os
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

import wscan.monitor as monitor_mod
from wscan.monitor import MonitorServer
from fastapi.testclient import TestClient


class ZipDownloadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig = monitor_mod.OUTPUT_BASE
        monitor_mod.OUTPUT_BASE = self.tmp

    def tearDown(self):
        monitor_mod.OUTPUT_BASE = self._orig

    def test_download_returns_valid_zip_and_cleans_temp(self):
        d = self.tmp / "1700000000"
        d.mkdir()
        (d / "report.html").write_text("<html>r</html>")
        (d / "evidence.json").write_text("{}")
        srv = MonitorServer(port=0, auth_token="")
        c = TestClient(srv.app)
        r = c.get("/api/v1/scans/1700000000/download")
        self.assertEqual(r.status_code, 200)
        names = zipfile.ZipFile(io.BytesIO(r.content)).namelist()
        self.assertTrue(any(n.endswith("report.html") for n in names))
        # 一時 zip が残っていない（送信後に背景タスクで削除）
        leftover = glob.glob(os.path.join(tempfile.gettempdir(), "wscan-1700000000-*.zip"))
        self.assertEqual(leftover, [])

    def test_download_missing_scan_404(self):
        srv = MonitorServer(port=0, auth_token="")
        c = TestClient(srv.app)
        self.assertEqual(c.get("/api/v1/scans/nope/download").status_code, 404)


class WatchdogTests(unittest.TestCase):
    def test_fires_once_after_timeout(self):
        srv = MonitorServer(port=0, auth_token="")
        srv.scan_max_seconds = 60
        srv.scan_in_progress = True
        srv.mark_scan_started()
        srv._scan_started_at = time.time() - 120  # 2 分前に開始
        self.assertTrue(srv.watchdog_check())
        self.assertEqual(srv.command_queue.get_nowait(), "abort")
        self.assertFalse(srv.watchdog_check())  # 二度目は撃たない

    def test_disabled_when_no_limit(self):
        srv = MonitorServer(port=0, auth_token="")
        srv.scan_in_progress = True
        srv.mark_scan_started()
        srv._scan_started_at = time.time() - 10_000
        self.assertFalse(srv.watchdog_check())  # scan_max_seconds=0 → 無効

    def test_not_fired_within_limit(self):
        srv = MonitorServer(port=0, auth_token="")
        srv.scan_max_seconds = 600
        srv.scan_in_progress = True
        srv.mark_scan_started()
        self.assertFalse(srv.watchdog_check())


if __name__ == "__main__":
    unittest.main()
