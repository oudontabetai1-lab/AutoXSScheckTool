"""サーバーモードの信頼性機能のテスト。

- スキャン成果物 zip ダウンロードの正当性と一時ファイルの後始末。
- スキャン watchdog（上限時間超過で一度だけ abort を要求）。
"""
import asyncio
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


class PendingInteractiveReplayTests(unittest.TestCase):
    """再接続時のイベント履歴再生で、解決済みの一過性モーダル
    (crawl_review / plan_review / awaiting_config) を亡霊表示しないことを検証。

    再現していた不具合:
    - レビューを操作で閉じても、WS 再接続/リロードで履歴が再生されて再表示される。
    - 1スキャン完了後、2回目のスキャン準備中に前スキャンの巡回レビューが出てくる。
    """

    def test_emit_crawl_review_marks_pending(self):
        srv = MonitorServer(port=0, auth_token="")
        asyncio.run(srv.emit_crawl_review([{"url": "http://x/"}]))
        self.assertIsNotNone(srv.pending_interactive)
        self.assertEqual(srv.pending_interactive["type"], "crawl_review")

    def test_resolving_crawl_review_clears_pending(self):
        srv = MonitorServer(port=0, auth_token="")
        asyncio.run(srv.emit_crawl_review([{"url": "http://x/"}]))
        srv._handle_client_message('{"action":"crawl_review","command":"continue"}')
        self.assertIsNone(srv.pending_interactive)

    def test_resolving_plan_review_clears_pending(self):
        srv = MonitorServer(port=0, auth_token="")
        asyncio.run(srv.emit_plan_review([{"url": "http://x/"}]))
        self.assertEqual(srv.pending_interactive["type"], "plan_review")
        srv._handle_client_message('{"action":"plan_confirm","edits":{}}')
        self.assertIsNone(srv.pending_interactive)

    def test_awaiting_config_marks_pending(self):
        srv = MonitorServer(port=0, auth_token="")
        asyncio.run(srv.emit_awaiting_config())
        self.assertEqual(srv.pending_interactive["type"], "awaiting_config")

    def test_replay_suppresses_resolved_review(self):
        """解決済み(crawl_review を履歴に持つが pending=None)では再接続で再生されない。"""
        srv = MonitorServer(port=0, auth_token="")
        srv.event_history.append({"type": "crawl_review", "timestamp": 0, "data": {"pages": []}})
        srv.event_history.append({"type": "finding", "timestamp": 0, "data": {"id": 1}})
        srv.pending_interactive = None  # 既に操作で解決済み
        # crawl_review は再生抑制対象として宣言されている
        self.assertIn("crawl_review", MonitorServer._REPLAY_SUPPRESS_TYPES)
        c = TestClient(srv.app)
        with c.websocket_connect("/ws") as ws:
            msg = ws.receive_json()  # 抑制されない finding が先頭に届く
            self.assertEqual(msg["type"], "finding")
            ws.close()

    def test_replay_redelivers_unresolved_review(self):
        """未解決(pending=crawl_review)なら再接続で1件だけ再送される。"""
        srv = MonitorServer(port=0, auth_token="")
        srv.event_history.append({"type": "crawl_review", "timestamp": 0, "data": {"pages": []}})
        srv.event_history.append({"type": "finding", "timestamp": 0, "data": {"id": 1}})
        srv.pending_interactive = {"type": "crawl_review", "timestamp": 1, "data": {"pages": []}}
        c = TestClient(srv.app)
        with c.websocket_connect("/ws") as ws:
            first = ws.receive_json()
            second = ws.receive_json()
            ws.close()
        self.assertEqual(first["type"], "finding")        # 履歴中の crawl_review は抑制
        self.assertEqual(second["type"], "crawl_review")  # pending を末尾に1件だけ再送


if __name__ == "__main__":
    unittest.main()
