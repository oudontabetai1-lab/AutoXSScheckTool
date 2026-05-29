"""Tests for the server portal: scan history, report serving, downloads,
deletion and scan management endpoints."""
import io
import json
import shutil
import unittest
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

import wscan.monitor as monitor_mod
from wscan.monitor import MonitorServer


class PortalTestBase(unittest.TestCase):
    SCAN_ID = "20260529_120000"

    def setUp(self):
        self.tmp = Path("/tmp/wscan_portal_test")
        if self.tmp.exists():
            shutil.rmtree(self.tmp)
        self.tmp.mkdir(parents=True)
        # Redirect the module-level output base at the temp dir.
        self._orig_base = monitor_mod.OUTPUT_BASE
        monitor_mod.OUTPUT_BASE = self.tmp
        self._make_scan(self.SCAN_ID)
        self.srv = MonitorServer(port=9000, auth_token=self.auth_token())
        self.client = TestClient(self.srv.app)

    def tearDown(self):
        monitor_mod.OUTPUT_BASE = self._orig_base
        shutil.rmtree(self.tmp, ignore_errors=True)

    def auth_token(self):
        return ""

    def _make_scan(self, sid, findings=None):
        d = self.tmp / sid
        d.mkdir()
        (d / "report.html").write_text(
            "<html><body><h1>RPT</h1><a href='evidence.json'>e</a></body></html>",
            encoding="utf-8",
        )
        (d / "evidence.json").write_text(json.dumps({
            "target": "https://target.example.com",
            "scan_date": "2026-05-29T12:00:00",
            "findings": findings if findings is not None else [
                {"severity": "critical"}, {"severity": "high"},
                {"severity": "high"}, {"severity": "low"},
            ],
        }), encoding="utf-8")
        (d / "screenshots").mkdir()
        (d / "screenshots" / "x.txt").write_text("img", encoding="utf-8")
        return d


class PortalEndpointTests(PortalTestBase):
    def test_portal_and_monitor_pages(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Server Portal", r.text)
        self.assertEqual(self.client.get("/monitor").status_code, 200)

    def test_list_scans_summary(self):
        scans = self.client.get("/api/v1/scans").json()["scans"]
        self.assertEqual(len(scans), 1)
        s = scans[0]
        self.assertEqual(s["id"], self.SCAN_ID)
        self.assertEqual(s["target"], "https://target.example.com")
        self.assertEqual(s["findings_count"], 4)
        self.assertEqual(s["severity"]["critical"], 1)
        self.assertEqual(s["severity"]["high"], 2)
        self.assertTrue(s["report_available"])
        self.assertEqual(s["status"], "done")

    def test_running_scan_marked_scanning(self):
        self.srv.scan_in_progress = True
        self.srv.current_scan_id = self.SCAN_ID
        s = self.client.get("/api/v1/scans").json()["scans"][0]
        self.assertEqual(s["status"], "scanning")

    def test_serve_report_and_assets(self):
        self.assertIn("RPT", self.client.get(f"/reports/{self.SCAN_ID}/report.html").text)
        self.assertEqual(
            self.client.get(f"/reports/{self.SCAN_ID}/evidence.json").status_code, 200
        )
        # Empty path defaults to report.html
        self.assertIn("RPT", self.client.get(f"/reports/{self.SCAN_ID}/").text)

    def test_report_path_traversal_blocked(self):
        r = self.client.get(f"/reports/{self.SCAN_ID}/../../etc/passwd")
        self.assertIn(r.status_code, (403, 404))

    def test_report_unknown_scan_404(self):
        self.assertEqual(self.client.get("/reports/nope/report.html").status_code, 404)

    def test_zip_download(self):
        r = self.client.get(f"/api/v1/scans/{self.SCAN_ID}/download")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers["content-type"], "application/zip")
        zf = zipfile.ZipFile(io.BytesIO(r.content))
        names = zf.namelist()
        self.assertTrue(any("report.html" in n for n in names))
        self.assertTrue(any("evidence.json" in n for n in names))

    def test_delete_scan(self):
        self.assertEqual(
            self.client.delete(f"/api/v1/scans/{self.SCAN_ID}").status_code, 200
        )
        self.assertFalse((self.tmp / self.SCAN_ID).exists())
        self.assertEqual(self.client.get("/api/v1/scans").json()["scans"], [])

    def test_delete_missing_404(self):
        self.assertEqual(self.client.delete("/api/v1/scans/nope").status_code, 404)

    def test_cannot_delete_running_scan(self):
        self.srv.scan_in_progress = True
        self.srv.current_scan_id = self.SCAN_ID
        self.assertEqual(
            self.client.delete(f"/api/v1/scans/{self.SCAN_ID}").status_code, 409
        )

    def test_abort_idle_returns_409(self):
        self.assertEqual(self.client.post("/api/v1/scan/abort").status_code, 409)

    def test_abort_running_queues_command(self):
        self.srv.scan_in_progress = True
        r = self.client.post("/api/v1/scan/abort")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.srv.command_queue.get_nowait(), "abort")

    def test_unusual_scan_id_is_listed_and_deletable(self):
        # A scan dir name with a quote (possible from a custom output_dir) must
        # round-trip safely; the portal JS uses data attributes, never inline JS.
        weird = "scan_'oops"
        self._make_scan(weird, findings=[{"severity": "low"}])
        ids = [s["id"] for s in self.client.get("/api/v1/scans").json()["scans"]]
        self.assertIn(weird, ids)
        self.assertEqual(
            self.client.delete(
                "/api/v1/scans/" + __import__("urllib.parse", fromlist=["quote"]).quote(weird, safe="")
            ).status_code,
            200,
        )


class PortalAuthTests(PortalTestBase):
    def auth_token(self):
        return "tok"

    def test_portal_requires_auth(self):
        r = self.client.get("/", headers={"accept": "text/html"}, follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.client.get("/api/v1/scans").status_code, 401)

    def test_authed_access(self):
        self.client.post("/login", data={"token": "tok"})
        self.assertEqual(self.client.get("/api/v1/scans").status_code, 200)
        self.assertEqual(
            self.client.get(f"/reports/{self.SCAN_ID}/report.html").status_code, 200
        )


if __name__ == "__main__":
    unittest.main()
