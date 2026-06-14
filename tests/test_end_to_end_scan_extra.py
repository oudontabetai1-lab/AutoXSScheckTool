"""
追加の End-to-End 統合テスト：注入系クラスタ（OS/SSRF/NoSQL/DOM-XSS）を、
社内ツールポータルを模した realistic_intranet フィクスチャに対して実エンジンで
スキャンし、正解データと突き合わせる。

tests/test_end_to_end_scan.py と同じく opt-in（WSCAN_E2E=1）かつ Chromium が
必要。realistic_site が反射型/SQLi/SSTI 等をカバーするのに対し、本モジュールは
サーバサイド注入と DOM-based XSS の検出を実環境に近い文脈で検証する。

    WSCAN_E2E=1 python -m pytest tests/test_end_to_end_scan_extra.py -v
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import tempfile
import threading
import time
import unittest
from urllib.parse import urlparse

import uvicorn

from tests.fixtures.realistic_intranet import (
    EXPECTED_FINDINGS,
    SAFE_ENDPOINTS,
    create_app,
)
from wscan.engine import ScanEngine

# 検出が決定的な注入系チェック。
CHECKS = ["os", "ssrf", "nosql", "dom_xss"]
SCAN_TIMEOUT_S = 600  # payload mutation wave 追加分の余裕を見て延長


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _wait_until_serving(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with contextlib.closing(socket.create_connection(("127.0.0.1", port), 0.25)):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"fixture server never came up on port {port}")


def _e2e_enabled() -> bool:
    return os.environ.get("WSCAN_E2E", "").strip().lower() in {"1", "true", "yes", "on"}


def _chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return False
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False


async def _run_scan(port: int, output_dir: str):
    engine = ScanEngine(
        f"http://127.0.0.1:{port}/",
        checks=list(CHECKS),
        llm_provider="none",
        headless=True,
        output_dir=output_dir,
        open_report=False,
        enable_waf_detection=False,
        enable_ai_analysis=False,
        enable_payload_learning=False,
        enable_adaptive_payloads=False,
        enable_sitemap_crawl=False,
        depth=2,
        fast_mode=True,
        max_payloads=12,
        request_delay=0,
        use_planner=False,
        sarif=False,
        timeout=10,
        navigation_retries=0,
    )
    await asyncio.wait_for(engine.run(), timeout=SCAN_TIMEOUT_S)
    return engine


@unittest.skipUnless(_e2e_enabled(), "set WSCAN_E2E=1 to run the end-to-end browser scan")
@unittest.skipUnless(
    _chromium_available(),
    "Playwright Chromium browser is not installed (run: playwright install chromium)",
)
class EndToEndIntranetScanTests(unittest.TestCase):
    findings: list

    @classmethod
    def setUpClass(cls):
        cls._app = create_app()
        cls._port = _free_port()
        cls._config = uvicorn.Config(
            cls._app, host="127.0.0.1", port=cls._port, log_level="error"
        )
        cls._server = uvicorn.Server(cls._config)
        cls._thread = threading.Thread(target=cls._server.run, daemon=True)
        cls._thread.start()
        _wait_until_serving(cls._port)

        cls._tmp = tempfile.TemporaryDirectory()
        engine = asyncio.run(_run_scan(cls._port, cls._tmp.name))
        cls.findings = list(engine.all_findings)
        cls.reported = {
            (f.check_type, urlparse(f.url).path, f.field_name) for f in cls.findings
        }

    @classmethod
    def tearDownClass(cls):
        cls._server.should_exit = True
        cls._thread.join(timeout=5)
        cls._tmp.cleanup()

    def _matching(self, check: str, path: str, field: str) -> list:
        return [
            f
            for f in self.findings
            if f.check_type == check
            and urlparse(f.url).path == path
            and f.field_name == field
        ]

    def _findings_on_path(self, path: str) -> list:
        return [f for f in self.findings if urlparse(f.url).path == path]

    def test_scan_reported_some_findings(self):
        self.assertTrue(self.findings, "engine reported no findings at all")

    def test_every_planted_vulnerability_is_detected(self):
        for spec in EXPECTED_FINDINGS:
            with self.subTest(check=spec["check"], path=spec["path"], field=spec["field"]):
                matches = self._matching(spec["check"], spec["path"], spec["field"])
                self.assertTrue(
                    matches,
                    f"FALSE NEGATIVE: expected a '{spec['check']}' finding on "
                    f"{spec['path']} (field '{spec['field']}') — {spec['note']}. "
                    f"Reported instead: {sorted(self.reported)}",
                )

    def test_safe_endpoints_produce_no_findings(self):
        for spec in SAFE_ENDPOINTS:
            with self.subTest(path=spec["path"], field=spec["field"]):
                bogus = self._findings_on_path(spec["path"])
                self.assertEqual(
                    bogus,
                    [],
                    "FALSE POSITIVE: safe endpoint "
                    f"{spec['path']} (field '{spec['field']}') was flagged — "
                    f"{spec['note']}. Findings: "
                    f"{[(f.check_type, f.field_name, f.evidence[:80]) for f in bogus]}",
                )


if __name__ == "__main__":
    unittest.main()
