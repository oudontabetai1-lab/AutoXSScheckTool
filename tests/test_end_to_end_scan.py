"""
End-to-end integration test: run the *real* scan engine (crawl → plan →
attack → verify) against the realistic-site fixture and check the results
against ground truth.

This is the test that surfaces bugs in the program itself:

* Every planted vulnerability (``EXPECTED_FINDINGS``) must be reported — a
  miss means a scanner regressed into a false negative.
* Every safe input (``SAFE_ENDPOINTS``) must stay clean — a report there is
  a false positive.

The scan drives a headless Chromium through Playwright and takes a few
minutes, so this module is opt-in: it only runs when ``WSCAN_E2E`` is set to
a truthy value (``1``/``true``/``yes``). It is also skipped when no browser
binary is available (e.g. a CI box without ``playwright install chromium``).
The scan is expensive, so it runs once in ``setUpClass`` and every assertion
reads the shared result.

    # run it explicitly:
    WSCAN_E2E=1 python -m pytest tests/test_end_to_end_scan.py -v
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

from tests.fixtures.realistic_site import (
    EXPECTED_FINDINGS,
    SAFE_ENDPOINTS,
    create_app,
)
from tests.fixtures.spa_app import app as spa_app
from wscan.engine import ScanEngine
from wscan.recall_gate import compute_recall

# Injection checks whose detection is deterministic over HTTP/Chromium.
CHECKS = ["xss", "sqli", "ssti", "path_traversal", "open_redirect", "header_injection"]


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
    """Quick probe so the module skips cleanly where no browser is installed."""
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


# Upper bound on the whole crawl→attack→verify pipeline. A real hang (e.g. a
# verifier that never returns) then fails the test instead of wedging the suite.
SCAN_TIMEOUT_S = 900  # payload mutation wave + XSS 発火トリガ層/追加フィクスチャ分の余裕


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
        max_payloads=8,
        request_delay=0,
        use_planner=False,
        sarif=False,
        timeout=8,
        navigation_retries=0,
    )
    await asyncio.wait_for(engine.run(), timeout=SCAN_TIMEOUT_S)
    return engine


async def _run_spa_json_scan(port: int, output_dir: str):
    engine = ScanEngine(
        f"http://127.0.0.1:{port}/",
        checks=["sqli"],
        llm_provider="none",
        headless=True,
        output_dir=output_dir,
        open_report=False,
        enable_waf_detection=False,
        enable_ai_analysis=False,
        enable_payload_learning=False,
        enable_payload_evolution=False,
        enable_payload_mutation=False,
        enable_adaptive_payloads=False,
        enable_sitemap_crawl=False,
        spa_crawl=True,
        depth=1,
        fast_mode=True,
        max_payloads=4,
        request_delay=0,
        use_planner=False,
        sarif=False,
        timeout=8,
        navigation_retries=0,
    )
    await asyncio.wait_for(engine.run(), timeout=SCAN_TIMEOUT_S)
    return engine


@unittest.skipUnless(_e2e_enabled(), "set WSCAN_E2E=1 to run the end-to-end browser scan")
@unittest.skipUnless(
    _chromium_available(),
    "Playwright Chromium browser is not installed (run: playwright install chromium)",
)
class EndToEndRealisticScanTests(unittest.TestCase):
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
        cls.pages_crawled = len(getattr(engine, "page_graph", {}) or {})
        # (check_type, path, field) tuples actually reported
        cls.reported = {
            (f.check_type, urlparse(f.url).path, f.field_name) for f in cls.findings
        }

    @classmethod
    def tearDownClass(cls):
        cls._server.should_exit = True
        cls._thread.join(timeout=5)
        cls._tmp.cleanup()

    # ── helpers ──────────────────────────────────────────────────────────
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

    # ── sanity ───────────────────────────────────────────────────────────
    def test_crawl_reached_the_planted_pages(self):
        # depth=2 from the home page must reach every section linked in the nav.
        self.assertGreaterEqual(
            self.pages_crawled,
            6,
            f"crawl only reached {self.pages_crawled} page(s); "
            "the realistic site links many sections from home",
        )

    def test_scan_reported_some_findings(self):
        self.assertTrue(self.findings, "engine reported no findings at all")

    # ── true positives: no false negatives ──────────────────────────────
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

    def test_recall_gate_is_100_percent(self):
        # ADR-0016 / PRINCIPLE-001: 固定 ground truth に対し recall 100% を単一のリリースゲート
        # として要求する（有効化した CHECKS のみを分母にする）。個別 subTest の集約＋recall 数値と
        # 見逃し一覧を1メッセージで surface する。
        report = compute_recall(EXPECTED_FINDINGS, self.reported, target_checks=CHECKS)
        self.assertTrue(
            report.is_complete,
            "RECALL REGRESSION (見逃し発生):\n" + report.describe(),
        )

    def test_detected_vulnerabilities_survive_verification(self):
        # The engine re-checks findings in its verify phase; a planted, truly
        # reproducible vulnerability should not be marked unverified.
        for spec in EXPECTED_FINDINGS:
            with self.subTest(check=spec["check"], path=spec["path"], field=spec["field"]):
                matches = self._matching(spec["check"], spec["path"], spec["field"])
                if not matches:
                    self.skipTest("covered by the false-negative test")
                self.assertTrue(
                    any(f.verified for f in matches),
                    f"'{spec['check']}' on {spec['path']} was detected but every "
                    f"instance was marked UNVERIFIED — the verifier cannot "
                    f"reproduce a real vulnerability ({spec['note']}).",
                )

    # ── true negatives: no false positives ──────────────────────────────
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


@unittest.skipUnless(_e2e_enabled(), "set WSCAN_E2E=1 to run the end-to-end browser scan")
@unittest.skipUnless(
    _chromium_available(),
    "Playwright Chromium browser is not installed (run: playwright install chromium)",
)
class EndToEndSpaJsonSqlInjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._port = _free_port()
        cls._config = uvicorn.Config(
            spa_app, host="127.0.0.1", port=cls._port, log_level="error"
        )
        cls._server = uvicorn.Server(cls._config)
        cls._thread = threading.Thread(target=cls._server.run, daemon=True)
        cls._thread.start()
        _wait_until_serving(cls._port)

        cls._tmp = tempfile.TemporaryDirectory()
        cls.engine = asyncio.run(_run_spa_json_scan(cls._port, cls._tmp.name))
        cls.findings = list(cls.engine.all_findings)

    @classmethod
    def tearDownClass(cls):
        cls._server.should_exit = True
        cls._thread.join(timeout=5)
        cls._tmp.cleanup()

    def _json_sqli_on(self, path: str) -> list:
        return [
            finding
            for finding in self.findings
            if finding.check_type == "sqli"
            and urlparse(finding.url).path == path
            and finding.injection_location == "json_body"
        ]

    def test_spa_json_login_sqli_is_harvested_detected_and_verified(self):
        harvested = [
            ip
            for ip in self.engine.json_injection_points
            if urlparse(ip.url).path == "/api/login"
            and ip.parameter_id == "/email"
        ]
        self.assertTrue(harvested, "SPA harvest が /api/login の /email を収穫しなかった")

        matches = [
            finding
            for finding in self._json_sqli_on("/api/login")
            if finding.injection_pointer == "/email"
        ]
        self.assertTrue(matches, "JSON body SQLi が end-to-end で検出されなかった")
        self.assertTrue(
            any(finding.verified for finding in matches),
            "JSON body SQLi が verify で再現されなかった",
        )

    def test_safe_json_login_twin_produces_no_sqli_finding(self):
        self.assertEqual(
            self._json_sqli_on("/api/login_safe"),
            [],
            "安全ツイン /api/login_safe が SQLi と誤検出された",
        )


if __name__ == "__main__":
    unittest.main()
