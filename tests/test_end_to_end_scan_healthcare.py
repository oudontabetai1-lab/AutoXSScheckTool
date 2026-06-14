"""
End-to-End 統合テスト：患者ポータル realistic_healthcare に対して実エンジンで
注入系スキャンを回し、難易度段階付きの正解データと突き合わせる。

tests/test_end_to_end_scan.py（realistic_site）/ tests/test_end_to_end_scan_extra.py
（realistic_intranet）と同じく opt-in（WSCAN_E2E=1）かつ Chromium が必要。

    WSCAN_E2E=1 python -m pytest tests/test_end_to_end_scan_healthcare.py -v

設計（realistic_healthcare の難易度方針に整合）:

* ヘッダ/ページ系チェック（security_headers/clickjacking/cors/csrf/session/
  secret_leak/jwt/sri/host_header/info_disclosure）は「ヘッダの無いページすべて」で
  発火するため E2E には**載せない**（パス単位の安全判定を壊す）。これらは
  tests/test_realistic_healthcare_fixture.py の httpx 自己検証が担保する。
* 注入系のうち low/medium は決定的に検出できる前提で**必須**（検出漏れ=リグレッション）。
* high/ultra のうち現状のエンジンが確実に取れるものだけ必須にし、素朴な防御の
  バイパスを要する難問（boolean-blind/blind OS/二重エンコード等）は
  :data:`KNOWN_DETECTION_GAPS` として**ベンチマーク的に許容**（CLAUDE.md の ultra 方針）。
* 安全ツイン（注入系）からは finding ゼロ＝誤検知ガード（必須）。
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

from tests.fixtures.realistic_healthcare import (
    EXPECTED_FINDINGS,
    SAFE_ENDPOINTS,
    create_app,
)
from wscan.engine import ScanEngine

# E2E で検査する注入系チェック（ヘッダ/ページ系は httpx 自己検証に委譲）。
CHECKS = [
    "xss", "sqli", "ssti", "path_traversal", "open_redirect", "header_injection",
    "os", "ssrf", "nosql", "dom_xss", "ldap", "xxe", "stored_xss",
]

# 現状エンジンが確実には取れない高難度（素朴な防御をバイパスして初めて成立）。
# ここに挙げたものは検出されなくてもテストを失敗させない（CLAUDE.md: ultra 方針）。
# NOTE: blind OS (/tools/nslookup) は payload mutation wave（; sleep 3 等を確実に投入）で
#       検出可能になったためギャップから外した。残りはブラウザ駆動スキャン固有の壁:
#       - boolean-blind は応答類似度しきい値、
#       - ultra の 2 件は test_url_param のエンコードで NULL/バックスラッシュが
#         エンコードされ素のままブラウザへ届かない（生バイト依存のバイパス）。
KNOWN_DETECTION_GAPS = {
    ("sqli", "/pharmacy/refill"),       # high: boolean-based blind（類似度しきい値）
    ("path_traversal", "/vault/file"),  # ultra: 二重エンコード + NULL バイト（生バイト依存）
    ("open_redirect", "/sso/return"),   # ultra: '/\\' のブラウザ正規化（生バックスラッシュ依存）
}

# finding の field 名がスキャナ実装に依存して安定しないクラス（パス一致で判定）。
_FIELD_LENIENT_CHECKS = {"stored_xss"}

# payload mutation wave（未検出フィールドでバイパス変種を追加投入）でスキャンが重くなるため
# 既存 E2E より長めに確保する。
SCAN_TIMEOUT_S = 1500


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
        max_payloads=10,
        request_delay=0,
        use_planner=False,
        sarif=False,
        timeout=8,
        navigation_retries=0,
    )
    await asyncio.wait_for(engine.run(), timeout=SCAN_TIMEOUT_S)
    return engine


# 注入系 EXPECTED / SAFE のみ抽出（このモジュールが扱う対象）。
_INJ_EXPECTED = [s for s in EXPECTED_FINDINGS if s["check"] in CHECKS]
_INJ_SAFE = [s for s in SAFE_ENDPOINTS if s["check"] in CHECKS]


@unittest.skipUnless(_e2e_enabled(), "set WSCAN_E2E=1 to run the end-to-end browser scan")
@unittest.skipUnless(
    _chromium_available(),
    "Playwright Chromium browser is not installed (run: playwright install chromium)",
)
class EndToEndHealthcareScanTests(unittest.TestCase):
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

    # ── helpers ──────────────────────────────────────────────────────────
    def _detected(self, spec: dict) -> bool:
        """spec（正解データ1件）に対応する finding が出ているか。"""
        for f in self.findings:
            if f.check_type != spec["check"]:
                continue
            if urlparse(f.url).path != spec["path"]:
                continue
            if spec["check"] in _FIELD_LENIENT_CHECKS or f.field_name == spec["field"]:
                return True
        return False

    def _findings_on_path(self, path: str) -> list:
        return [f for f in self.findings if urlparse(f.url).path == path]

    # ── sanity ───────────────────────────────────────────────────────────
    def test_scan_reported_some_findings(self):
        self.assertTrue(self.findings, "engine reported no findings at all")

    # ── true positives：low/medium は検出必須 ────────────────────────────
    def test_low_and_medium_injection_detected(self):
        for spec in _INJ_EXPECTED:
            if spec["difficulty"] not in ("low", "medium"):
                continue
            with self.subTest(check=spec["check"], path=spec["path"], diff=spec["difficulty"]):
                self.assertTrue(
                    self._detected(spec),
                    f"FALSE NEGATIVE: expected a '{spec['check']}' finding on "
                    f"{spec['path']} (field '{spec['field']}', {spec['difficulty']}) — "
                    f"{spec['note']}. Reported: {sorted(self.reported)}",
                )

    # ── true positives：high/ultra のうち既知のギャップ以外は検出必須 ─────
    def test_high_and_ultra_injection_detected_except_known_gaps(self):
        for spec in _INJ_EXPECTED:
            if spec["difficulty"] not in ("high", "ultra"):
                continue
            if (spec["check"], spec["path"]) in KNOWN_DETECTION_GAPS:
                continue
            with self.subTest(check=spec["check"], path=spec["path"], diff=spec["difficulty"]):
                self.assertTrue(
                    self._detected(spec),
                    f"FALSE NEGATIVE ({spec['difficulty']}): expected '{spec['check']}' "
                    f"on {spec['path']} — {spec['note']}. "
                    f"既知ギャップなら KNOWN_DETECTION_GAPS へ追加。"
                    f"Reported: {sorted(self.reported)}",
                )

    # ── true negatives：注入系の安全ツインからは finding ゼロ ─────────────
    def test_injection_safe_twins_have_no_findings(self):
        safe_paths = {s["path"] for s in _INJ_SAFE}
        for path in sorted(safe_paths):
            with self.subTest(path=path):
                bogus = [
                    f for f in self._findings_on_path(path) if f.check_type in CHECKS
                ]
                self.assertEqual(
                    bogus,
                    [],
                    f"FALSE POSITIVE: safe twin {path} was flagged — "
                    f"{[(f.check_type, f.field_name, (f.evidence or '')[:80]) for f in bogus]}",
                )


if __name__ == "__main__":
    unittest.main()
