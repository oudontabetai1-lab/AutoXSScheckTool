"""実 XSSScanner の採点回帰。WSCAN_E2E opt-in で suite を一度だけ走らせる。"""
import os
from pathlib import Path

import pytest

from wscan.benchmark_fixtures import UvicornFixtureLauncher
from wscan.benchmark_model import load_manifest_file
from wscan.benchmark_runner import run_scanned_suite
from wscan.benchmark_scan import ScanEngineScanRunner

pytestmark = pytest.mark.skipif(
    os.environ.get("WSCAN_E2E", "").strip().lower() not in {"1", "true", "yes", "on"},
    reason="WSCAN_E2E opt-in required",
)


def _require_chromium():
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        if not Path(pw.chromium.executable_path).is_file():
            pytest.skip("Chromium is not installed (playwright install chromium)")
        # バイナリが存在しても起動できない場合は失敗として報告する。
        browser = pw.chromium.launch(headless=True)
        browser.close()


def _run_manifest(name: str, checks: set[str]):
    path = Path(__file__).resolve().parents[2] / "benchmarks/manifests" / name
    suite = load_manifest_file(path, registry_keys=checks)
    return run_scanned_suite(
        suite, launcher=UvicornFixtureLauncher(), scan_runner=ScanEngineScanRunner(),
        run_id="scanner-e2e", source_sha="test", manifest_digest="test",
        registry_digest="test", scan_timeout=900,
    )


def test_realistic_site_xss_scanner_scorecard():
    _require_chromium()
    out = _run_manifest("realistic_site_xss.yaml", {"xss"})
    assert "run_error" not in out, out
    assert out["case_counts"] == {"planned": 2, "completed": 2, "incomplete": 0}
    assert [c["classification"]["candidate"] for c in out["cases"]] == ["tp", "tn"], out


def test_realistic_site_sqli_scanner_scorecard():
    """実 SQLiScanner が /products=TP・/catalog=TN を採点する（0034-R3）。"""
    _require_chromium()
    out = _run_manifest("realistic_site_sqli.yaml", {"sqli"})
    assert "run_error" not in out, out
    assert out["case_counts"] == {"planned": 2, "completed": 2, "incomplete": 0}
    assert [c["classification"]["candidate"] for c in out["cases"]] == ["tp", "tn"], out
