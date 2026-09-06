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


def test_realistic_intranet_injection_scanner_scorecard():
    """realistic_intranet の HTTP 注入系 4 scanner（os/ssrf/nosql/dom_xss）を実採点する（0034-R3）。

    各 check の vulnerable=TP・safe twin=TN を確認し、recall/precision 100% を固定する。
    manifest 順（os→ssrf→nosql→dom_xss、各 vulnerable→safe）に tp/tn が並ぶ。
    """
    _require_chromium()
    out = _run_manifest(
        "realistic_intranet_injection.yaml", {"os", "ssrf", "nosql", "dom_xss"}
    )
    assert "run_error" not in out, out
    assert out["case_counts"] == {"planned": 8, "completed": 8, "incomplete": 0}
    assert [c["classification"]["candidate"] for c in out["cases"]] == [
        "tp", "tn", "tp", "tn", "tp", "tn", "tp", "tn",
    ], out


def test_realistic_site_injection_scanner_scorecard():
    """ssti/path_traversal/open_redirect を実 scanner で採点（各 vuln=TP・safe twin=TN・0034-R3）。"""
    _require_chromium()
    out = _run_manifest(
        "realistic_site_injection.yaml", {"ssti", "path_traversal", "open_redirect"}
    )
    assert "run_error" not in out, out
    assert out["case_counts"] == {"planned": 6, "completed": 6, "incomplete": 0}
    # manifest 順: 各 check の vulnerable→safe twin。
    assert [c["classification"]["candidate"] for c in out["cases"]] == [
        "tp", "tn", "tp", "tn", "tp", "tn",
    ], out


def test_realistic_site_header_injection_scanner_scorecard():
    """header_injection（CRLF レスポンスヘッダ注入）を実 scanner で採点（0034-R3）。

    /locale?lang=（脆弱）=TP・/locale-safe?lang=（allow-list 検証の安全ツイン）=TN。
    """
    _require_chromium()
    out = _run_manifest("realistic_site_header_injection.yaml", {"header_injection"})
    assert "run_error" not in out, out
    assert out["case_counts"] == {"planned": 2, "completed": 2, "incomplete": 0}
    assert [c["classification"]["candidate"] for c in out["cases"]] == ["tp", "tn"], out


def test_realistic_healthcare_ldap_scanner_scorecard():
    """realistic_healthcare の LDAP 注入を実 scanner で採点する（0034-R3）。

    /directory/lookup?user=（uid フィルタへ生展開）=TP・/directory/search?name=
    （RFC4515 エスケープの安全ツイン）=TN。
    """
    _require_chromium()
    out = _run_manifest("realistic_healthcare_ldap.yaml", {"ldap"})
    assert "run_error" not in out, out
    assert out["case_counts"] == {"planned": 2, "completed": 2, "incomplete": 0}
    assert [c["classification"]["candidate"] for c in out["cases"]] == ["tp", "tn"], out


def test_realistic_healthcare_security_headers_scanner_scorecard():
    """realistic_healthcare の security_headers（page 観測系＝passive）を実採点する（0034-R3）。

    /legacy/status（セキュリティヘッダ欠落）=TP・/legacy/status-secure（全付与の安全ツイン）=TN。
    注入点を持たない passive check を (check, path) で採点する scorer 拡張の回帰でもある。
    """
    _require_chromium()
    out = _run_manifest("realistic_healthcare_security_headers.yaml", {"security_headers"})
    assert "run_error" not in out, out
    assert out["case_counts"] == {"planned": 2, "completed": 2, "incomplete": 0}
    assert [c["classification"]["candidate"] for c in out["cases"]] == ["tp", "tn"], out


def test_realistic_healthcare_js_static_scanner_scorecard():
    """realistic_healthcare の js_static（first-party JS の source→sink＝passive）を実採点する（0034-R3）。

    /portal/notice（location.search→innerHTML）=TP・/portal/notice-safe（安全ツイン）=TN。
    passive(page観測系)採点の 2 つ目の check としての回帰でもある。
    """
    _require_chromium()
    out = _run_manifest("realistic_healthcare_page_observation.yaml", {"js_static"})
    assert "run_error" not in out, out
    assert out["case_counts"] == {"planned": 2, "completed": 2, "incomplete": 0}
    assert [c["classification"]["candidate"] for c in out["cases"]] == ["tp", "tn"], out
