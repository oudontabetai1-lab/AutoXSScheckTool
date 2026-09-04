"""0016: check レベル coverage の純粋集計テスト。"""
from wscan.check_coverage import compute_check_coverage


def test_partial_when_subset_selected():
    c = compute_check_coverage(["sqli", "xss", "os", "ssti"], ["sqli", "xss"])
    assert c["registry_total"] == 4
    assert c["selected"] == ["sqli", "xss"]
    assert c["selected_count"] == 2
    assert c["not_selected"] == ["os", "ssti"]
    assert c["not_selected_count"] == 2
    assert c["coverage_status"] == "PARTIAL"


def test_complete_when_all_selected():
    c = compute_check_coverage(["a", "b"], ["b", "a"])
    assert c["coverage_status"] == "COMPLETE"
    assert c["not_selected"] == []


def test_incomplete_when_none_selected():
    c = compute_check_coverage(["a", "b"], [])
    assert c["coverage_status"] == "INCOMPLETE"
    assert c["selected"] == []
    assert c["not_selected"] == ["a", "b"]


def test_unknown_selected_is_surfaced():
    c = compute_check_coverage(["a", "b"], ["a", "zzz"])
    assert c["unknown_selected"] == ["zzz"]
    assert c["selected"] == ["a"]  # registry 内のみ selected 扱い
    assert c["coverage_status"] == "PARTIAL"


def test_per_check_entries_and_dedup():
    c = compute_check_coverage(["a", "a", "b"], ["a"])
    # 重複 registry は畳む
    assert c["registry_total"] == 2
    assert c["checks"]["a"]["selected"] is True
    assert c["checks"]["b"]["selected"] is False


def test_registry_matches_real_scanners_default_is_partial():
    from wscan.scanners import SCANNERS
    c = compute_check_coverage(
        SCANNERS.keys(), ["sqli", "xss", "os"],
        contracts={k: v.CONTRACT for k, v in SCANNERS.items()},
    )
    assert c["registry_total"] == len(SCANNERS)
    assert c["coverage_status"] == "PARTIAL"
    assert c["selected_count"] == 3
    # contract 文脈が載る
    assert "state_change" in c["checks"]["sqli"]
    assert "prerequisites" in c["checks"]["sqli"]


def test_coverage_summary_text_appends_check_coverage_when_present():
    from wscan.engine import _coverage_summary_text
    base = {"reached_count": 1, "attempts": 4, "http_status": {"blocked": 2}}
    # check_coverage 無し → 従来どおり（後方互換）
    assert _coverage_summary_text(base) == "Coverage: reached URLs=1 / attempts=4 / blocked=2"
    # check_coverage 有り → 「N/M run (STATUS)」を併記
    withcc = dict(base, check_coverage={
        "selected_count": 3, "registry_total": 36, "coverage_status": "PARTIAL",
    })
    assert _coverage_summary_text(withcc) == (
        "Coverage: reached URLs=1 / attempts=4 / blocked=2 / checks 3/36 in-scope (PARTIAL)"
    )


def test_coverage_html_renders_check_coverage(tmp_path):
    from wscan.report import ReportGenerator
    coverage = {
        "reached_count": 1, "attempts": 4, "findings_total": 0,
        "http_status": {"total": 4, "blocked": 0},
        "by_status": {}, "reached_urls": [], "unreached": [],
        "check_coverage": {
            "registry_total": 36, "selected_count": 3, "coverage_status": "PARTIAL",
            "not_selected": ["cms", "cors", "csrf"],
        },
    }
    html = ReportGenerator(tmp_path)._build_coverage_html(coverage)
    assert "検査カバレッジ（in-scope の scanner）" in html
    assert "<strong>3</strong>" in html and "<strong>36</strong>" in html
    assert "PARTIAL" in html
    # 未実行の検査名が出る
    assert "cms" in html and "cors" in html
    # PARTIAL 警告（0件≠安全）
    assert "「安全」とは限りません" in html


def test_coverage_summary_union_surfaces_unknown_and_autoenabled():
    """coverage_summary の check_coverage は checks(設定) と scanners(実体) の union を使い、
    誤記 check（unknown_selected）と auto-enable scanner（selected）の両方を取りこぼさない。"""
    from types import SimpleNamespace
    from wscan.engine import ScanEngine

    engine = SimpleNamespace(
        checks=["xss", "xs"],                 # xs は誤記（registry 外）
        scanners={"xss": object(), "privesc": object()},  # privesc は auto-enable（checks 外）
        visited_urls=set(), reached_urls=set(), scan_matrix=[], all_findings=[],
    )
    cc = ScanEngine.coverage_summary(engine)["check_coverage"]
    assert "xs" in cc["unknown_selected"]          # 誤記が診断に出る
    assert "xss" in cc["selected"] and "privesc" in cc["selected"]  # auto-enable も in-scope


def test_coverage_html_warns_on_unknown_configured_checks(tmp_path):
    from wscan.report import ReportGenerator
    coverage = {
        "reached_count": 0, "attempts": 0, "findings_total": 0,
        "http_status": {}, "by_status": {}, "reached_urls": [], "unreached": [],
        "check_coverage": {
            "registry_total": 36, "selected_count": 36, "coverage_status": "COMPLETE",
            "not_selected": [], "unknown_selected": ["xs"],
        },
    }
    html = ReportGenerator(tmp_path)._build_coverage_html(coverage)
    # COMPLETE でも誤記 xs が設定警告として出る
    assert "未知の検査名" in html
    assert "xs" in html
