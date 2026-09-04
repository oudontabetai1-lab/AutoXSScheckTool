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


def test_coverage_summary_text_appends_prerequisite_warnings():
    """前提不足/state profile skip 数を console 要約へ併記する（--no-monitor/バッチ観測性・0016）。"""
    from wscan.engine import _coverage_summary_text
    base = {"reached_count": 0, "attempts": 0, "http_status": {"blocked": 0}}
    # 前提不足も skip も無ければ従来どおり（noise を出さない）
    quiet = dict(base, prerequisite_coverage={
        "prerequisite_missing_count": 0, "state_profile_skipped_count": 0,
    })
    assert "unmet-prereq" not in _coverage_summary_text(quiet)
    assert "profile-skipped" not in _coverage_summary_text(quiet)
    # 警告があれば件数を併記
    warned = dict(base, prerequisite_coverage={
        "prerequisite_missing_count": 2, "state_profile_skipped_count": 3,
    })
    text = _coverage_summary_text(warned)
    assert "unmet-prereq 2" in text and "profile-skipped 3" in text


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


def test_prerequisite_coverage_classifies_runnable_and_missing():
    from wscan.check_coverage import compute_prerequisite_coverage
    from types import SimpleNamespace as NS
    contracts = {
        "needs_api": NS(prerequisites=[NS(value="api_spec")]),
        "needs_browser": NS(prerequisites=[NS(value="browser")]),
        "no_contract": None,
    }
    out = compute_prerequisite_coverage(
        ["needs_api", "needs_browser", "no_contract"],
        contracts,
        available_prerequisites={"browser", "second_request"},
    )
    # browser は充足 → runnable。api_spec は欠落 → missing（理由付き）。CONTRACT 無しは除外。
    assert out["runnable"] == ["needs_browser"]
    assert out["prerequisite_missing_count"] == 1
    m = out["prerequisite_missing"][0]
    assert m["check"] == "needs_api"
    assert m["missing_prerequisites"] == ["api_spec"]
    assert m["reasons"] and "API 仕様" in m["reasons"][0]


def test_prerequisite_coverage_all_available_when_env_satisfies():
    from wscan.check_coverage import compute_prerequisite_coverage
    from types import SimpleNamespace as NS
    contracts = {"needs_oob": NS(prerequisites=[NS(value="oob_sink")])}
    out = compute_prerequisite_coverage(
        ["needs_oob"], contracts, available_prerequisites={"oob_sink"}
    )
    assert out["runnable"] == ["needs_oob"]
    assert out["prerequisite_missing"] == []


def test_coverage_summary_flags_prerequisite_missing_for_api_spec():
    """mass_assignment は api_spec 前提。消費可能な mutation テンプレートが無ければ前提不足（0016）。"""
    from types import SimpleNamespace
    from wscan.engine import ScanEngine
    engine = SimpleNamespace(
        checks=["mass_assignment"], scanners={"mass_assignment": object()},
        api_seed_requests=[],  # 未設定 → api_spec 欠落
        visited_urls=set(), reached_urls=set(), scan_matrix=[], all_findings=[],
    )
    pc = ScanEngine.coverage_summary(engine)["prerequisite_coverage"]
    names = [m["check"] for m in pc["prerequisite_missing"]]
    assert "mass_assignment" in names

    # POST テンプレート（mass_assignment が消費できる）→ 充足
    engine.api_seed_requests = [SimpleNamespace(url="http://t/api", method="POST")]
    pc2 = ScanEngine.coverage_summary(engine)["prerequisite_coverage"]
    names2 = [m["check"] for m in pc2["prerequisite_missing"]]
    assert "mass_assignment" not in names2


def test_coverage_summary_api_spec_needs_consumable_mutation_template():
    """GET/DELETE のみの seed は mass_assignment が消費できず、api_spec は充足しない（Codex P2）。"""
    from types import SimpleNamespace
    from wscan.engine import ScanEngine
    engine = SimpleNamespace(
        checks=["mass_assignment"], scanners={"mass_assignment": object()},
        api_seed_requests=[
            SimpleNamespace(url="http://t/api", method="GET"),
            SimpleNamespace(url="http://t/api/1", method="DELETE"),
        ],
        visited_urls=set(), reached_urls=set(), scan_matrix=[], all_findings=[],
    )
    pc = ScanEngine.coverage_summary(engine)["prerequisite_coverage"]
    # 非空 seed でも消費可能な POST/PUT/PATCH が無いので前提不足のまま。
    assert "mass_assignment" in [m["check"] for m in pc["prerequisite_missing"]]


def test_prerequisite_coverage_read_only_skips_state_changing():
    """read-only は state_change=always の scanner を skip として計上する（Codex P1）。"""
    from wscan.check_coverage import compute_prerequisite_coverage
    from types import SimpleNamespace as NS
    contracts = {
        "mass_assignment": NS(state_change=NS(value="always"),
                              prerequisites=[NS(value="api_spec")]),
        "xss": NS(state_change=NS(value="conditional"), prerequisites=[]),
    }
    # read-only + api_spec 充足でも mass_assignment は profile skip（前提充足より優先）。
    out = compute_prerequisite_coverage(
        ["mass_assignment", "xss"], contracts,
        available_prerequisites={"api_spec", "browser"},
        state_profile="read-only",
    )
    skipped = [s["check"] for s in out["state_profile_skipped"]]
    assert "mass_assignment" in skipped
    assert out["state_profile_skipped"][0]["reason"]  # 理由が付く
    assert "mass_assignment" not in [m["check"] for m in out["prerequisite_missing"]]
    assert out["runnable"] == ["xss"]  # conditional は skip されない

    # unrestricted では profile skip しない（api_spec 充足なら runnable）。
    out2 = compute_prerequisite_coverage(
        ["mass_assignment"], contracts,
        available_prerequisites={"api_spec"}, state_profile="unrestricted",
    )
    assert out2["state_profile_skipped"] == []
    assert out2["runnable"] == ["mass_assignment"]


def test_coverage_summary_read_only_profile_flags_state_changing_skip():
    from types import SimpleNamespace
    from wscan.engine import ScanEngine
    engine = SimpleNamespace(
        checks=["mass_assignment"], scanners={"mass_assignment": object()},
        api_seed_requests=[{"url": "http://t/api"}],  # 前提は充足させる
        state_profile="read-only",
        visited_urls=set(), reached_urls=set(), scan_matrix=[], all_findings=[],
    )
    pc = ScanEngine.coverage_summary(engine)["prerequisite_coverage"]
    # 前提は充足だが read-only で skip → state_profile_skipped に出る
    assert "mass_assignment" in [s["check"] for s in pc["state_profile_skipped"]]
    assert "mass_assignment" not in [m["check"] for m in pc["prerequisite_missing"]]


def test_coverage_summary_browser_prereq_gated_on_init_success():
    """browser 前提（csrf 等）は _browser.init() 成功時のみ充足とみなす（Codex P2）。
    init 失敗（Chromium 不在）でも finally で partial report を出すため、実行できていない
    browser scanner を runnable と偽らない。"""
    from types import SimpleNamespace
    from wscan.engine import ScanEngine
    engine = SimpleNamespace(
        checks=["csrf"], scanners={"csrf": object()},
        _browser_ready=False,  # init 失敗相当
        visited_urls=set(), reached_urls=set(), scan_matrix=[], all_findings=[],
    )
    pc = ScanEngine.coverage_summary(engine)["prerequisite_coverage"]
    assert "csrf" in [m["check"] for m in pc["prerequisite_missing"]]

    engine._browser_ready = True  # init 成功 → runnable
    pc2 = ScanEngine.coverage_summary(engine)["prerequisite_coverage"]
    assert "csrf" in pc2["runnable"]
    assert "csrf" not in [m["check"] for m in pc2["prerequisite_missing"]]


def test_coverage_html_renders_prerequisite_missing(tmp_path):
    from wscan.report import ReportGenerator
    coverage = {
        "reached_count": 0, "attempts": 0, "findings_total": 0,
        "http_status": {}, "by_status": {}, "reached_urls": [], "unreached": [],
        "prerequisite_coverage": {
            "prerequisite_missing": [
                {"check": "mass_assignment", "missing_prerequisites": ["api_spec"],
                 "reasons": ["API 仕様シード未設定（--api-spec の OpenAPI/Postman）"]},
            ],
            "state_profile_skipped": [
                {"check": "graphql", "reason": "state profile 'read-only' は状態変更を伴う検査を送信しません＝probe 未投入"},
            ],
        },
    }
    html = ReportGenerator(tmp_path)._build_coverage_html(coverage)
    assert "実行条件が満たされない検査" in html
    assert "mass_assignment" in html and "API 仕様" in html
    # state profile skip も同じ表に併記される
    assert "graphql" in html and "state profile" in html
    # どちらも無ければ節ごと省略
    coverage["prerequisite_coverage"] = {"prerequisite_missing": [], "state_profile_skipped": []}
    html2 = ReportGenerator(tmp_path)._build_coverage_html(coverage)
    assert "実行条件が満たされない検査" not in html2


def test_coverage_summary_includes_scoped_capability_matrix():
    """coverage_summary は in-scope の scanner に限定した capability_matrix を出す（0035-E）。
    全 registry(36) を毎回出さず、実際に動かした検査の carrier 射程だけを供給する。"""
    from types import SimpleNamespace
    from wscan.engine import ScanEngine

    engine = SimpleNamespace(
        checks=["xss"],                          # 実在＋CONTRACT あり
        scanners={"xss": object(), "privesc": object()},  # privesc は auto-enable
        visited_urls=set(), reached_urls=set(), scan_matrix=[], all_findings=[],
    )
    cm = ScanEngine.coverage_summary(engine)["capability_matrix"]
    assert cm and "scanners" in cm and "carriers" in cm
    # in-scope（xss, privesc）だけ。全 36 は出さない。
    assert set(cm["scanners"].keys()) == {"xss", "privesc"}
    # carrier 語彙は全 carrier を列に持つ（build_capability_matrix の契約）
    from wscan.scanner_contract import Carrier
    assert set(cm["carriers"]) == {c.value for c in Carrier}


def test_coverage_html_renders_capability_matrix_when_present(tmp_path):
    from wscan.report import ReportGenerator
    from wscan.scanner_contract import build_capability_matrix
    from wscan.scanners import SCANNERS
    matrix = build_capability_matrix({"xss": SCANNERS["xss"].CONTRACT})
    coverage = {
        "reached_count": 0, "attempts": 0, "findings_total": 0,
        "http_status": {}, "by_status": {}, "reached_urls": [], "unreached": [],
        "capability_matrix": matrix,
    }
    html = ReportGenerator(tmp_path)._build_coverage_html(coverage)
    assert "Scanner capability matrix" in html
    assert ">xss<" in html
    # matrix 無しでは節ごと省略（矛盾表示を作らない）
    coverage.pop("capability_matrix")
    html2 = ReportGenerator(tmp_path)._build_coverage_html(coverage)
    assert "Scanner capability matrix" not in html2


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
