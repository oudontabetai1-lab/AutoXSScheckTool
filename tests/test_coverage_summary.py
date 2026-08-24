"""到達性カバレッジと HTTP status 集計のブラウザ非依存テスト。"""

from types import SimpleNamespace

from wscan.browser import NetworkCapture
from wscan.engine import ScanEngine, _coverage_summary_text
from wscan.report import ReportGenerator


def _response(status: int, url: str = "http://fixture.test/"):
    request = SimpleNamespace(
        url=url,
        method="GET",
        headers={},
        post_data=None,
    )
    return SimpleNamespace(
        url=url,
        status=status,
        headers={},
        request=request,
    )


def test_network_capture_tallies_statuses_across_clear():
    capture = NetworkCapture()
    for status in (200, 403, 429, 404, 500, 503):
        response = _response(status)
        capture.on_request(response.request)
        capture.on_response(response)

    assert capture.status_counts == {
        200: 1,
        403: 1,
        429: 1,
        404: 1,
        500: 1,
        503: 1,
    }
    assert capture.status_summary() == {
        "total": 6,
        "blocked": 2,
        "client_error": 3,
        "server_error": 2,
    }

    capture.clear()

    assert capture.pairs == []
    assert capture._pending == {}
    assert capture.status_summary()["total"] == 6


def test_coverage_summary_aggregates_matrix_urls_and_http_status():
    engine = SimpleNamespace(
        visited_urls={"http://fixture.test/b", "http://fixture.test/a"},
        scan_matrix=[
            {
                "url": "http://fixture.test/a",
                "check": "xss",
                "status": "clean",
                "finding_count": 0,
            },
            {
                "url": "http://fixture.test/a",
                "check": "sqli",
                "status": "vulnerable",
                "finding_count": 2,
            },
            {
                "url": "http://fixture.test/missing",
                "check": "access",
                "status": "error",
                "note": "HTTP 503",
            },
            {
                "url": "http://fixture.test/missing",
                "check": "access",
                "status": "error",
                "note": "duplicate reason",
            },
        ],
        browser=SimpleNamespace(
            network=SimpleNamespace(
                status_summary=lambda: {
                    "total": 8,
                    "blocked": 2,
                    "client_error": 3,
                    "server_error": 1,
                }
            )
        ),
    )

    summary = ScanEngine.coverage_summary(engine)

    assert summary == {
        "reached_urls": ["http://fixture.test/a", "http://fixture.test/b"],
        "reached_count": 2,
        "attempts": 2,
        "by_status": {"clean": 1, "vulnerable": 1},
        "findings_total": 2,
        "unreached": [
            {"url": "http://fixture.test/missing", "reason": "HTTP 503"}
        ],
        "unreached_count": 1,
        "http_status": {
            "total": 8,
            "blocked": 2,
            "client_error": 3,
            "server_error": 1,
        },
    }


def test_coverage_summary_handles_empty_matrix_and_missing_browser():
    engine = SimpleNamespace(visited_urls=set(), scan_matrix=[], browser=None)

    assert ScanEngine.coverage_summary(engine) == {
        "reached_urls": [],
        "reached_count": 0,
        "attempts": 0,
        "by_status": {},
        "findings_total": 0,
        "unreached": [],
        "unreached_count": 0,
        "http_status": {
            "total": 0,
            "blocked": 0,
            "client_error": 0,
            "server_error": 0,
        },
    }


def test_coverage_console_and_html_render_blocked_warning(tmp_path):
    coverage = {
        "reached_urls": ["http://fixture.test/?q=<safe>"],
        "reached_count": 1,
        "attempts": 4,
        "by_status": {"clean": 3, "error": 1},
        "findings_total": 0,
        "unreached": [
            {"url": "http://fixture.test/<admin>", "reason": "HTTP 403 & blocked"}
        ],
        "unreached_count": 1,
        "http_status": {
            "total": 10,
            "blocked": 2,
            "client_error": 2,
            "server_error": 1,
        },
    }

    assert _coverage_summary_text(coverage) == (
        "Coverage: reached URLs=1 / attempts=4 / blocked=2"
    )

    html = ReportGenerator(tmp_path)._build_coverage_html(coverage)
    assert "Coverage（到達性カバレッジ）" in html
    assert "到達 URL: <strong>1</strong> 件" in html
    assert "試行: <strong>4</strong> 件" in html
    assert "2 件が 403/429 でブロック" in html
    assert "十分に検査できていない可能性があります" in html
    assert "http://fixture.test/&lt;admin&gt;" in html
    assert "HTTP 403 &amp; blocked" in html
    assert "http://fixture.test/<admin>" not in html


def test_generate_threads_coverage_after_observability_for_all_templates(tmp_path):
    coverage = {
        "reached_count": 1,
        "attempts": 2,
        "findings_total": 0,
        "http_status": {"total": 3, "blocked": 0, "server_error": 0},
    }
    generator = ReportGenerator(tmp_path)

    for template in ("audit", "executive", "developer"):
        report_path = generator.generate(
            target="http://fixture.test",
            findings=[],
            visited_urls=["http://fixture.test"],
            checks=["xss"],
            observability={"total": 0},
            coverage=coverage,
            template=template,
        )
        html = report_path.read_text(encoding="utf-8")
        assert html.index("Observability（観測性メトリクス）") < html.index(
            "Coverage（到達性カバレッジ）"
        )
