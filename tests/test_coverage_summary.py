"""到達性カバレッジと HTTP status 集計のブラウザ非依存テスト。"""

import asyncio
from collections import Counter
from types import SimpleNamespace

from wscan.browser import NetworkCapture, bucketize_status_counts
from wscan.checkpoint import CheckpointState, load_checkpoint
from wscan.engine import ScanEngine, _coverage_summary_text
from wscan.report import ReportGenerator


def _response(
    status: int,
    url: str = "http://fixture.test/",
    resource_type: str | None = None,
):
    request_data = {
        "url": url,
        "method": "GET",
        "headers": {},
        "post_data": None,
    }
    if resource_type is not None:
        request_data["resource_type"] = resource_type
    request = SimpleNamespace(**request_data)
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


def test_network_capture_excludes_static_assets_from_status_counts():
    capture = NetworkCapture()
    for resource_type in ("image", "font", "stylesheet", "media"):
        response = _response(403, resource_type=resource_type)
        capture.on_request(response.request)
        capture.on_response(response)

    assert capture.status_counts == {}
    assert len(capture.pairs) == 4


def test_network_capture_counts_scan_related_and_unknown_resource_types():
    capture = NetworkCapture()
    for status, resource_type in (
        (403, "document"),
        (403, "xhr"),
        (429, "fetch"),
        (429, None),
    ):
        response = _response(status, resource_type=resource_type)
        capture.on_request(response.request)
        capture.on_response(response)

    assert capture.status_counts == {403: 2, 429: 2}


def test_bucketize_status_counts_groups_blocked_and_error_classes():
    assert bucketize_status_counts({200: 3, 403: 2, 404: 1, 429: 4, 503: 5}) == {
        "total": 15,
        "blocked": 6,
        "client_error": 7,
        "server_error": 5,
    }


def test_coverage_summary_aggregates_matrix_urls_and_http_status():
    engine = SimpleNamespace(
        visited_urls={
            "http://fixture.test/a",
            "http://fixture.test/b",
            "http://fixture.test/missing",
        },
        reached_urls={"http://fixture.test/b", "http://fixture.test/a"},
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
                status_counts=Counter({200: 4, 403: 1})
            )
        ),
        _worker_status_counts=Counter({404: 1, 429: 1, 500: 1}),
        _restored_status_counts=Counter({429: 2, 502: 1}),
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
            "total": 11,
            "blocked": 4,
            "client_error": 5,
            "server_error": 2,
        },
    }


def test_coverage_summary_excludes_resume_only_skipped_rows():
    restored_row = {
        "url": "http://fixture.test/a",
        "check": "xss",
        "status": "vulnerable",
        "finding_count": 1,
    }
    resume_skip_row = {
        "url": "http://fixture.test/a",
        "check": "xss",
        "status": "skipped",
        "finding_count": 9,
        "note": "Skipped — already completed in checkpoint",
    }
    engine = SimpleNamespace(
        reached_urls={"http://fixture.test/a"},
        scan_matrix=[restored_row, resume_skip_row],
        browser=None,
    )

    summary = ScanEngine.coverage_summary(engine)

    assert summary["attempts"] == 1
    assert summary["by_status"] == {"vulnerable": 1}
    assert summary["findings_total"] == 1


def test_coverage_summary_excludes_reached_url_from_unreached_rows():
    url = "http://fixture.test/recovered"
    engine = SimpleNamespace(
        reached_urls={url},
        scan_matrix=[
            {
                "url": url,
                "check": "access",
                "status": "error",
                "note": "restore navigation failed",
            }
        ],
        browser=None,
    )

    summary = ScanEngine.coverage_summary(engine)

    assert summary["reached_urls"] == [url]
    assert summary["unreached"] == []
    assert summary["unreached_count"] == 0


def test_coverage_summary_handles_empty_matrix_and_missing_browser():
    engine = SimpleNamespace(
        visited_urls={"http://fixture.test/discovered-only"},
        reached_urls=set(),
        scan_matrix=[],
        browser=None,
    )

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


def test_parallel_worker_statuses_are_checkpointed_after_close(tmp_path):
    class _Worker:
        def __init__(self):
            self.network = SimpleNamespace(status_counts=Counter({403: 2, 503: 1}))
            self.closed = False

        async def close(self):
            self.closed = True

    worker = _Worker()

    class _MainBrowser:
        async def create_worker(self):
            return worker

    engine = SimpleNamespace(
        concurrency=2,
        _browser=_MainBrowser(),
        _worker_status_counts=Counter(),
        _restored_status_counts=Counter(),
        enable_checkpoint=True,
        checkpoint=CheckpointState(
            target_url="http://fixture.test/", checks=["xss"]
        ),
        all_findings=[],
        scan_matrix=[],
        output_dir=tmp_path,
        wave_errors=[],
    )
    save_calls = []

    def _save_checkpoint():
        save_calls.append(dict(engine._worker_status_counts))
        ScanEngine._save_checkpoint(engine)

    engine._save_checkpoint = _save_checkpoint

    asyncio.run(ScanEngine._phase_attack_concurrent(engine, [], {}))

    assert engine._worker_status_counts == Counter({403: 2, 503: 1})
    assert worker.closed is True
    assert save_calls == [{403: 2, 503: 1}]
    assert load_checkpoint(tmp_path).http_status_counts == {"403": 2, "503": 1}


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
