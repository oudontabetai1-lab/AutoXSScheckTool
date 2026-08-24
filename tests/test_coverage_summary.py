"""到達性カバレッジと HTTP status 集計のブラウザ非依存テスト。"""

import asyncio
import importlib
from collections import Counter
from types import SimpleNamespace

from wscan.browser import NetworkCapture, bucketize_status_counts
from wscan.checkpoint import CheckpointState, load_checkpoint
from wscan.engine import (
    CrawledPage,
    ScanEngine,
    _coverage_allowed_origins,
    _coverage_summary_text,
)
from wscan.report import ReportGenerator
from wscan.scanners.base import BaseScanner, Finding


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


def _finding(check_type: str, url: str = "http://fixture.test/a") -> Finding:
    return Finding(
        check_type=check_type,
        severity="high",
        url=url,
        field_name="(page)",
        payload="probe",
        evidence="fixture finding",
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


def test_network_capture_filters_status_counts_to_allowed_origins():
    capture = NetworkCapture()
    capture.allowed_origins = {"http://fixture.test"}
    for status, url, resource_type in (
        (403, "http://fixture.test/private", "document"),
        (429, "http://fixture.test/api", "fetch"),
        (403, "https://cdn.example.test/script.js", "script"),
        (403, "https://api.example.test/data", "xhr"),
        (403, "https://api.example.test/data", "fetch"),
    ):
        response = _response(status, url=url, resource_type=resource_type)
        capture.on_request(response.request)
        capture.on_response(response)

    assert capture.status_counts == {403: 1, 429: 1}
    assert len(capture.pairs) == 5


def test_network_capture_without_allowed_origins_counts_every_origin():
    capture = NetworkCapture()
    for url in (
        "http://fixture.test/private",
        "https://api.example.test/data",
    ):
        response = _response(403, url=url, resource_type="xhr")
        capture.on_request(response.request)
        capture.on_response(response)

    assert capture.allowed_origins is None
    assert capture.status_counts == {403: 2}


def test_network_capture_origin_filter_is_exception_safe():
    capture = NetworkCapture()
    capture.allowed_origins = {"http://fixture.test"}
    response = _response(403, url="http://[invalid", resource_type="fetch")
    capture.on_request(response.request)

    capture.on_response(response)

    assert capture.status_counts == {}
    assert len(capture.pairs) == 1


def test_coverage_allowed_origins_uses_target_and_access_urls():
    assert _coverage_allowed_origins(
        ["https://target.test/app", "http://other.test:8080/path"],
        ["https://auth.test/login", "/relative-scope", "http://[invalid"],
    ) == {
        "https://target.test",
        "http://other.test:8080",
        "https://auth.test",
    }


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
        _probe_status_counts=Counter({403: 1, 429: 2}),
        checks=["xss", "sqli"],
        scanners={},
        all_findings=[_finding("xss"), _finding("sqli")],
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
            "total": 14,
            "blocked": 7,
            "client_error": 8,
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
        checks=["xss"],
        scanners={},
        all_findings=[_finding("xss")],
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
        checks=[],
        scanners={},
        all_findings=[],
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
        checks=[],
        scanners={},
        all_findings=[],
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
            self.network = SimpleNamespace(
                status_counts=Counter({403: 2, 503: 1}),
                allowed_origins=None,
            )
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
        _probe_status_counts=Counter({429: 2}),
        _coverage_origins={"http://fixture.test"},
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
    assert worker.network.allowed_origins == {"http://fixture.test"}
    assert worker.closed is True
    assert save_calls == [{403: 2, 503: 1}]
    assert load_checkpoint(tmp_path).http_status_counts == {
        "403": 2,
        "429": 2,
        "503": 1,
    }


def test_record_probe_status_is_guarded_and_contributes_to_blocked():
    engine = SimpleNamespace(
        _probe_status_counts=Counter(),
        reached_urls=set(),
        scan_matrix=[],
        browser=None,
        checks=[],
        scanners={},
        all_findings=[],
    )

    for status in ("403", 429, None, "invalid", 99, 600):
        ScanEngine.record_probe_status(engine, status)

    assert engine._probe_status_counts == Counter({403: 1, 429: 1})
    assert ScanEngine.coverage_summary(engine)["http_status"] == {
        "total": 2,
        "blocked": 2,
        "client_error": 2,
        "server_error": 0,
    }


def test_scanner_probe_status_forwarding_is_optional_and_exception_safe():
    class _Scanner(BaseScanner):
        async def scan_field(self, *args, **kwargs):
            return []

    scanner = _Scanner.__new__(_Scanner)
    recorded = []
    scanner.engine = SimpleNamespace(record_probe_status=recorded.append)
    scanner._record_probe_status(SimpleNamespace(status_code=403))
    assert recorded == [403]

    scanner.engine = SimpleNamespace()
    scanner._record_probe_status(SimpleNamespace(status_code=403))

    def broken_recorder(_status):
        raise RuntimeError("recorder unavailable")

    scanner.engine.record_probe_status = broken_recorder
    scanner._record_probe_status(SimpleNamespace(status_code=429))


def test_findings_total_uses_all_in_scope_findings_without_matrix_rows():
    engine = SimpleNamespace(
        reached_urls=set(),
        scan_matrix=[],
        browser=None,
        checks=["security_headers"],
        scanners={},
        all_findings=[_finding("security_headers"), _finding("xss")],
    )

    summary = ScanEngine.coverage_summary(engine)

    assert summary["attempts"] == 0
    assert summary["findings_total"] == 1


def test_builtin_page_level_capability_flags_match_scanner_contract():
    page_level_scanners = {
        "cache_poisoning.CachePoisoningScanner",
        "clickjacking.ClickjackingScanner",
        "cms.CmsScanner",
        "cors.CORSScanner",
        "csrf.CSRFScanner",
        "graphql.GraphQLScanner",
        "host_header.HostHeaderScanner",
        "info_disclosure.InfoDisclosureScanner",
        "js_static.JsStaticScanner",
        "jwt_scanner.JWTScanner",
        "mass_assignment.MassAssignmentScanner",
        "privesc.PrivEscScanner",
        "prototype_pollution.PrototypePollutionScanner",
        "race_condition.RaceConditionScanner",
        "request_smuggling.RequestSmugglingScanner",
        "secret_leak.SecretLeakScanner",
        "security_headers.SecurityHeadersScanner",
        "session.SessionScanner",
        "sri.SRIScanner",
        "stored_xss.StoredXSSScanner",
        "websocket.WebSocketScanner",
    }
    compat_noop_scanners = {
        "deserialization.DeserializationScanner",
        "file_upload.FileUploadScanner",
        "ldap_injection.LDAPScanner",
        "nosql_injection.NoSQLInjectionScanner",
        "xxe.XXEScanner",
    }

    for scanner_path in page_level_scanners | compat_noop_scanners:
        module_name, class_name = scanner_path.split(".")
        module = importlib.import_module(f"wscan.scanners.{module_name}")
        scanner_class = getattr(module, class_name)
        assert scanner_class.HAS_PAGE_LEVEL is (scanner_path in page_level_scanners)


def test_page_level_attempt_uses_only_findings_returned_by_scanner(tmp_path):
    engine = ScanEngine(
        "http://fixture.test/page",
        checks=["security_headers"],
        llm_provider="none",
        output_dir=tmp_path,
        open_report=False,
        enable_waf_detection=False,
        enable_ai_analysis=False,
        enable_payload_learning=False,
        enable_adaptive_payloads=False,
    )

    class _Scanner:
        HAS_PAGE_LEVEL = True

        async def scan_page(self, url):
            engine.all_findings.append(
                Finding(
                    check_type="sqli",
                    severity="critical",
                    url="http://fixture.test/other-page",
                    field_name="q",
                    payload="other",
                    evidence="concurrent finding from another page",
                )
            )
            return [_finding("security_headers", url)]

    engine.scanners = {"security_headers": _Scanner()}
    page = CrawledPage(
        url=engine.target_url,
        html="<html></html>",
        forms=[],
        url_params=[],
        depth=0,
    )

    asyncio.run(engine._attack_one_page(page, {}))

    row = engine.scan_matrix[-1]
    assert row["field_name"] == "(page)"
    assert row["status"] == "vulnerable"
    assert row["severity"] == "high"
    assert row["finding_count"] == 1
    assert engine.coverage_summary()["attempts"] == 1


def test_compat_scan_page_noop_does_not_create_page_level_attempt(tmp_path):
    engine = ScanEngine(
        "http://fixture.test/page",
        checks=["xss"],
        llm_provider="none",
        output_dir=tmp_path,
        open_report=False,
        enable_waf_detection=False,
        enable_ai_analysis=False,
        enable_payload_learning=False,
        enable_adaptive_payloads=False,
    )

    class _FieldOnlyScanner(BaseScanner):
        async def scan_field(self, *args, **kwargs):
            return []

        async def scan_page(self, url):
            return []

    engine.scanners = {"xss": _FieldOnlyScanner(engine)}
    page = CrawledPage(
        url=engine.target_url,
        html="<html></html>",
        forms=[],
        url_params=[],
        depth=0,
    )

    asyncio.run(engine._attack_one_page(page, {}))

    assert engine.scan_matrix == []
    assert engine.coverage_summary()["attempts"] == 0


def test_scan_page_context_creates_page_level_attempt_without_flag(tmp_path):
    engine = ScanEngine(
        "http://fixture.test/page",
        checks=["js_static"],
        llm_provider="none",
        output_dir=tmp_path,
        open_report=False,
        enable_waf_detection=False,
        enable_ai_analysis=False,
        enable_payload_learning=False,
        enable_adaptive_payloads=False,
    )

    class _ContextScanner:
        async def scan_page_context(self, page):
            return []

    engine.scanners = {"js_static": _ContextScanner()}
    page = CrawledPage(
        url=engine.target_url,
        html="<html></html>",
        forms=[],
        url_params=[],
        depth=0,
    )

    asyncio.run(engine._attack_one_page(page, {}))

    assert engine.scan_matrix[-1]["field_name"] == "(page)"
    assert engine.scan_matrix[-1]["status"] == "tested"


def test_api_template_execution_is_recorded_as_an_attempt(tmp_path):
    engine = ScanEngine(
        "http://fixture.test/api",
        checks=["mass_assignment"],
        llm_provider="none",
        output_dir=tmp_path,
        open_report=False,
        enable_waf_detection=False,
        enable_ai_analysis=False,
        enable_payload_learning=False,
        enable_adaptive_payloads=False,
    )

    class _Scanner:
        HAS_PAGE_LEVEL = True

        async def scan_page(self, url):
            return [_finding("mass_assignment", url)]

    engine.scanners = {"mass_assignment": _Scanner()}
    engine.api_seed_requests = [SimpleNamespace(url=engine.target_url)]

    asyncio.run(engine._run_api_template_checks())

    row = engine.scan_matrix[-1]
    assert row["field_name"] == "(api-template)"
    assert row["status"] == "vulnerable"
    assert row["finding_count"] == 1
    assert engine.coverage_summary()["attempts"] == 1


def test_compat_scan_page_noop_does_not_create_api_template_attempt(tmp_path):
    engine = ScanEngine(
        "http://fixture.test/api",
        checks=["nosql"],
        llm_provider="none",
        output_dir=tmp_path,
        open_report=False,
        enable_waf_detection=False,
        enable_ai_analysis=False,
        enable_payload_learning=False,
        enable_adaptive_payloads=False,
    )

    class _FieldOnlyScanner(BaseScanner):
        async def scan_field(self, *args, **kwargs):
            return []

        async def scan_page(self, url):
            return []

    engine.scanners = {"nosql": _FieldOnlyScanner(engine)}
    engine.api_seed_requests = [SimpleNamespace(url=engine.target_url)]

    asyncio.run(engine._run_api_template_checks())

    assert engine.scan_matrix == []
    assert engine.coverage_summary()["attempts"] == 0


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
