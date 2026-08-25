"""到達性カバレッジと HTTP status 集計のブラウザ非依存テスト。"""

import asyncio
import importlib
from collections import Counter
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from wscan.browser import NetworkCapture, bucketize_status_counts, canonical_host
from wscan.checkpoint import CheckpointState, load_checkpoint
from wscan.engine import (
    CrawledPage,
    ScanEngine,
    _coverage_allowed_hosts,
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


def test_canonical_host_strips_www_casefolds_and_default_ports_but_keeps_explicit():
    # www 除去・casefold・既定 port(http80/https443)と暗黙 port は省く。
    assert canonical_host("https://WWW.Fixture.Test/path") == "fixture.test"
    assert canonical_host("http://fixture.test:80") == "fixture.test"
    assert canonical_host("https://fixture.test:443") == "fixture.test"
    # 明示された非既定 port は保持し別 origin と区別する（Codex #102）。
    assert canonical_host("https://WWW.Fixture.Test:8443/path") == "fixture.test:8443"
    assert canonical_host("http://fixture.test:3000") == "fixture.test:3000"
    assert canonical_host("http://fixture.test:3000") != canonical_host("http://fixture.test:8080")
    assert canonical_host("http://[invalid") == ""


def test_network_capture_filters_status_counts_to_allowed_hosts():
    capture = NetworkCapture()
    capture.allowed_hosts = {"fixture.test"}
    for status, url, resource_type in (
        (403, "http://fixture.test/private", "document"),
        (429, "https://www.FIXTURE.test/api", "fetch"),
        (403, "https://cdn.example.test/script.js", "script"),
        (403, "https://api.example.test/data", "xhr"),
        (403, "https://api.example.test/data", "fetch"),
    ):
        response = _response(status, url=url, resource_type=resource_type)
        capture.on_request(response.request)
        capture.on_response(response)

    assert capture.status_counts == {403: 1, 429: 1}
    assert len(capture.pairs) == 5


def test_network_capture_without_allowed_hosts_counts_every_origin():
    capture = NetworkCapture()
    for url in (
        "http://fixture.test/private",
        "https://api.example.test/data",
    ):
        response = _response(403, url=url, resource_type="xhr")
        capture.on_request(response.request)
        capture.on_response(response)

    assert capture.allowed_hosts is None
    assert capture.status_counts == {403: 2}


def test_network_capture_host_filter_is_exception_safe():
    capture = NetworkCapture()
    capture.allowed_hosts = {"fixture.test"}
    response = _response(403, url="http://[invalid", resource_type="fetch")
    capture.on_request(response.request)

    capture.on_response(response)

    assert capture.status_counts == {}
    assert len(capture.pairs) == 1


def test_coverage_allowed_hosts_uses_canonical_target_and_access_hosts():
    assert _coverage_allowed_hosts(
        ["https://www.TARGET.test/app", "http://other.test:8080/path"],
        ["https://auth.test/login", "/relative-scope", "http://[invalid"],
    ) == {
        "target.test",
        "other.test:8080",
        "auth.test",
    }


def test_note_coverage_origin_refreshes_in_scope_host_on_main_and_workers():
    main = SimpleNamespace(network=SimpleNamespace(allowed_hosts=None))
    worker = SimpleNamespace(network=SimpleNamespace(allowed_hosts=None))
    engine = SimpleNamespace(
        _coverage_hosts={"fixture.test"},
        _browser=main,
        _coverage_workers=[worker],
        # Canonical redirects must not depend on exact scheme/host scope checks.
        _is_access_allowed_url=lambda _url: False,
    )

    ScanEngine._note_coverage_origin(engine, "https://www.fixture.test/app")

    expected = {"fixture.test"}
    assert engine._coverage_hosts == expected
    assert main.network.allowed_hosts == expected
    assert worker.network.allowed_hosts == expected

    ScanEngine._note_coverage_origin(engine, "https://third-party.test/track")
    ScanEngine._note_coverage_origin(engine, "http://[invalid")

    assert engine._coverage_hosts == expected
    assert main.network.allowed_hosts == expected
    assert worker.network.allowed_hosts == expected


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
    out_of_scope_row = {
        "url": "http://fixture.test/a",
        "check": "sqli",
        "status": "vulnerable",
        "finding_count": 1,
    }
    engine = SimpleNamespace(
        reached_urls={"http://fixture.test/a"},
        scan_matrix=[restored_row, resume_skip_row, out_of_scope_row],
        browser=None,
        checks=["xss"],
        scanners={},
        all_findings=[_finding("xss")],
    )

    summary = ScanEngine.coverage_summary(engine)

    assert summary["attempts"] == 1
    assert summary["by_status"] == {"vulnerable": 1}
    assert summary["findings_total"] == 1


def test_scan_matrix_display_view_keeps_access_and_current_scope_only():
    xss_row = {"check": "xss", "status": "clean"}
    sqli_row = {"check": "sqli", "status": "vulnerable"}
    access_row = {"check": "access", "status": "error"}
    engine = SimpleNamespace(
        scan_matrix=[xss_row, sqli_row, access_row, "legacy malformed row"],
        checks=["xss"],
        scanners={},
    )

    assert ScanEngine._scan_matrix_for_display(engine) == [xss_row, access_row]


def test_generate_report_passes_only_display_scope_matrix(monkeypatch, tmp_path):
    xss_row = {"check": "xss", "status": "clean"}
    sqli_row = {"check": "sqli", "status": "vulnerable"}
    access_row = {"check": "access", "status": "error"}
    generated = []

    class _ReportGenerator:
        def __init__(self, output_dir):
            self.output_dir = output_dir

        def generate(self, **kwargs):
            generated.append(kwargs)
            return self.output_dir / "report.html"

    monkeypatch.setattr("wscan.report.ReportGenerator", _ReportGenerator)
    engine = SimpleNamespace(
        output_dir=tmp_path,
        previous_scan_dir="",
        target_url="http://fixture.test",
        all_findings=[],
        visited_urls=set(),
        checks=["xss"],
        scanners={},
        attack_plans=[],
        ctf_found_flags=[],
        page_graph={},
        scan_matrix=[xss_row, sqli_row, access_row],
        open_report=False,
        monitor=None,
        _scan_matrix_for_display=lambda: [xss_row, access_row],
        _llm_runtime_summary=lambda: {},
        _observability_report_data=lambda: {},
        coverage_summary=lambda: {},
    )

    ScanEngine._generate_report(engine)

    assert len(generated) == 3
    assert all(call["scan_matrix"] == [xss_row, access_row] for call in generated)


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
        # queued(visited)だが未到達の URL は「未試行」として unreached に出る（Codex #102）。
        "unreached": [
            {
                "url": "http://fixture.test/discovered-only",
                "reason": "not attempted (scan ended before navigation)",
            }
        ],
        "unreached_count": 1,
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
                allowed_hosts=None,
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
        _coverage_hosts={"fixture.test"},
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
    assert worker.network.allowed_hosts == {"fixture.test"}
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
        _coverage_hosts=set(),
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


def test_record_probe_status_filters_url_by_canonical_host():
    engine = SimpleNamespace(
        _probe_status_counts=Counter(),
        _coverage_hosts={"fixture.test"},
    )

    ScanEngine.record_probe_status(engine, 403, "https://www.FIXTURE.test/private")
    ScanEngine.record_probe_status(engine, 429, "https://external.test/rate-limit")
    ScanEngine.record_probe_status(engine, 500, None)

    assert engine._probe_status_counts == Counter({403: 1, 500: 1})

    engine._coverage_hosts.clear()
    ScanEngine.record_probe_status(engine, 429, "https://external.test/rate-limit")

    assert engine._probe_status_counts == Counter({403: 1, 429: 1, 500: 1})


class _QueuedAsyncClient:
    def __init__(self, responses):
        self.responses = list(responses)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def get(self, *args, **kwargs):
        return self.responses.pop(0)


def test_engine_session_preflight_records_final_url_with_host_filter():
    responses = [
        SimpleNamespace(
            status_code=403,
            url="https://external-idp.test/login",
            text="blocked",
        ),
        SimpleNamespace(
            status_code=429,
            url="https://www.FIXTURE.test/login",
            text="rate limited",
        ),
    ]
    engine = SimpleNamespace(
        relogin_on_expiry=True,
        login_url="http://fixture.test/login",
        logged_in_marker="",
        timeout=1,
        proxy="",
        _coverage_hosts={"fixture.test"},
        _probe_status_counts=Counter(),
        auth_headers=lambda **kwargs: {},
    )
    engine.record_probe_status = lambda status, url=None: ScanEngine.record_probe_status(
        engine, status, url
    )

    with patch("httpx.AsyncClient", return_value=_QueuedAsyncClient(responses)):
        asyncio.run(ScanEngine._api_session_looks_expired(engine, "http://fixture.test/a"))
        asyncio.run(ScanEngine._api_session_looks_expired(engine, "http://fixture.test/b"))

    assert engine._probe_status_counts == Counter({429: 1})


def test_sitemap_and_robots_fetches_record_each_response_status():
    responses = [
        SimpleNamespace(
            status_code=200,
            url="http://fixture.test/robots.txt",
            text="Sitemap: http://fixture.test/nested-sitemap.xml",
        ),
        SimpleNamespace(
            status_code=403,
            url="http://fixture.test/nested-sitemap.xml",
            text="blocked",
        ),
        SimpleNamespace(
            status_code=429,
            url="http://fixture.test/sitemap.xml",
            text="rate limited",
        ),
    ]
    recorded = []
    engine = SimpleNamespace(
        target_url="http://fixture.test",
        visited_urls=set(),
        httpx_client_kwargs=lambda **kwargs: kwargs,
        auth_headers=lambda **kwargs: {},
        record_probe_status=lambda status, url: recorded.append((status, url)),
        _extract_sitemap_locs=ScanEngine._extract_sitemap_locs,
    )
    engine._parse_sitemap = lambda client, url: ScanEngine._parse_sitemap(
        engine, client, url
    )

    with patch("httpx.AsyncClient", return_value=_QueuedAsyncClient(responses)):
        discovered = asyncio.run(ScanEngine._fetch_sitemap_urls(engine))

    assert discovered == []
    assert recorded == [
        (200, "http://fixture.test/robots.txt"),
        (403, "http://fixture.test/nested-sitemap.xml"),
        (429, "http://fixture.test/sitemap.xml"),
    ]


def test_run_saves_probe_status_recorded_during_verification(tmp_path):
    engine = ScanEngine(
        "http://fixture.test/",
        checks=["xss"],
        llm_provider="none",
        output_dir=tmp_path,
        open_report=False,
        enable_waf_detection=False,
        enable_ai_analysis=False,
        enable_payload_learning=False,
        enable_adaptive_payloads=False,
    )
    engine.controller = SimpleNamespace(
        start=lambda *args, **kwargs: None,
        stop=lambda: None,
    )
    engine.header_manager = SimpleNamespace(
        start_background_refresh=lambda: None,
        stop_background_refresh=AsyncMock(),
    )
    engine._browser = SimpleNamespace(
        init=AsyncMock(),
        close=AsyncMock(),
        network=SimpleNamespace(status_counts=Counter()),
        auth_user="",
        auth_pass="",
    )
    engine._phase_crawl = AsyncMock(return_value=[])
    engine._phase_plan = AsyncMock(return_value={})
    engine._phase_attack = AsyncMock()
    engine._run_api_template_checks = AsyncMock()
    engine._run_json_injection_checks = AsyncMock()
    engine._phase_report_async = AsyncMock()
    engine._merge_additional_report_findings = lambda: None

    async def _verify():
        engine.record_probe_status(429, engine.target_url)

    engine._phase_verify = _verify
    saved_statuses = []
    real_save = engine._save_checkpoint

    def _tracked_save():
        saved_statuses.append(dict(engine._probe_status_counts))
        real_save()

    engine._save_checkpoint = _tracked_save

    asyncio.run(engine.run())

    assert saved_statuses[-1] == {429: 1}
    assert load_checkpoint(tmp_path).http_status_counts == {"429": 1}


def test_engine_ssti_fallback_records_each_final_url_with_host_filter():
    payload = "{{2654435761*2654435761}}"
    responses = [
        SimpleNamespace(
            status_code=403,
            url="https://external-idp.test/login",
            text="blocked",
        ),
        SimpleNamespace(
            status_code=429,
            url="https://www.fixture.test/search?q=probe",
            text="rate limited",
        ),
    ]
    scanner = SimpleNamespace(verify_finding=AsyncMock(return_value=False))
    engine = SimpleNamespace(
        scanners={"ssti": scanner},
        timeout=1,
        _coverage_hosts={"fixture.test"},
        _probe_status_counts=Counter(),
        httpx_client_kwargs=lambda **kwargs: kwargs,
        auth_headers=lambda **kwargs: {},
    )
    engine.record_probe_status = lambda status, url=None: ScanEngine.record_probe_status(
        engine, status, url
    )
    finding = Finding(
        check_type="ssti",
        severity="critical",
        url=f"http://fixture.test/search?q={payload}",
        field_name="q",
        payload=payload,
        evidence="fixture",
        injection_location="url_param",
    )

    with patch("httpx.AsyncClient", return_value=_QueuedAsyncClient(responses)):
        result = asyncio.run(ScanEngine._verify_one(engine, finding))

    assert result == "unreproduced"
    assert engine._probe_status_counts == Counter({429: 1})


def test_scanner_probe_status_forwarding_is_optional_and_exception_safe():
    class _Scanner(BaseScanner):
        async def scan_field(self, *args, **kwargs):
            return []

    scanner = _Scanner.__new__(_Scanner)
    recorded = []
    scanner.engine = SimpleNamespace(
        record_probe_status=lambda status, url: recorded.append((status, url))
    )
    scanner._record_probe_status(
        SimpleNamespace(status_code=403, url="https://fixture.test/final")
    )
    scanner._record_probe_status(SimpleNamespace(status_code=429))
    assert recorded == [
        (403, "https://fixture.test/final"),
        (429, None),
    ]

    scanner.engine = SimpleNamespace()
    scanner._record_probe_status(SimpleNamespace(status_code=403))

    def broken_recorder(_status, _url):
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


def test_top_severity_uses_explicit_order_not_lexicographic():
    from types import SimpleNamespace
    from wscan.engine import _top_severity
    fs = [SimpleNamespace(severity="medium"), SimpleNamespace(severity="critical"),
          SimpleNamespace(severity="low")]
    # 辞書順(max)なら "medium" になるが、明示順序で最重は critical。
    assert _top_severity(fs) == "critical"
    assert _top_severity([SimpleNamespace(severity="high"), SimpleNamespace(severity="info")]) == "high"
    assert _top_severity([]) == ""


def test_scan_matrix_display_and_save_exclude_skipped_rows():
    """resume-only の skip 行は display/evidence/save から除外される（Codex #102 P2）。"""
    from wscan.engine import ScanEngine

    eng = ScanEngine.__new__(ScanEngine)
    eng.checks = ["xss"]
    eng.scan_matrix = [
        {"url": "u1", "field_name": "q", "check": "xss", "status": "tested", "location": "", "severity": "", "finding_count": 0, "note": ""},
        {"url": "u1", "field_name": "q", "check": "xss", "status": "skipped", "location": "", "note": "resume"},
        {"url": "u1", "field_name": "(page)", "check": "access", "status": "error", "location": "", "note": "x"},
    ]
    disp = eng._scan_matrix_for_display()
    statuses = [r["status"] for r in disp]
    assert "skipped" not in statuses
    assert "tested" in statuses and "error" in statuses  # 実行行と access 行は残る


def test_coverage_includes_live_worker_status_before_cleanup():
    """cleanup 前でも live worker(_coverage_workers)の status が coverage に反映される（Codex #102）。"""
    from collections import Counter
    from wscan.engine import ScanEngine

    live_worker = SimpleNamespace(network=SimpleNamespace(status_counts=Counter({403: 2, 429: 1})))
    eng = SimpleNamespace(
        scan_matrix=[], reached_urls=set(), visited_urls=set(), checks=[], scanners={},
        all_findings=[], browser=None,
        _worker_status_counts=Counter(),      # cleanup 未実施なので空
        _restored_status_counts=Counter(),
        _probe_status_counts=Counter(),
        _coverage_workers=[live_worker],
    )
    hs = ScanEngine.coverage_summary(eng)["http_status"]
    assert hs["blocked"] == 3  # 403x2 + 429x1（live worker 由来）
    assert hs["total"] == 3


def test_coverage_html_omitted_when_no_metrics():
    """coverage 未提供(None/空)なら Coverage セクションを描画しない（Codex #102）。"""
    from wscan.report import ReportGenerator
    gen = ReportGenerator.__new__(ReportGenerator)
    assert gen._build_coverage_html(None) == ""
    assert gen._build_coverage_html({}) == ""
    # 実データがあれば描画する。
    html = gen._build_coverage_html({
        "reached_count": 1, "attempts": 2, "findings_total": 0,
        "http_status": {"total": 3, "blocked": 0, "server_error": 0},
        "by_status": {}, "unreached": [],
    })
    assert "Coverage" in html
