"""通常層の probe/wave 脱落が console・レポートへ届くことを検証する。"""

import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from wscan.engine import ScanEngine, _observability_warning_text
from wscan.injection_point import InjectionPoint
from wscan.report import ReportGenerator
from wscan.scanners.base import BaseScanner


class _Scanner(BaseScanner):
    CHECK_TYPE = "xss"
    SUPPORTS_JSON_BODY = True

    async def scan_field(self, url, form_index, field, is_url_param=False):
        return []

    async def _apply_payload(
        self, url, form_index, field_name, payload, is_url_param
    ):
        raise TimeoutError("transport down")


def _engine(**overrides):
    values = {
        "browser": None,
        "monitor": None,
        "payload_gen": None,
        "wave_errors": [],
        "injection_templates": {},
        "timeout": 1,
        "proxy": "",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_observability_summary_groups_categories_and_other():
    engine = ScanEngine.__new__(ScanEngine)
    engine.wave_errors = [
        "transport_error:xss:TimeoutError",
        "transport_error:nosql:OSError",
        "baseline_unavailable:os",
        "legacy note without category",
    ]

    assert engine.observability_summary() == {
        "total": 4,
        "by_category": {
            "transport_error": 2,
            "baseline_unavailable": 1,
            "other": 1,
        },
    }


@pytest.mark.asyncio
async def test_form_transport_exception_is_recorded_and_falls_back():
    engine = _engine()
    scanner = _Scanner(engine)
    ip = InjectionPoint.for_url_param("http://fixture.test/?q=x", "q")

    assert await scanner._apply_ip(ip, "probe") == ("", {})
    assert engine.wave_errors == ["transport_error:xss:TimeoutError"]


@pytest.mark.asyncio
async def test_json_transport_exception_and_missing_template_are_recorded():
    template_ip = InjectionPoint.for_json_body(
        "POST", "http://fixture.test/api", "/name", template_id="t1"
    )
    engine = _engine(
        injection_templates={
            "t1": {
                "url": "http://fixture.test/api",
                "method": "POST",
                "json_body": {"name": "safe"},
            }
        },
        httpx_client_kwargs=lambda **_kwargs: (_ for _ in ()).throw(
            RuntimeError("config failed")
        ),
    )
    scanner = _Scanner(engine)

    assert await scanner._apply_json_payload(template_ip, "probe") == ("", {})
    assert engine.wave_errors == ["transport_error:xss:RuntimeError"]

    missing_ip = InjectionPoint.for_json_body(
        "POST", "http://fixture.test/api", "/name", template_id="missing"
    )
    assert await scanner._apply_json_payload(missing_ip, "probe") == ("", {})
    assert engine.wave_errors[-1] == "unexecutable_template:xss"


def test_console_warning_is_only_built_for_degradation():
    assert _observability_warning_text({"total": 0, "by_category": {}}) == ""
    warning = _observability_warning_text(
        {"total": 2, "by_category": {"probe_error": 1, "transport_error": 1}}
    )
    assert "⚠ 観測性: 2 件" in warning
    assert "probe_error=1" in warning
    assert "0 findings は「安全」を意味しない可能性" in warning


def test_report_contains_observability_total_categories_and_samples():
    observability = {
        "total": 2,
        "by_category": {"transport_error": 2},
        "samples": ["transport_error:xss:TimeoutError"],
    }
    with tempfile.TemporaryDirectory() as tmp:
        report_path = ReportGenerator(Path(tmp)).generate(
            target="http://fixture.test",
            findings=[],
            visited_urls=["http://fixture.test"],
            checks=["xss"],
            observability=observability,
        )
        html = report_path.read_text(encoding="utf-8")

    assert "Observability（観測性メトリクス）" in html
    assert "劣化・脱落した probe/wave: <strong>2</strong> 件" in html
    assert "by_category" in html
    assert "transport_error" in html
    assert "transport_error:xss:TimeoutError" in html

