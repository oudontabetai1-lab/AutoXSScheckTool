"""フォーム action origin を学習キーへ配線するブラウザ非依存テスト。"""

import asyncio
import types

from wscan.engine import CrawledPage, ScanEngine
from wscan.scanners.base import BaseScanner, Finding


class _CapturingLearner:
    def __init__(self):
        self.calls = []

    def record(self, check_type, payload, success, domain=None):
        self.calls.append((check_type, payload, success, domain))


def _thin_engine():
    return object.__new__(ScanEngine)


def test_form_effective_action_origin_prefers_submit_override_and_normalizes():
    engine = _thin_engine()
    assert engine._form_effective_action_origin(
        {
            "action": "http://fallback.test/submit",
            "submit_action": "https://user:secret@b.test:443/override",
        },
        "http://a.test/page",
    ) == "https://b.test"


def test_form_effective_action_origin_falls_back_to_form_action():
    engine = _thin_engine()
    assert engine._form_effective_action_origin(
        {"action": "/submit"},
        "http://a.test:80/page",
    ) == "http://a.test"


def test_form_effective_action_origin_returns_empty_when_unresolvable():
    engine = _thin_engine()
    assert engine._form_effective_action_origin(
        {"submit_action": "mailto:ops@example.test"},
        "http://a.test/page",
    ) == ""


def test_injection_point_carries_target_origin_without_registry():
    engine = _thin_engine()
    ip = engine._injection_point_for(
        "http://a.test/page", "q", 3, False, target_origin="http://b.test"
    )
    assert ip.target_origin == "http://b.test"
    assert ip.form_index == 3


def test_carry_along_keeps_slash_variant_origins_independent():
    engine = _thin_engine()
    app_ip = engine._injection_point_for(
        "http://a.test/app", "q", 0, False, target_origin="http://b.test"
    )
    slash_ip = engine._injection_point_for(
        "http://a.test/app/", "q", 0, False, target_origin="http://c.test"
    )
    assert app_ip.target_origin == "http://b.test"
    assert slash_ip.target_origin == "http://c.test"


def test_scan_field_uses_carried_target_origin_for_scanner():
    async def run():
        captured_ips = []

        async def scan_injection_point(ip, field):
            captured_ips.append(ip)
            return []

        engine = types.SimpleNamespace(
            scanners={
                "xss": types.SimpleNamespace(
                    scan_injection_point=scan_injection_point,
                ),
            },
            all_findings=[],
            flag_finder=None,
            adaptive_enabled=False,
            completed_fields=0,
            total_fields=1,
            monitor=None,
            _checkpoint_is_done_ip=lambda ip, check: False,
            _checkpoint_mark_done_ip=lambda ip, check: None,
            _record_scan_matrix=lambda **kwargs: None,
            _record_finding=lambda finding, source="": None,
            _save_checkpoint=lambda: None,
        )
        engine._injection_point_for = types.MethodType(
            ScanEngine._injection_point_for, engine
        )

        await ScanEngine._scan_field(
            engine,
            "http://a.test/page",
            0,
            {"name": "q"},
            target_origin="http://b.test",
        )

        assert len(captured_ips) == 1
        assert captured_ips[0].target_origin == "http://b.test"

    asyncio.run(run())


class _MultiParamBrowser:
    dialog_fired = True
    dialog_message = "multi-xss"

    async def navigate(self, url, retries=0):
        return True

    def reset_dialog(self):
        pass

    async def fill_and_submit_form_multi(self, form_index, field_payloads):
        return "", {"request": {}, "response": {}}

    async def screenshot_b64(self, label=""):
        return ""


class _MultiParamScanner(BaseScanner):
    CHECK_TYPE = "xss"

    async def scan_field(self, url, form_index, field, is_url_param=False):
        return []


class _MultiParamController:
    async def wait_if_paused_or_abort(self):
        return None


def test_multi_param_finding_stamps_form_effective_action_origin():
    async def run():
        browser = _MultiParamBrowser()
        engine = types.SimpleNamespace(
            max_forms=10,
            exclude_fields=set(),
            payload_gen=types.SimpleNamespace(
                default_payloads={"xss": ["<x>"]},
            ),
            controller=_MultiParamController(),
            browser=browser,
            navigation_retries=0,
            _effective_delay=0,
            flag_finder=None,
            monitor=None,
            _finding_dedup=set(),
            all_findings=[],
            scanners={},
            _record_finding=lambda finding, source="": None,
            _record_unscannable_url=lambda *args, **kwargs: None,
            _navigation_failure_note=lambda: "",
        )
        engine._form_effective_action_origin = types.MethodType(
            ScanEngine._form_effective_action_origin, engine
        )
        engine._form_action_url = types.MethodType(
            ScanEngine._form_action_url, engine
        )
        engine.scanners["xss"] = _MultiParamScanner(engine)
        page = CrawledPage(
            url="http://a.test/page",
            html="",
            forms=[{
                "action": "http://fallback.test/submit",
                "submit_action": "http://b.test/override",
                "inputs": [{"name": "first"}, {"name": "second"}],
            }],
            url_params=[],
            depth=0,
        )

        await ScanEngine._phase_multi_param(engine, page, None)

        assert len(engine.all_findings) == 1
        assert engine.all_findings[0].injection_target_origin == "http://b.test"

    asyncio.run(run())


def test_record_finding_prefers_action_origin_and_falls_back_to_page_origin():
    engine = _thin_engine()
    engine._finding_dedup = set()
    engine.all_findings = []
    engine._notifier = None
    engine.enable_payload_learning = True
    engine.payload_learner = _CapturingLearner()
    engine.flag_finder = None

    action_finding = Finding(
        check_type="xss",
        severity="high",
        url="http://a.test/page",
        field_name="q",
        payload="<b-only>",
        evidence="dialog",
        injection_target_origin="http://b.test",
    )
    legacy_finding = Finding(
        check_type="xss",
        severity="high",
        url="http://a.test/legacy",
        field_name="q2",
        payload="<a-only>",
        evidence="dialog",
    )

    engine._record_finding(action_finding)
    engine._record_finding(legacy_finding)

    assert engine.payload_learner.calls == [
        ("xss", "<b-only>", True, "http://b.test"),
        ("xss", "<a-only>", True, "http://a.test"),
    ]
