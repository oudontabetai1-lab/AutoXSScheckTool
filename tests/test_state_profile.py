from pathlib import Path
import sys
from types import SimpleNamespace

import httpx
import pytest

import main
from tests.fixtures.state_profile_app import create_app
from wscan.engine import ScanEngine
from wscan.injection_point import InjectionPoint
from wscan.scanners.base import BaseScanner
from wscan.state_profile import (
    DESTRUCTIVE_KEYWORDS,
    VALID_PROFILES,
    is_state_changing,
    looks_destructive,
    may_submit,
)


@pytest.mark.parametrize("method", ["POST", "put", " Patch ", "DELETE"])
def test_is_state_changing_write_methods(method):
    assert is_state_changing(method)


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "", "TRACE"])
def test_is_state_changing_safe_or_unknown_methods(method):
    assert not is_state_changing(method)


@pytest.mark.parametrize("keyword", DESTRUCTIVE_KEYWORDS)
def test_looks_destructive_matches_action_and_labels_case_insensitively(keyword):
    assert looks_destructive(method="POST", action=f"/account/{keyword.upper()}")
    assert looks_destructive(method="DELETE", labels=f"Confirm {keyword.title()}")
    assert not looks_destructive(method="GET", action=f"/{keyword}")


@pytest.mark.parametrize("profile", VALID_PROFILES)
@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "PATCH", "DELETE"])
def test_may_submit_profile_method_matrix(profile, method):
    allowed = may_submit(profile, method=method, action="/profile/update", labels="Save")
    if profile == "read-only":
        assert allowed is (method == "GET")
    else:
        assert allowed


def test_controlled_write_only_blocks_destructive_state_changes():
    assert not may_submit(
        "controlled-write", method="POST", action="/account/delete", labels="Delete"
    )
    assert may_submit(
        "controlled-write", method="POST", action="/login", labels="Sign in"
    )


def test_unknown_profile_preserves_unrestricted_compatibility():
    assert may_submit("future-profile", method="DELETE", action="/account/delete")


class _FixtureBrowser:
    def __init__(self, app):
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://fixture.test"
        )
        self.forms = {
            0: ("POST", "/account/delete", "reason"),
            1: ("POST", "/login", "username"),
        }

    async def close(self):
        await self.client.aclose()

    async def fill_and_submit_form(self, form_index, field_name, payload):
        method, action, expected_field = self.forms[form_index]
        assert field_name == expected_field
        response = await self.client.request(method, action, data={field_name: payload})
        return response.text, {"response": {"body": response.text}}

    async def test_url_param(self, url, field_name, payload):
        response = await self.client.get(url, params={field_name: payload})
        return response.text, {"response": {"body": response.text}}


class _FixtureScanner(BaseScanner):
    CHECK_TYPE = "sqli"

    async def scan_field(self, url, form_index, field, is_url_param=False):
        return []

    async def _apply_payload(self, url, form_index, field_name, payload, is_url_param):
        if is_url_param:
            return await self.browser.test_url_param(url, field_name, payload)
        return await self.browser.fill_and_submit_form(form_index, field_name, payload)

    async def detects_sqli(self, ip):
        source, _ = await self._apply_ip(ip, "'")
        return "SQL syntax error" in source


def _scanner(app, profile_marker=...):
    engine_values = {
        "browser": _FixtureBrowser(app),
        "monitor": None,
        "payload_gen": SimpleNamespace(),
        "wave_errors": [],
    }
    if profile_marker is not ...:
        engine_values["state_profile"] = profile_marker
    engine = SimpleNamespace(**engine_values)
    return _FixtureScanner(engine), engine


@pytest.mark.asyncio
async def test_unrestricted_default_preserves_post_injection_detection():
    app = create_app()
    scanner, engine = _scanner(app)  # state_profile 欠落時も unrestricted
    try:
        login = InjectionPoint.for_form(
            "http://fixture.test/", "username", 1,
            method="POST", action="/login", labels="Sign in",
        )
        assert await scanner.detects_sqli(login)
        assert app.state.submissions["login"] == 1
        assert engine.wave_errors == []
    finally:
        await scanner.browser.close()


@pytest.mark.asyncio
async def test_read_only_skips_post_and_continues_get_detection():
    app = create_app()
    scanner, engine = _scanner(app, "read-only")
    try:
        login = InjectionPoint.for_form(
            "http://fixture.test/", "username", 1,
            method="POST", action="/login", labels="Sign in",
        )
        search = InjectionPoint.for_url_param("http://fixture.test/search", "q")
        assert not await scanner.detects_sqli(login)
        assert app.state.submissions["login"] == 0
        assert await scanner.detects_sqli(search)
        assert app.state.submissions["search"] == 1
        assert engine.wave_errors == ["state_change_skipped:sqli"]
        assert ScanEngine.observability_summary(engine)["by_category"] == {
            "state_change_skipped": 1
        }
    finally:
        await scanner.browser.close()


@pytest.mark.asyncio
async def test_controlled_write_skips_destructive_twin_but_detects_normal_post():
    app = create_app()
    scanner, engine = _scanner(app, "controlled-write")
    try:
        destructive = InjectionPoint.for_form(
            "http://fixture.test/", "reason", 0,
            method="POST", action="/account/delete", labels="Delete account",
        )
        login = InjectionPoint.for_form(
            "http://fixture.test/", "username", 1,
            method="POST", action="/login", labels="Sign in",
        )
        assert not await scanner.detects_sqli(destructive)
        assert app.state.submissions["delete"] == 0
        assert await scanner.detects_sqli(login)
        assert app.state.submissions["login"] == 1
        assert engine.wave_errors == ["state_change_skipped:sqli"]
    finally:
        await scanner.browser.close()


def test_engine_invalid_profile_warns_and_falls_back(tmp_path):
    with pytest.warns(RuntimeWarning, match="falling back to 'unrestricted'"):
        engine = ScanEngine(
            "http://fixture.test/",
            state_profile="not-a-profile",
            output_dir=str(tmp_path),
            llm_provider="none",
            checks=[],
        )
    assert engine.state_profile == "unrestricted"


def test_config_loader_and_cli_expose_state_profile(tmp_path, monkeypatch):
    config_path = tmp_path / "wscan.yaml"
    config_path.write_text(
        "scan:\n  state_profile: controlled-write\n", encoding="utf-8"
    )
    assert main._load_config(config_path)["state_profile"] == "controlled-write"

    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "scan", "http://fixture.test", "--state-profile", "read-only"],
    )
    assert main.parse_args().state_profile == "read-only"


def test_dashboard_selector_defaults_and_scan_payload_are_wired():
    html = Path("templates/dashboard.html").read_text(encoding="utf-8")
    assert 'id="cfgStateProfile"' in html
    assert "state_profile: document.getElementById('cfgStateProfile').value" in html
    assert "if (cfg.state_profile) document.getElementById('cfgStateProfile').value" in html


@pytest.mark.parametrize("action", ["/deleteAccount", "/payments", "/checkoutSession",
                                    "/account/delete", "/transferFunds", "/removeItems"])
def test_looks_destructive_matches_identifier_style_urls(action):
    # camelCase/複数形の identifier も破壊語として検出する（#109 P2）。
    from wscan.state_profile import looks_destructive
    assert looks_destructive(method="POST", action=action) is True


@pytest.mark.parametrize("action", ["/submit-payload", "/login", "/search", "/pages", "/render"])
def test_looks_destructive_ignores_non_destructive_identifiers(action):
    # payload 等の無関係 identifier を破壊語と誤検出しない。
    from wscan.state_profile import looks_destructive
    assert looks_destructive(method="POST", action=action) is False


class _ConcreteScanner(BaseScanner):
    CHECK_TYPE = "xxe"

    async def scan_field(self, url, form_index, field, is_url_param):  # pragma: no cover
        return []


def test_gate_uses_url_when_action_is_benign():
    # action が benign でも url が destructive なら controlled-write は送信しない（#109 P1・XXE 経路）。
    engine = SimpleNamespace(state_profile="controlled-write", wave_errors=[])
    scanner = _ConcreteScanner.__new__(_ConcreteScanner)  # __init__ を回避（engine 属性のみ必要）
    scanner.engine = engine
    ip = InjectionPoint.for_form(
        "http://fixture.test/account/delete", "xml", 0,
        method="POST", action="http://fixture.test/submit", labels="",
    )
    assert scanner.may_scan_injection_point(ip, record_skip=False) is False
    # unrestricted は常に許可。
    engine.state_profile = "unrestricted"
    assert scanner.may_scan_injection_point(ip, record_skip=False) is True
