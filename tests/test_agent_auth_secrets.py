"""Agent login secret の prompt 非混入と domain scope 契約。"""
import json

from wscan.llm_agent_browser import AgentBrowserScanner, build_agent_sensitive_data
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest


def test_auth_secrets_are_placeholders_in_task():
    scanner = AgentBrowserScanner(
        "https://app.example.test",
        auth_user="real-user",
        auth_pass="real-password",
        login_url="https://login.example.test/sign-in",
        totp_secret="JBSWY3DPEHPK3PXP",
    )
    task = scanner._build_task()
    assert "real-user" not in task
    assert "real-password" not in task
    assert "JBSWY3DPEHPK3PXP" not in task
    assert "WSCAN_AUTH_USER" in task
    assert "WSCAN_bu_2fa_code" in task


def test_sensitive_data_is_domain_scoped_and_totp_named_for_browser_use():
    data = build_agent_sensitive_data(
        "https://login.example.test/sign-in", "user", "pass", "totp-secret"
    )
    assert data == {
        "login.example.test": {
            "WSCAN_AUTH_USER": "user",
            "WSCAN_AUTH_PASS": "pass",
            "WSCAN_bu_2fa_code": "totp-secret",
        }
    }


def test_storage_state_auth_task_does_not_request_missing_placeholders():
    scanner = AgentBrowserScanner(
        "https://app.example.test",
        login_url="https://app.example.test/login",
        storage_state="state.json",
    )
    from wscan.agent_harness import AgentRole, AgentWorkItem

    work = AgentWorkItem("auth", AgentRole.AUTHENTICATOR, scanner.login_url)
    task = scanner._build_work_task(work, [])
    assert "WSCAN_AUTH_USER" not in task
    assert "AUTH COMPLETE" in task


def test_resume_auth_fingerprint_covers_credentials_headers_and_storage(tmp_path):
    storage = tmp_path / "storage.json"
    storage.write_text('{"cookies":[]}', encoding="utf-8")
    base = dict(
        target_url="https://app.example.test",
        login_url="https://app.example.test/login",
        auth_user="account-a",
        auth_pass="password-a",
        totp_secret="totp-a",
        extra_headers={"Authorization": "Bearer a"},
        storage_state=str(storage),
    )
    original = AgentBrowserScanner(**base)._auth_context_hash()
    assert len(original) == 64
    for change in (
        {"auth_user": "account-b"},
        {"auth_pass": "password-b"},
        {"totp_secret": "totp-b"},
        {"extra_headers": {"Authorization": "Bearer b"}},
        {"login_url": "https://app.example.test/other-login"},
    ):
        assert AgentBrowserScanner(**(base | change))._auth_context_hash() != original
    storage.write_text('{"cookies":[{"name":"session","value":"b"}]}', encoding="utf-8")
    assert AgentBrowserScanner(**base)._auth_context_hash() != original


@pytest.mark.asyncio
async def test_engine_redacts_reflected_login_secrets_from_artifacts(tmp_path):
    from wscan.agent_engine import AgentEngine

    result = SimpleNamespace(
        findings=[], steps_taken=1, success=False, error="",
        final_summary="target echoed user-secret and password-secret",
        harness_status="partial", coverage_gaps=["auth incomplete"],
    )
    with patch("wscan.llm_agent_browser.AgentBrowserScanner") as scanner:
        scanner.return_value.run = AsyncMock(return_value=result)
        engine = AgentEngine(
            "https://app.example.test", auth_user="user-secret",
            auth_pass="password-secret", output_dir=str(tmp_path), open_report=False,
        )
        await engine.run()

    artifacts = (tmp_path / "evidence.json").read_text() + (tmp_path / "agent_summary.md").read_text()
    assert "user-secret" not in artifacts
    assert "password-secret" not in artifacts
    assert "<redacted>" in artifacts


@pytest.mark.asyncio
async def test_engine_redacts_values_without_corrupting_evidence_json(tmp_path):
    from wscan.agent_engine import AgentEngine

    result = SimpleNamespace(
        findings=[], steps_taken=1, success=False, error="",
        final_summary='a says "hello"', harness_status="partial",
        coverage_gaps=['a " gap'],
    )
    with patch("wscan.llm_agent_browser.AgentBrowserScanner") as scanner:
        scanner.return_value.run = AsyncMock(return_value=result)
        engine = AgentEngine(
            "https://app.example.test/a", auth_user="a", auth_pass='"',
            output_dir=str(tmp_path), open_report=False,
        )
        await engine.run()

    evidence = json.loads((tmp_path / "evidence.json").read_text())
    assert set(evidence) >= {"target", "final_summary", "coverage_gaps", "findings"}
    assert evidence["final_summary"] == (
        "<redacted> s<redacted>ys <redacted>hello<redacted>"
    )


@pytest.mark.asyncio
async def test_rejected_non_resume_invocation_preserves_existing_artifacts(tmp_path):
    from wscan.agent_engine import AgentEngine

    evidence = tmp_path / "evidence.json"
    reproduction = tmp_path / "reproduction.json"
    evidence.write_text("original evidence")
    reproduction.write_text("original reproduction")
    result = SimpleNamespace(
        findings=[], steps_taken=0, success=False,
        error="Agent output already contains harness state",
        final_summary="", preserve_existing_artifacts=True,
    )
    with patch("wscan.llm_agent_browser.AgentBrowserScanner") as scanner:
        scanner.return_value.run = AsyncMock(return_value=result)
        engine = AgentEngine(
            "https://app.example.test", output_dir=str(tmp_path), open_report=False
        )
        returned = await engine.run()

    assert returned is result
    assert evidence.read_text() == "original evidence"
    assert reproduction.read_text() == "original reproduction"
