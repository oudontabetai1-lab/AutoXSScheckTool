"""probe 証跡台帳 schema と純粋ヘルパのユニットテスト（0032-A・ブラウザ非依存）。

redaction（機微値を残さない）・hash 安定性・JSONL 1 行直列化・相関・enum 値を固定する。
"""
import json

import pytest

from wscan.probe_ledger import (
    ProbeAttemptRecord,
    ProbeOutcome,
    ProbeRole,
    RequestRecord,
    ResponseRecord,
    Transport,
    body_length,
    derive_attempt_id,
    redact_excerpt,
    sha256_hex,
    to_jsonl_line,
)


def test_role_and_outcome_vocabularies():
    assert {r.value for r in ProbeRole} == {
        "discover", "baseline", "control", "attack", "verify", "cleanup"
    }
    assert {o.value for o in ProbeOutcome} == {
        "matched", "no_match", "blocked", "skipped", "timeout",
        "transport_error", "verification_error", "unexecutable",
    }


def test_sha256_and_length_stable_and_pure():
    assert sha256_hex("abc") == sha256_hex("abc")
    assert sha256_hex(b"abc") == sha256_hex("abc")
    assert sha256_hex(None) == "" and sha256_hex("") != ""
    assert body_length("abc") == 3
    assert body_length("あ") == 3  # utf-8 3 bytes
    assert body_length(None) == 0


def test_redact_sensitive_headers_and_tokens():
    raw = (
        "Authorization: Bearer eyJhbGciOiJ.secretpart\n"
        "Cookie: session=abcdef123456\n"
        "X-Api-Key: key_live_9999\n"
        "User-Agent: wscan\n"
        "body token=supersecret&x=1"
    )
    out = redact_excerpt(raw)
    # 機微値は残らない
    assert "eyJhbGciOiJ.secretpart" not in out
    assert "abcdef123456" not in out
    assert "key_live_9999" not in out
    assert "supersecret" not in out
    assert "<redacted>" in out
    # 非機微は残る
    assert "User-Agent: wscan" in out


def test_redact_truncates_to_cap():
    out = redact_excerpt("A" * 1000, cap=100)
    assert len(out) <= 101 and out.endswith("…")


def test_redact_empty_is_empty():
    assert redact_excerpt("") == "" and redact_excerpt(None) == ""


def test_derive_attempt_id_deterministic():
    assert derive_attempt_id("scanX", 1) == "scanX:000001"
    assert derive_attempt_id("scanX", 1) == derive_attempt_id("scanX", 1)
    assert derive_attempt_id("scanX", 2) != derive_attempt_id("scanX", 1)


def test_record_correlated_property():
    base = dict(scan_id="s", attempt_id="a", role=ProbeRole.ATTACK)
    assert not ProbeAttemptRecord(**base).correlated
    assert ProbeAttemptRecord(**base, baseline_attempt_ids=("s:000001",)).correlated
    assert ProbeAttemptRecord(**base, control_attempt_ids=("s:000002",)).correlated


def test_jsonl_line_is_single_line_and_serializes_enums():
    rec = ProbeAttemptRecord(
        scan_id="s", attempt_id="s:000003", role=ProbeRole.ATTACK,
        check="xss", actor="xss_scanner", state_profile="unrestricted",
        baseline_attempt_ids=("s:000001",),
        request=RequestRecord(
            method="POST", url="http://h/a", transport=Transport.HTTPX,
            headers_excerpt=redact_excerpt("Cookie: x=secret"),
            body_excerpt=redact_excerpt("q=<script>"), body_hash=sha256_hex("q=<script>"),
            body_length=body_length("q=<script>"), sent=True,
        ),
        response=ResponseRecord(status=200, body_hash=sha256_hex("<html>"), dialog=True),
        outcome=ProbeOutcome.MATCHED, decision_rule="dialog_fired", decision_version="1",
    )
    line = to_jsonl_line(rec)
    assert "\n" not in line
    parsed = json.loads(line)
    # enum は値へ直列化
    assert parsed["role"] == "attack"
    assert parsed["outcome"] == "matched"
    assert parsed["request"]["transport"] == "httpx"
    # 相関 ID / 機微 redaction が保存されている
    assert parsed["baseline_attempt_ids"] == ["s:000001"]
    assert "secret" not in json.dumps(parsed)  # cookie 値は redact 済み


def test_records_are_frozen():
    import dataclasses
    r = ProbeAttemptRecord(scan_id="s", attempt_id="a", role=ProbeRole.BASELINE)
    with pytest.raises(dataclasses.FrozenInstanceError):
        r.scan_id = "z"  # type: ignore[misc]


def test_redact_json_credential_fields():
    # JSON body の quoted key/value（Codex P1）。request_logger 正典の JSON 対応へ委譲。
    out = redact_excerpt('{"password":"hunter2","access_token":"abc123","q":"safe"}')
    assert "hunter2" not in out and "abc123" not in out
    assert "<redacted>" in out
    assert "safe" in out  # 非機微は残る


def test_redact_custom_registered_sensitive_header():
    # runtime 登録したカスタム認証ヘッダ（Codex P2・#90 R13 の正典 registry を共有）
    from wscan.request_logger import register_sensitive_headers, clear_sensitive_headers
    try:
        register_sensitive_headers(["X-Company-Auth"])
        out = redact_excerpt("X-Company-Auth: opaquecredential\nUser-Agent: wscan")
        assert "opaquecredential" not in out
        assert "<redacted>" in out
        assert "User-Agent: wscan" in out
    finally:
        clear_sensitive_headers()


def test_jsonl_redacts_url_query_credentials():
    # request.url / response.final_url のクエリ機微値を永続化境界で伏せる（Codex P2）
    rec = ProbeAttemptRecord(
        scan_id="s", attempt_id="s:1", role=ProbeRole.ATTACK,
        request=RequestRecord(method="GET", url="http://h/cb?access_token=abc123&q=1",
                              transport=Transport.HTTPX),
        response=ResponseRecord(status=302, final_url="http://h/next?token=zzz999"),
    )
    line = to_jsonl_line(rec)
    assert "abc123" not in line and "zzz999" not in line
    assert "<redacted>" in line
    import json as _json
    assert _json.loads(line)["request"]["url"].startswith("http://h/cb?")


def test_redact_escaped_quote_json_credential():
    # `\"` を含む JSON scalar 全体を伏せる（Codex P1 追撃・escape-aware）
    out = redact_excerpt(r'{"password":"abc\"secret-tail","q":"safe"}')
    assert "secret-tail" not in out
    assert "abc" not in out or "<redacted>" in out
    assert "safe" in out


def test_jsonl_redacts_url_fragment_and_userinfo():
    # OAuth implicit の fragment token と userinfo を永続化境界で伏せる（Codex P2 追撃）
    rec = ProbeAttemptRecord(
        scan_id="s", attempt_id="s:1", role=ProbeRole.ATTACK,
        request=RequestRecord(method="GET", url="http://user:pass@host/p?token=leak&id=5",
                              transport=Transport.HTTPX),
        response=ResponseRecord(status=200, final_url="https://app/cb#access_token=abc123&state=ok"),
    )
    line = to_jsonl_line(rec)
    assert "abc123" not in line       # fragment token
    assert "user:pass" not in line    # userinfo
    assert "leak" not in line         # query token
    assert "state" in line and "id=5" in line  # 非機微は残る
