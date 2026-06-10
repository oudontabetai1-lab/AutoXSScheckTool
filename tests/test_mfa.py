"""MFA コード取得ロジックの単体テスト（MCP / ネットワーク非依存）。

純粋関数（``extract_otp`` / ``looks_like_mfa_page`` / ``collect_tool_text`` /
``parse_command`` / ``parse_json_obj``）と ``MFAConfig.from_env`` の構成解釈を
検証する。実際の MCP 通信は対象外。
"""
from wscan import mfa


# ── extract_otp ────────────────────────────────────────────────────────────
def test_extract_otp_default_6_digits():
    assert mfa.extract_otp("Your code is 482913 — valid 5 min") == "482913"


def test_extract_otp_ignores_longer_or_shorter_runs():
    # 7桁の注文番号や年は拾わない（前後が数字でない6桁のみ）
    assert mfa.extract_otp("order 1234567 placed in 2026") is None


def test_extract_otp_custom_length():
    assert mfa.extract_otp("PIN: 12345678", length=8) == "12345678"


def test_extract_otp_custom_regex_group():
    assert mfa.extract_otp("code=[ABZ123]", regex=r"\[([A-Z0-9]+)\]") == "ABZ123"


def test_extract_otp_bad_regex_returns_none():
    assert mfa.extract_otp("123456", regex="(") is None


def test_extract_otp_empty():
    assert mfa.extract_otp("") is None
    assert mfa.extract_otp(None) is None


# ── looks_like_mfa_page ────────────────────────────────────────────────────
def test_looks_like_mfa_page_positive_en():
    html = "<h1>Enter the verification code from your authenticator app</h1>"
    assert mfa.looks_like_mfa_page(html) is True


def test_looks_like_mfa_page_positive_ja():
    assert mfa.looks_like_mfa_page("<p>ワンタイムパスワードを入力してください</p>") is True


def test_looks_like_mfa_page_negative_plain_login():
    # 通常のログインフォームは MFA とみなさない（誤検知ガード）
    html = '<form><input name="username"><input name="password"></form>'
    assert mfa.looks_like_mfa_page(html) is False


def test_looks_like_mfa_page_empty():
    assert mfa.looks_like_mfa_page("") is False


# ── mfa_field_present / mfa_challenge_present ──────────────────────────────
def test_mfa_field_present_by_name():
    html = '<form><input type="text" name="otp" maxlength="6"></form>'
    assert mfa.mfa_field_present(html, "otp") is True


def test_mfa_field_present_by_id_case_insensitive():
    html = '<input id="Code" autocomplete="one-time-code">'
    assert mfa.mfa_field_present(html, "code") is True


def test_mfa_field_present_no_match():
    html = '<input name="username"><input name="password">'
    assert mfa.mfa_field_present(html, "otp") is False
    assert mfa.mfa_field_present(html, "") is False
    assert mfa.mfa_field_present("", "otp") is False


def test_mfa_field_present_not_partial():
    # name="otptoken" は field="otp" に誤マッチしない（\b 境界）
    html = '<input name="otptoken">'
    assert mfa.mfa_field_present(html, "otp") is False


def test_mfa_challenge_present_via_generic_field():
    # 文言は素っ気ない（"Enter code"）が、設定欄 code があれば検出する
    html = '<h2>Enter code</h2><input name="code">'
    assert mfa.looks_like_mfa_page(html) is False
    assert mfa.mfa_challenge_present(html, "code") is True


def test_mfa_challenge_present_via_signal():
    html = "<p>verification code sent</p>"
    assert mfa.mfa_challenge_present(html, "otp") is True


def test_mfa_challenge_present_negative():
    html = '<form><input name="username"><input name="password"></form>'
    assert mfa.mfa_challenge_present(html, "otp") is False


# ── parse_command / parse_json_obj ─────────────────────────────────────────
def test_parse_command_shlex():
    assert mfa.parse_command("mcp-email-server@latest stdio") == [
        "mcp-email-server@latest",
        "stdio",
    ]


def test_parse_command_json_array():
    assert mfa.parse_command('["node", "/srv/dist/index.js"]') == [
        "node",
        "/srv/dist/index.js",
    ]


def test_parse_command_list_passthrough():
    assert mfa.parse_command(["a", "b"]) == ["a", "b"]


def test_parse_command_empty():
    assert mfa.parse_command("") == []
    assert mfa.parse_command(None) == []


def test_parse_json_obj():
    assert mfa.parse_json_obj('{"account": "ops", "page_size": 5}') == {
        "account": "ops",
        "page_size": 5,
    }
    assert mfa.parse_json_obj("") == {}
    assert mfa.parse_json_obj("not json") == {}
    assert mfa.parse_json_obj("[1,2]") == {}


# ── collect_tool_text ──────────────────────────────────────────────────────
class _FakeText:
    def __init__(self, text):
        self.text = text


class _FakeResult:
    def __init__(self, content, structured=None):
        self.content = content
        self.structuredContent = structured


def test_collect_tool_text_from_objects():
    res = _FakeResult([_FakeText("482913"), _FakeText("expires soon")])
    assert "482913" in mfa.collect_tool_text(res)


def test_collect_tool_text_from_dicts_and_structured():
    res = {
        "content": [{"text": "code: 100200"}],
        "structuredContent": {"otp": "100200"},
    }
    out = mfa.collect_tool_text(res)
    assert "100200" in out
    assert "otp" in out


def test_collect_tool_text_empty():
    assert mfa.collect_tool_text(_FakeResult([])) == ""


# ── MFAConfig.from_env ─────────────────────────────────────────────────────
def test_mfaconfig_disabled_by_default():
    cfg = mfa.MFAConfig.from_env(env={})
    assert cfg.type == "none"
    assert cfg.enabled is False


def test_mfaconfig_totp_enabled():
    env = {
        "WSCAN_MFA_TYPE": "totp",
        "WSCAN_MFA_TOTP_COMMAND": "node",
        "WSCAN_MFA_TOTP_ARGS": "/srv/dist/index.js",
        "WSCAN_MFA_TOTP_LABEL": "ops@example.com",
    }
    cfg = mfa.MFAConfig.from_env(env=env)
    assert cfg.type == "totp"
    assert cfg.enabled is True
    assert cfg.totp_args == ["/srv/dist/index.js"]
    assert cfg.totp_label == "ops@example.com"


def test_mfaconfig_totp_without_args_disabled():
    cfg = mfa.MFAConfig.from_env(env={"WSCAN_MFA_TYPE": "totp"})
    # node コマンド既定はあるが起動スクリプト(args)が無いので無効
    assert cfg.enabled is False


def test_mfaconfig_email_defaults_enabled():
    cfg = mfa.MFAConfig.from_env(env={"WSCAN_MFA_TYPE": "email"})
    assert cfg.enabled is True
    assert cfg.email_command == "uvx"
    assert cfg.email_args == ["mcp-email-server@latest", "stdio"]
    assert cfg.email_tool == "get_emails"


def test_mfaconfig_overrides_take_precedence():
    env = {"WSCAN_MFA_TYPE": "email", "WSCAN_MFA_FIELD": "otp"}
    cfg = mfa.MFAConfig.from_env(env=env, overrides={"type": "totp", "field": "code"})
    assert cfg.type == "totp"
    assert cfg.field == "code"


def test_mfaconfig_invalid_type_falls_back_to_none():
    cfg = mfa.MFAConfig.from_env(env={"WSCAN_MFA_TYPE": "sms"})
    assert cfg.type == "none"


def test_mfaconfig_email_tool_args_parsed():
    env = {
        "WSCAN_MFA_TYPE": "email",
        "WSCAN_MFA_EMAIL_TOOL": "list_emails",
        "WSCAN_MFA_EMAIL_TOOL_ARGS": '{"account": "ops", "page_size": 3}',
        "WSCAN_MFA_CODE_LENGTH": "8",
    }
    cfg = mfa.MFAConfig.from_env(env=env)
    assert cfg.email_tool == "list_emails"
    assert cfg.email_tool_args == {"account": "ops", "page_size": 3}
    assert cfg.code_length == 8


# ── MFASolver の分岐（MCP 呼び出しはモック） ───────────────────────────────
def test_solver_disabled_returns_none():
    import asyncio

    cfg = mfa.MFAConfig.from_env(env={})
    solver = mfa.MFASolver(cfg)
    assert solver.enabled is False
    assert asyncio.run(solver.solve()) is None
