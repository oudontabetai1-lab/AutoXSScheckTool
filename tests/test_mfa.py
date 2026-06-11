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
    # gosusnkr/mcp-totp-authenticator は account_label 引数を読む（label ではない）
    assert cfg.totp_label_arg == "account_label"


def test_mfaconfig_totp_without_args_disabled():
    cfg = mfa.MFAConfig.from_env(env={"WSCAN_MFA_TYPE": "totp"})
    # node コマンド既定はあるが起動スクリプト(args)が無いので無効
    assert cfg.enabled is False


def test_mfaconfig_email_requires_account():
    # account_name が無いと list/get が必ず失敗するため無効扱い
    cfg = mfa.MFAConfig.from_env(env={"WSCAN_MFA_TYPE": "email"})
    assert cfg.enabled is False


def test_mfaconfig_email_enabled_with_account():
    cfg = mfa.MFAConfig.from_env(
        env={"WSCAN_MFA_TYPE": "email", "WSCAN_MFA_EMAIL_ACCOUNT": "ops"}
    )
    assert cfg.enabled is True
    assert cfg.email_command == "uvx"
    assert cfg.email_args == ["mcp-email-server@latest", "stdio"]
    # 実在ツール名がデフォルト（get_emails は存在しない）
    assert cfg.email_list_tool == "list_emails_metadata"
    assert cfg.email_content_tool == "get_emails_content"
    assert cfg.email_account == "ops"


def test_mfaconfig_overrides_take_precedence():
    env = {"WSCAN_MFA_TYPE": "email", "WSCAN_MFA_FIELD": "otp"}
    cfg = mfa.MFAConfig.from_env(env=env, overrides={"type": "totp", "field": "code"})
    assert cfg.type == "totp"
    assert cfg.field == "code"


def test_mfaconfig_invalid_type_falls_back_to_none():
    cfg = mfa.MFAConfig.from_env(env={"WSCAN_MFA_TYPE": "sms"})
    assert cfg.type == "none"


def test_mfaconfig_email_tool_overrides_parsed():
    env = {
        "WSCAN_MFA_TYPE": "email",
        "WSCAN_MFA_EMAIL_ACCOUNT": "ops",
        "WSCAN_MFA_EMAIL_LIST_TOOL": "list_emails",
        "WSCAN_MFA_EMAIL_LIST_ARGS": '{"subject": "code"}',
        "WSCAN_MFA_EMAIL_PAGE_SIZE": "3",
        "WSCAN_MFA_CODE_LENGTH": "8",
    }
    cfg = mfa.MFAConfig.from_env(env=env)
    assert cfg.email_list_tool == "list_emails"
    assert cfg.email_list_args == {"subject": "code"}
    assert cfg.email_page_size == 3
    assert cfg.code_length == 8


def test_mfaconfig_explicit_disable_overrides_env():
    # UI/config で「無効」("") を選んだら env の WSCAN_MFA_TYPE を上書きして無効化
    env = {"WSCAN_MFA_TYPE": "totp", "WSCAN_MFA_TOTP_ARGS": "/srv/i.js"}
    cfg = mfa.MFAConfig.from_env(env=env, overrides={"type": "none"})
    assert cfg.type == "none"
    assert cfg.enabled is False


def test_mfaconfig_no_override_uses_env():
    # overrides に type が無ければ env を採用（未指定=env 委譲）
    env = {"WSCAN_MFA_TYPE": "totp", "WSCAN_MFA_TOTP_ARGS": "/srv/i.js"}
    cfg = mfa.MFAConfig.from_env(env=env, overrides={})
    assert cfg.type == "totp"
    assert cfg.enabled is True


# ── extract_email_ids ──────────────────────────────────────────────────────
def test_extract_email_ids_from_json():
    text = '{"emails": [{"uid": 1012, "subject": "x"}, {"uid": 1011}]}'
    assert mfa.extract_email_ids(text) == [1012, 1011]


def test_extract_email_ids_string_ids_and_dedup():
    text = '[{"id": "A1"}, {"id": "A1"}, {"email_id": "B2"}]'
    assert mfa.extract_email_ids(text) == ["A1", "B2"]


def test_extract_email_ids_limit():
    text = ",".join(f'{{"uid": {i}}}' for i in range(10))
    assert mfa.extract_email_ids(text, limit=3) == [0, 1, 2]


def test_extract_email_ids_empty():
    assert mfa.extract_email_ids("") == []
    assert mfa.extract_email_ids("no ids here") == []


# ── extract_subjects ───────────────────────────────────────────────────────
def test_extract_subjects():
    text = '{"emails":[{"uid":100200,"subject":"Your code is 482913"}]}'
    assert mfa.extract_subjects(text) == "Your code is 482913"


def test_extract_subjects_multiple():
    text = '[{"subject":"a"},{"subject":"b"}]'
    assert mfa.extract_subjects(text) == "a\nb"


def test_extract_subjects_empty():
    assert mfa.extract_subjects("") == ""
    assert mfa.extract_subjects('{"uid": 123456}') == ""


def test_subject_first_pass_ignores_uid():
    # 6桁の UID(100200) は OTP と誤判定せず、件名内の 482913 のみ拾う
    meta = '{"emails":[{"email_id":100200,"subject":"Code: 482913"}]}'
    assert mfa.extract_otp(mfa.extract_subjects(meta)) == "482913"
    # 件名にコードが無ければ件名パスは None（→本文取得に進む想定）
    meta2 = '{"emails":[{"email_id":100200,"subject":"New login"}]}'
    assert mfa.extract_otp(mfa.extract_subjects(meta2)) is None


# ── parse_email_items / email_item_id（古いメール対策） ─────────────────────
def test_parse_email_items_list():
    text = '[{"uid": 5, "subject": "a"}, {"uid": 6, "subject": "b"}]'
    items = mfa.parse_email_items(text)
    assert [it["uid"] for it in items] == [5, 6]


def test_parse_email_items_wrapped():
    text = '{"emails": [{"id": 1}, {"id": 2}], "page": 1}'
    items = mfa.parse_email_items(text)
    assert len(items) == 2


def test_parse_email_items_single_dict():
    text = '{"uid": 9, "subject": "x"}'
    assert mfa.parse_email_items(text) == [{"uid": 9, "subject": "x"}]


def test_parse_email_items_embedded_json():
    # 前後にテキストが付いていても JSON 部分を拾う
    text = 'result: {"emails": [{"uid": 7}]} done'
    assert mfa.parse_email_items(text) == [{"uid": 7}]


def test_parse_email_items_garbage():
    assert mfa.parse_email_items("not json") == []
    assert mfa.parse_email_items("") == []


# ── extract_email_texts（本文応答からの抽出は subject/body に限定） ─────────
def test_extract_email_texts_ignores_identifiers():
    # email_id(652130) と message_id/date は拾わず、body の 482913 のみ対象
    body = (
        '[{"email_id": 652130, "message_id": "<a@b>", "date": "2026-06-10", '
        '"subject": "Security", "body": "Your code is 482913"}]'
    )
    texts = mfa.extract_email_texts(body)
    assert mfa.extract_otp(texts) == "482913"
    assert "652130" not in texts


def test_extract_email_texts_subject_and_body():
    body = '[{"subject": "s", "body": "b"}]'
    assert mfa.extract_email_texts(body) == "s\nb"


def test_extract_email_texts_no_items():
    assert mfa.extract_email_texts("not json") == ""
    assert mfa.extract_email_texts("") == ""


def test_email_item_id_priority_and_coercion():
    assert mfa.email_item_id({"uid": "1012", "id": 5}) == 1012   # uid 優先・数字は int
    assert mfa.email_item_id({"email_id": "ABC"}) == "ABC"       # 非数字は str
    assert mfa.email_item_id({"subject": "x"}) is None
    assert mfa.email_item_id({"uid": None, "id": 3}) == 3        # 無効値は次キーへ
    assert mfa.email_item_id("nope") is None


def test_baseline_skip_logic():
    # 古いメール(uid 100)は baseline 化され、新着(uid 101)のみ対象になることを
    # 純粋関数レベルで確認（_solve_email の判定ロジックと同等）。
    old = mfa.parse_email_items('[{"uid":100,"subject":"old 111111"}]')
    baseline = {mfa.email_item_id(it) for it in old}
    later = mfa.parse_email_items(
        '[{"uid":101,"subject":"new 222222"},{"uid":100,"subject":"old 111111"}]'
    )
    new_items = [it for it in later if mfa.email_item_id(it) not in baseline]
    assert [mfa.email_item_id(it) for it in new_items] == [101]
    subj = "\n".join(it.get("subject", "") for it in new_items)
    assert mfa.extract_otp(subj) == "222222"


# ── MFASolver の分岐（MCP 呼び出しはモック） ───────────────────────────────
def test_solver_disabled_returns_none():
    import asyncio

    cfg = mfa.MFAConfig.from_env(env={})
    solver = mfa.MFASolver(cfg)
    assert solver.enabled is False
    assert asyncio.run(solver.solve()) is None


def test_solver_prime_noop_for_totp():
    import asyncio

    cfg = mfa.MFAConfig.from_env(
        env={"WSCAN_MFA_TYPE": "totp", "WSCAN_MFA_TOTP_ARGS": "/srv/i.js"}
    )
    solver = mfa.MFASolver(cfg)
    assert solver._email_baseline is None
    # TOTP では prime は何もしない（例外も出さない）。
    asyncio.run(solver.prime())
    assert solver._email_baseline is None
