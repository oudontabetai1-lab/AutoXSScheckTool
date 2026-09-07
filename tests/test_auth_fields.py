"""認証欄検出の TP/FP と二段階 TOTP fixture の実行検証。"""
import pytest
from fastapi.testclient import TestClient

from tests.fixtures.totp_login_app import PASSWORD, TOTP_SECRET, USERNAME, create_app
from wscan.auth_fields import find_otp_field, find_password_field, find_username_field
from wscan.totp import generate_totp


@pytest.mark.parametrize("html, expected", [
    ('<input name="f_9x" type="password">', 'input[type="password"]'),
    ('<INPUT TYPE=PASSWORD>', 'input[type="password"]'),
    ('<input type="password"><input type="password">', 'input[type="password"]'),
    ('<input name="password">', None),
    ('<!-- <input type="password"> -->', None),
    ('<script>const s = \'<input type="password">\';</script>', None),
    ('', None),
])
def test_password(html, expected):
    assert find_password_field(html) == expected


@pytest.mark.parametrize("html, expected", [
    ('<input autocomplete="username">', 'input[autocomplete="username"]'),
    ('<input name="x1" autocomplete="username"><input type="email">', 'input[autocomplete="username"]'),
    ('<input type="email"><input name="user">', 'input[type="email"]'),
    ('<input name="f_2z"><input type="password">', '[name="f_2z"]'),
    ('<input id="f_2z"><input type="password">', '[id="f_2z"]'),
    ('<input type="text"><input type="password">', 'input[type="text"]'),
    ('<input><input type="password">', 'input:not([type])'),
    ('<input type="tel"><input type="password">', 'input[type="tel"]'),
    ('<input name="user"><input name="x1"><input type="password">', '[name="x1"]'),
    ('<input name="account_name">', '[name="account_name"]'),
    ('<input id="USERID">', '[id="USERID"]'),
    ('<input type="text"><input type="text"><input type="password">', None),
    ('<input type="email"><input type="email">', None),
    ('<input autocomplete="username"><input autocomplete="username">', None),
    ('<input type="hidden" name="user">', None),
    ('<input name="x1">', None),
    ('', None),
])
def test_username(html, expected):
    assert find_username_field(html) == expected


@pytest.mark.parametrize("html, expected", [
    ('<input autocomplete="one-time-code">', 'input[autocomplete="one-time-code"]'),
    ('<input name="otp"><input autocomplete="one-time-code">', 'input[autocomplete="one-time-code"]'),
    ('<input name="otp" inputmode="numeric">', '[name="otp"]'),
    ('<input name="x1" id="mfa">', '[name="x1"]'),
    ('<input id="TOTP">', '[id="TOTP"]'),
    ('<input inputmode="numeric">', 'input[inputmode="numeric"]'),
    ('<input inputmode="numeric" maxlength="8">', 'input[inputmode="numeric"]'),
    ('<input pattern="[0-9]{6}" maxlength="6">', 'input[maxlength="6"]'),
    ('<input pattern="[0-9]{6}">', 'input[pattern]'),
    ('<p>Verification code</p><input type="tel">', 'input[type="tel"]'),
    ('<p>Verification code</p><input>', 'input:not([type])'),
    ('<p>Verification code</p><input type="hidden"><input type="text">', 'input[type="text"]'),
    ('<input name="otp"><span name="otp"></span>', 'input:not([type])'),
    ('<input name="otp" id="unique"><input name="otp" type="hidden">', '[id="unique"]'),
    ('<input name="otp&quot;bad" id="safe">', '[id="safe"]'),
    ('<input name="subject"><input name="message">', None),
    ('<p>Verification code</p><input type="text"><input type="text">', None),
    ('<input inputmode="numeric"><input inputmode="numeric">', None),
    ('<input name="otp"><input name="pin">', None),
    ('<input autocomplete="one-time-code"><input autocomplete="one-time-code">', None),
    ('<input name="otp" type="hidden">', None),
    ('<input name="otp" disabled>', None),
    ('<input name="otp" readonly>', None),
    ('<input name="otp" hidden>', None),
    ('<div hidden><input name="otp"></div>', None),
    ('<template><input name="otp"></template>', None),
    ('<input name="otp" style="display: none">', None),
    ('<input name="otp" type="password">', None),
    ('<input autocomplete="one-time-code" type="password">', None),
    ('<input autocomplete="one-time-code" type="checkbox">', None),
    ('<input inputmode="numeric" maxlength="' + '9' * 5000 + '">', None),
    ('<input type="text" maxlength="6" inputmode="numeric"><input type="text"><input type="hidden" inputmode="numeric">', 'input[maxlength="6"]'),
    ('<input name="otp" type="submit">', None),
    ('<input inputmode="numeric" maxlength="9">', None),
    ('<input inputmode="numeric" maxlength="-1">', None),
    ('<input inputmode="numeric" maxlength="bad">', None),
    ('<input inputmode="numeric" maxlength="0">', None),
    ('<input name="otp&quot;bad" type="text"><input type="text">', None),
    ('<!-- <input autocomplete="one-time-code"> -->', None),
    ('', None),
])
def test_otp(html, expected):
    assert find_otp_field(html) == expected


@pytest.mark.parametrize("hint", ["otp", "code", "token", "mfa", "2fa", "totp", "passcode", "pin"])
def test_otp_name_hints(hint):
    assert find_otp_field(f'<input name="prefix_{hint}_suffix">') == f'[name="prefix_{hint}_suffix"]'


def test_fixture_login_totp_and_safe_twins(monkeypatch):
    # 時刻境界によるコード切替を避け、アプリとテストの時計を一致させる。
    monkeypatch.setattr("wscan.totp.time.time", lambda: 1_700_000_000)
    with TestClient(create_app()) as client:
        login = client.get("/login")
        assert login.status_code == 200
        assert find_username_field(login.text) == 'input[autocomplete="username"]'
        assert find_password_field(login.text) == 'input[type="password"]'
        assert find_otp_field(login.text) is None
        for path in ("/totp", "/dashboard"):
            assert client.get(path).status_code == 401
        assert client.post("/verify", data={"x1": generate_totp(TOTP_SECRET)}).status_code == 401
        assert client.post("/login", data={"f_2z": USERNAME, "f_9x": "wrong"}).status_code == 401
        response = client.post("/login", data={"f_2z": USERNAME, "f_9x": PASSWORD})
        assert response.status_code == 200
        assert response.url.path == "/totp"
        totp = client.get("/totp")
        assert find_otp_field(totp.text) == 'input[autocomplete="one-time-code"]'
        assert find_username_field(totp.text) is None
        assert find_password_field(totp.text) is None
        assert client.get("/dashboard").status_code == 401
        for wrong in ("", "invalid", "１２３４５６", generate_totp(TOTP_SECRET, timestamp=1_699_999_940)):
            assert client.post("/verify", data={"x1": wrong}).status_code == 401
            assert client.get("/dashboard").status_code == 401
        code = generate_totp(TOTP_SECRET)
        assert code is not None
        signed_in = client.post("/verify", data={"x1": code})
        assert signed_in.status_code == 200
        assert signed_in.url.path == "/dashboard"
        assert "Signed in" in signed_in.text
        for path in ("/safe/contact", "/safe/ambiguous"):
            safe = client.get(path)
            assert safe.status_code == 200
            assert find_otp_field(safe.text) is None
    with TestClient(create_app()) as other:
        assert other.get("/dashboard").status_code == 401
