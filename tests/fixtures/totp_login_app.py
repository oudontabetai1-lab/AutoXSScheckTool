"""難読フィールドによる二段階 TOTP ログインと、非検出確認用の安全ツイン。"""
from __future__ import annotations

import secrets

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from wscan.totp import generate_totp

# ローカルテスト専用の公開資格情報。実サービスでは使用しない。
TOTP_SECRET = "JBSWY3DPEHPK3PXP"
USERNAME = "fixture-user"
PASSWORD = "fixture-password"

LOGIN_HTML = '''<form method="post" action="/login">
<label>Username <input name="f_2z" autocomplete="username"></label>
<label>Password <input name="f_9x" type="password"></label>
<button type="submit">Continue</button></form>'''
TOTP_HTML = '''<p>Enter the verification code from your authenticator app.</p>
<form method="post" action="/verify">
<input name="x1" autocomplete="one-time-code" inputmode="numeric" maxlength="6">
<button type="submit">Verify</button></form>'''


def create_app() -> FastAPI:
    """テストごとにセッション状態を分離したアプリを作る。"""
    app = FastAPI(title="TOTP login fixture")
    sessions: dict[str, bool] = {}

    @app.get("/login", response_class=HTMLResponse)
    async def login_page():
        return LOGIN_HTML

    @app.post("/login")
    async def login(request: Request, f_2z: str = Form(""), f_9x: str = Form("")):
        sessions.pop(request.cookies.get("session", ""), None)
        if f_2z != USERNAME or f_9x != PASSWORD:
            return HTMLResponse("Invalid credentials", status_code=401)
        session = secrets.token_urlsafe(24)
        sessions[session] = False
        response = RedirectResponse("/totp", status_code=303)
        response.set_cookie("session", session, httponly=True, samesite="lax")
        return response

    @app.get("/totp", response_class=HTMLResponse)
    async def totp_page(request: Request):
        if request.cookies.get("session", "") not in sessions:
            return HTMLResponse("Login required", status_code=401)
        return TOTP_HTML

    @app.post("/verify")
    async def verify(request: Request, x1: str = Form("")):
        session = request.cookies.get("session", "")
        if session not in sessions:
            return HTMLResponse("Login required", status_code=401)
        expected = generate_totp(TOTP_SECRET)
        if expected is None or not secrets.compare_digest(x1.encode(), expected.encode()):
            return HTMLResponse("Invalid verification code", status_code=401)
        sessions[session] = True
        return RedirectResponse("/dashboard", status_code=303)

    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard(request: Request):
        if not sessions.get(request.cookies.get("session", ""), False):
            return HTMLResponse("Authentication required", status_code=401)
        return '<h1>Signed in</h1><form><input name="search"><input name="filter"></form>'

    @app.get("/safe/contact", response_class=HTMLResponse)
    async def contact():
        return '<form><input name="subject"><input name="message"><button>Send</button></form>'

    @app.get("/safe/ambiguous", response_class=HTMLResponse)
    async def ambiguous():
        return '<p>Verification code</p><form><input type="text"><input type="text"></form>'

    return app
