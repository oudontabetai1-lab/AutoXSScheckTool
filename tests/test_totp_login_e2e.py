"""実Chromiumでの認証フォールバック・OTP明示指定・QR連携（WSCAN_E2E=1）。"""
import asyncio
from contextlib import contextmanager
import os
import socket
import threading
import time

import pytest
import uvicorn

from tests.fixtures.totp_login_app import PASSWORD, TOTP_SECRET, USERNAME, create_app
from wscan.browser import BrowserManager
from wscan.manual_crawl import ManualCrawlSession
from wscan.mfa import MFAConfig, MFASolver

pytestmark = pytest.mark.skipif(os.getenv("WSCAN_E2E") != "1", reason="WSCAN_E2E=1 で実ブラウザ検証")


@contextmanager
def serving(app):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("fixture server did not start")
            time.sleep(.02)
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        sock.close()


@pytest.mark.parametrize("variant", ["obfuscated", "nameless", "override", "qr"])
def test_totp_login_with_real_browser(variant, monkeypatch, tmp_path):
    from tests.fixtures import totp_login_app as fixture
    if variant == "nameless":
        login = fixture.LOGIN_HTML.replace('name="f_2z"', '').replace('name="f_9x"', '')
        login += '''<script>document.querySelector('form').addEventListener('submit', async e => {
          e.preventDefault(); const fields = document.querySelectorAll('input');
          const data = new URLSearchParams({f_2z:fields[0].value, f_9x:fields[1].value});
          const response = await fetch('/login', {method:'POST', body:data});
          location.href = response.url;
        });</script>'''
        otp = fixture.TOTP_HTML.replace('name="x1"', '')
        otp += '''<script>document.querySelector('form').addEventListener('submit', async e => {
          e.preventDefault(); const data = new URLSearchParams({x1:document.querySelector('input').value});
          const response = await fetch('/verify', {method:'POST', body:data}); location.href = response.url;
        });</script>'''
        monkeypatch.setattr(fixture, "LOGIN_HTML", login)
        monkeypatch.setattr(fixture, "TOTP_HTML", otp)
    if variant == "override":
        monkeypatch.setattr(fixture, "TOTP_HTML", fixture.TOTP_HTML.replace(
            '<input name="x1"', '<input name="noise"><input id="custom" type="password" name="x1"'))
    with serving(create_app()) as url:
        async def exercise():
            cfg = MFAConfig(type="totp", totp_secret=TOTP_SECRET,
                            selector="#custom" if variant == "override" else "")
            if variant == "qr":
                from tests.test_totp_qr import _write_qr
                qr = tmp_path / "認証登録.png"
                _write_qr(qr)
                cfg.totp_secret = ""
                cfg.totp_qr = str(qr)
            browser = BrowserManager(headless=True, auth_user=USERNAME, auth_pass=PASSWORD,
                                     mfa_solver=MFASolver(cfg), sleep_factor=0)
            try:
                await browser.init()
                assert await browser.auto_login(url + "/login", success_indicator="/dashboard")
                assert browser.page.url == url + "/dashboard"
                assert browser.last_login_success
                assert "Signed in" in await browser.get_page_source()
            finally:
                await browser.close()
        asyncio.run(exercise())


def test_mfa_selection_and_fail_closed_with_real_dom():
    async def exercise():
        browser = BrowserManager(headless=True, mfa_solver=MFASolver(MFAConfig(type="totp", totp_secret=TOTP_SECRET)))
        try:
            await browser.init()
            await browser.page.set_content('<p>Verification code</p><input><input>')
            assert await browser._handle_mfa_challenge() == "failed"
            assert await browser.page.locator('input').evaluate_all('els => els.every(e => !e.value)')
            session = ManualCrawlSession()
            session._page = browser.page
            session.running = session.streaming = True
            box = await browser.page.locator('input').nth(1).bounding_box()
            selected = await session.select_mfa_field((box['x'] + 5) / session.view_width,
                                                      (box['y'] + 5) / session.view_height)
            assert await browser.page.locator(selected['selector']).count() == 1
            assert await browser.page.locator(selected['selector']).evaluate(
                "el => el === document.querySelectorAll('input')[1]")
            # override が不正でも、一般的な OTP 欄へ迂回して投入しない。
            browser.mfa_solver.config.selector = "#missing"
            await browser.page.set_content('<p>Verification code</p><input name="otp">')
            assert await browser._handle_mfa_challenge() == "failed"
            assert await browser.page.locator('input').input_value() == ''
            await browser.page.set_content('<input name="otp" hidden><input name="otp">')
            assert await browser._editable_auth_selector('input[name="otp"]') == ''
        finally:
            await browser.close()
    asyncio.run(exercise())
