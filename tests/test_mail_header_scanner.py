"""メールヘッダインジェクション・スキャナの検知ロジックのテスト。

ブラウザ/ネットワークは ``AsyncMock`` でスタブし、判定ロジック（反射検知・
OOB 確証・フィールド名判定）だけを検証する。OOB シンクもスタブし、外部接続は
発生させない。
"""
import unittest
from unittest.mock import AsyncMock

from wscan.oob_email import ReceivedEmail
from wscan.scanners import mail_header as mail_header_mod
from wscan.scanners.mail_header import (
    MailHeaderInjectionScanner,
    _field_name_suggests_mail,
    oob_payloads,
    reflection_payloads,
    _REFLECTED_INJECTION_RE,
)


class _Browser:
    def __init__(self, response_body=""):
        self._body = response_body
        self.navigate = AsyncMock(return_value=True)
        self.test_url_param = AsyncMock(
            return_value=(response_body, {"request": {}, "response": {"body": response_body}})
        )
        self.fill_and_submit_form = AsyncMock(
            return_value=(response_body, {"request": {}, "response": {"body": response_body}})
        )

    async def screenshot_b64(self, label=""):
        return ""


class _Engine:
    """OOB 未設定のダミーエンジン。"""

    def __init__(self, browser):
        self.browser = browser
        self.monitor = None
        self.payload_gen = None
        self._finding_dedup = set()
        self.all_findings = []
        self.checks = ["mail_header"]
        self.sleep_factor = 0  # テストの待ち時間を排除
        self.oob_sink = None
        self.oob_config = None

    def new_oob_address(self):
        return None


class _OOBEngine(_Engine):
    """OOB が設定済みのダミーエンジン。``oob_sink.fetch_recent`` をスタブする。

    ``received`` の To に当たり変種のアドレスを持たせ、``_poll_oob`` が
    ``email_matches_token`` でその変種に帰属することを検証できるようにする。
    """

    def __init__(self, browser, received, winning_index=0):
        super().__init__(browser)
        self._counter = 0

        class _Sink:
            def fetch_recent(self, limit=50):
                # 1 ポーリングで直近メールを一括返却（received があれば 1 件）。
                return [received] if received is not None else []

        self.oob_sink = _Sink()
        self._winning_index = winning_index

    def new_oob_address(self):
        token = f"wscan-oob-tok{self._counter}"
        self._counter += 1
        return (token, f"{token}@collab.test")


def _run(coro):
    import asyncio

    return asyncio.run(coro)


class PayloadHelperTests(unittest.TestCase):
    def test_reflection_payloads_include_standard_and_variants(self):
        payloads = reflection_payloads()
        self.assertIn(
            "test@example.com\r\nCc: attacker@evil.example.com", payloads
        )
        self.assertEqual(len(payloads), len(set(payloads)))
        self.assertGreater(len(payloads), len(set(payloads)) - 1)

    def test_oob_payloads_embed_address_as_cc(self):
        # 確証可能性のため Bcc ではなく Cc を注入する（配送後も残る可視ヘッダ）。
        payloads = oob_payloads("tok@collab.test")
        self.assertTrue(payloads)
        for payload, desc in payloads:
            self.assertIn("Cc: tok@collab.test", payload)
            self.assertNotIn("Bcc:", payload)
            self.assertTrue(desc)

    def test_oob_payloads_empty_for_blank_address(self):
        self.assertEqual(oob_payloads(""), [])

    def test_field_name_hint(self):
        self.assertTrue(_field_name_suggests_mail("email"))
        self.assertTrue(_field_name_suggests_mail("cc"))
        self.assertFalse(_field_name_suggests_mail("account"))


class ReflectionDetectionTests(unittest.TestCase):
    def test_raw_crlf_reflection_is_detected(self):
        body = "Sending...\nTo: test@example.com\nCc: attacker@evil.example.com\n"
        self.assertIsNotNone(_REFLECTED_INJECTION_RE.search(body))

    def test_escaped_reflection_is_not_detected(self):
        # CR/LF が除去された安全ツインの応答は反射として検知しない。
        body = "Sending...\nTo: test@example.comCc: attacker@evil.example.com\n"
        # 改行が無いので Cc: の前に \n/\r\n が来ず、未検知が正しい。
        self.assertIsNone(_REFLECTED_INJECTION_RE.search(body))

    def test_scanner_reports_reflection(self):
        body = "To: x\r\nCc: attacker@evil.example.com"
        scanner = MailHeaderInjectionScanner(_Engine(_Browser(body)))
        findings = _run(
            scanner.scan_field(
                "http://t.test/contact", 0, {"name": "email"}, is_url_param=False
            )
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence_type, "mail_header_reflected")
        self.assertEqual(findings[0].confidence, "likely")

    def test_safe_response_yields_no_finding(self):
        scanner = MailHeaderInjectionScanner(_Engine(_Browser("Thanks, your message was sent.")))
        findings = _run(
            scanner.scan_field(
                "http://t.test/contact-safe", 0, {"name": "email"}, is_url_param=False
            )
        )
        self.assertEqual(findings, [])

    def test_non_mail_field_skipped(self):
        scanner = MailHeaderInjectionScanner(_Engine(_Browser("To: x\r\nCc: attacker@e")))
        findings = _run(
            scanner.scan_field(
                "http://t.test/x", 0, {"name": "username"}, is_url_param=False
            )
        )
        self.assertEqual(findings, [])


class _MailErrorBrowser:
    """投入値に応じて応答を変えるブラウザ。ベースライン誤検知ガードの検証用。

    ``always_error=True`` なら良性値でもメールエラーを返す（恒常エラー）。
    ``distinct_error=True`` なら良性値は汎用エラー、注入値は別の注入特有エラーを返す。
    どちらでもなければ良性値は正常応答、CRLF 注入値のみメールエラーを返す。
    """

    def __init__(self, always_error=False, distinct_error=False):
        self.always_error = always_error
        self.distinct_error = distinct_error
        self.navigate = AsyncMock(return_value=True)

    async def screenshot_b64(self, label=""):
        return ""

    async def fill_and_submit_form(self, form_index, field_name, payload):
        err = "sendmail returned an error while sending mail"
        ok = "Thanks, your message was sent."
        is_baseline = payload == "baseline@example.com"
        if self.distinct_error:
            # 良性値は汎用 SMTP error、注入値は別の注入特有エラー。
            body = "SMTP error" if is_baseline else "invalid mail header detected"
        elif self.always_error:
            body = err
        else:
            body = err if not is_baseline else ok
        return body, {"request": {}, "response": {"body": body}}


class MailErrorBaselineGuardTests(unittest.TestCase):
    def test_injection_introduced_error_is_flagged(self):
        # ベースライン(良性値)は正常、注入値でのみメールエラー → 記録する。
        scanner = MailHeaderInjectionScanner(_Engine(_MailErrorBrowser(always_error=False)))
        findings = _run(
            scanner.scan_field(
                "http://t.test/contact", 0, {"name": "email"}, is_url_param=False
            )
        )
        errs = [f for f in findings if f.evidence_type == "mail_header_error"]
        self.assertEqual(len(errs), 1)

    def test_constant_mail_error_is_not_flagged(self):
        # 良性値でも同じメールエラーが出る（サーバ恒常エラー）→ 誤検知として記録しない。
        scanner = MailHeaderInjectionScanner(_Engine(_MailErrorBrowser(always_error=True)))
        findings = _run(
            scanner.scan_field(
                "http://t.test/contact", 0, {"name": "email"}, is_url_param=False
            )
        )
        errs = [f for f in findings if f.evidence_type == "mail_header_error"]
        self.assertEqual(errs, [])

    def test_injection_specific_error_flagged_despite_baseline_error(self):
        # ベースラインが汎用 SMTP error でも、注入特有の別エラーは取りこぼさない。
        scanner = MailHeaderInjectionScanner(
            _Engine(_MailErrorBrowser(distinct_error=True))
        )
        findings = _run(
            scanner.scan_field(
                "http://t.test/contact", 0, {"name": "email"}, is_url_param=False
            )
        )
        errs = [f for f in findings if f.evidence_type == "mail_header_error"]
        self.assertEqual(len(errs), 1)


class RawSubmissionTests(unittest.TestCase):
    """生 HTTP 送信を優先し、不能時のみブラウザ DOM 送信へフォールバックする。"""

    def test_raw_path_preferred_over_dom(self):
        body = "To: x\r\nCc: attacker@evil.example.com"
        browser = _Browser(body)
        scanner = MailHeaderInjectionScanner(_Engine(browser))
        scanner._apply_payload_raw = AsyncMock(
            return_value=(body, {"request": {}, "response": {"body": body}})
        )
        findings = _run(
            scanner.scan_field(
                "http://t.test/contact", 0, {"name": "email"}, is_url_param=False
            )
        )
        self.assertTrue(
            any(f.evidence_type == "mail_header_reflected" for f in findings)
        )
        # CRLF を落とす DOM 送信は使われないこと。
        browser.fill_and_submit_form.assert_not_called()

    def test_fallback_to_dom_when_raw_unavailable(self):
        body = "To: x\r\nCc: attacker@evil.example.com"
        browser = _Browser(body)
        scanner = MailHeaderInjectionScanner(_Engine(browser))
        scanner._apply_payload_raw = AsyncMock(side_effect=RuntimeError("no page"))
        findings = _run(
            scanner.scan_field(
                "http://t.test/contact", 0, {"name": "email"}, is_url_param=False
            )
        )
        self.assertTrue(
            any(f.evidence_type == "mail_header_reflected" for f in findings)
        )
        browser.fill_and_submit_form.assert_called()


class RawEncodingTests(unittest.TestCase):
    """raw httpx 送信のエンコーディング（urlencoded / multipart）を ASGI で検証。"""

    def _echo_app(self):
        from fastapi import FastAPI, Request

        app = FastAPI()

        @app.post("/contact")
        async def contact(request: Request):
            ct = request.headers.get("content-type", "")
            form = await request.form()
            return {"content_type": ct, "email": form.get("email", "")}

        return app

    def _engine_with_app(self, app):
        import httpx

        engine = _Engine(_Browser(""))

        def _kwargs(**ov):
            ov["transport"] = httpx.ASGITransport(app=app)
            return ov

        engine.httpx_client_kwargs = _kwargs
        return engine

    def _run_probe(self, enctype):
        import json

        scanner = MailHeaderInjectionScanner(self._engine_with_app(self._echo_app()))
        scanner._extract_form = AsyncMock(
            return_value={
                "action": "http://t.test/contact",
                "method": "POST",
                "enctype": enctype,
                "fields": {"email": ""},
            }
        )
        payload = "user@example.com\r\nCc: attacker@evil.example.com"
        body, _pair = _run(
            scanner._apply_payload_raw(
                "http://t.test/contact", 0, "email", payload, False
            )
        )
        return json.loads(body), payload

    def test_multipart_form_uses_multipart_and_preserves_crlf(self):
        data, payload = self._run_probe("multipart/form-data")
        self.assertIn("multipart/form-data", data["content_type"])
        # 値中の CR/LF が生のままサーバへ届く（注入が成立し得る）。
        self.assertEqual(data["email"], payload)

    def test_urlencoded_form_roundtrips_crlf(self):
        data, payload = self._run_probe("application/x-www-form-urlencoded")
        self.assertIn("urlencoded", data["content_type"])
        # urlencoded は %0D%0A としてエンコード→サーバ側でデコードされ復元する。
        self.assertEqual(data["email"], payload)


class _CookieBrowser:
    """``page.context.cookies()`` でセッション cookie を返すブラウザスタブ。"""

    def __init__(self, ctx_cookies):
        ctx = type("Ctx", (), {})()
        async def _cookies():
            return ctx_cookies
        ctx.cookies = _cookies
        page = type("Page", (), {})()
        page.context = ctx
        self.page = page

    async def screenshot_b64(self, label=""):
        return ""


class CollectCookiesTests(unittest.TestCase):
    def test_browser_session_cookies_merge_and_override(self):
        engine = _Engine(_CookieBrowser([
            {"name": "sid", "value": "browser"},
            {"name": "b", "value": "2"},
        ]))
        engine.cookies = "sid=explicit; a=1"
        scanner = MailHeaderInjectionScanner(engine)
        cookies = _run(scanner._collect_cookies())
        # engine.cookies の値はブラウザセッション cookie に上書きされる。
        self.assertEqual(cookies["sid"], "browser")
        self.assertEqual(cookies["a"], "1")
        self.assertEqual(cookies["b"], "2")

    def test_no_cookies_returns_empty(self):
        scanner = MailHeaderInjectionScanner(_Engine(_Browser("x")))
        self.assertEqual(_run(scanner._collect_cookies()), {})


class OOBConfirmationTests(unittest.TestCase):
    def setUp(self):
        # ポーリング待ちをゼロにしてテストを即時化する。
        self._orig_wait = mail_header_mod.OOB_WAIT_SECONDS
        self._orig_interval = mail_header_mod.OOB_POLL_INTERVAL
        mail_header_mod.OOB_WAIT_SECONDS = 0
        mail_header_mod.OOB_POLL_INTERVAL = 0

    def tearDown(self):
        mail_header_mod.OOB_WAIT_SECONDS = self._orig_wait
        mail_header_mod.OOB_POLL_INTERVAL = self._orig_interval

    def test_oob_received_attributes_finding_to_firing_variant(self):
        # 2 番目の変種(index=2)だけが着信する → その変種に正しく帰属すること。
        winning_index = 2
        winning_token = f"wscan-oob-tok{winning_index}"
        received = ReceivedEmail(
            uid="1",
            to_addrs=[f"{winning_token}@collab.test"],
            subject="Thanks",
        )
        scanner = MailHeaderInjectionScanner(
            _OOBEngine(
                _Browser("Thanks, your message was sent."),
                received,
                winning_index=winning_index,
            )
        )
        findings = _run(
            scanner.scan_field(
                "http://t.test/contact", 0, {"name": "email"}, is_url_param=False
            )
        )
        oob = [f for f in findings if f.evidence_type == "mail_header_oob"]
        self.assertEqual(len(oob), 1)
        self.assertEqual(oob[0].confidence, "confirmed")
        # last_payload ではなく実際に発火した変種のトークンに帰属している。
        self.assertEqual(oob[0].evidence_details["oob_token"], winning_token)
        self.assertIn("Cc: %s@collab.test" % winning_token, oob[0].payload)

    def test_oob_no_mail_yields_no_oob_finding(self):
        scanner = MailHeaderInjectionScanner(
            _OOBEngine(_Browser("Thanks, your message was sent."), None)
        )
        findings = _run(
            scanner.scan_field(
                "http://t.test/contact", 0, {"name": "email"}, is_url_param=False
            )
        )
        self.assertEqual(
            [f for f in findings if f.evidence_type == "mail_header_oob"], []
        )


if __name__ == "__main__":
    unittest.main()
