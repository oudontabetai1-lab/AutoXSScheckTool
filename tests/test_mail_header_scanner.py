"""メールヘッダインジェクション・スキャナの検知ロジックのテスト。

ブラウザ/ネットワークは ``AsyncMock`` でスタブし、判定ロジック（反射検知・
OOB 確証・フィールド名判定）だけを検証する。OOB シンクもスタブし、外部接続は
発生させない。
"""
import unittest
from unittest.mock import AsyncMock

from wscan.oob_email import ReceivedEmail
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
    """OOB が設定済みのダミーエンジン。``oob_sink.wait_for`` をスタブする。"""

    def __init__(self, browser, received):
        super().__init__(browser)

        class _Sink:
            def wait_for(self, token, timeout, interval):
                return received

        self.oob_sink = _Sink()

    def new_oob_address(self):
        return ("wscan-oob-tok", "wscan-oob-tok@collab.test")


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

    def test_oob_payloads_embed_address(self):
        payloads = oob_payloads("tok@collab.test")
        self.assertTrue(payloads)
        for p in payloads:
            self.assertIn("Bcc: tok@collab.test", p)

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


class OOBConfirmationTests(unittest.TestCase):
    def test_oob_received_yields_confirmed_finding(self):
        received = ReceivedEmail(
            uid="1",
            to_addrs=["wscan-oob-tok@collab.test"],
            subject="Thanks",
        )
        scanner = MailHeaderInjectionScanner(
            _OOBEngine(_Browser("Thanks, your message was sent."), received)
        )
        findings = _run(
            scanner.scan_field(
                "http://t.test/contact", 0, {"name": "email"}, is_url_param=False
            )
        )
        oob = [f for f in findings if f.evidence_type == "mail_header_oob"]
        self.assertEqual(len(oob), 1)
        self.assertEqual(oob[0].confidence, "confirmed")
        self.assertEqual(oob[0].evidence_details["oob_token"], "wscan-oob-tok")

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
