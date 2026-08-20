"""試行台帳（D5）と G1/G2/G3 配線のテスト。

- 純粋関数（attempt_from_pair / format_history_for_prompt / AttemptLedger）は
  ブラウザ非依存で高速検証。
- _apply_ip 経由の記録（G2）と get_payloads→generate への履歴受け渡し（G1）は
  MockTransport / スタックで配線を確認。
"""
import json
import unittest

import httpx

from wscan.attempt_ledger import (
    Attempt,
    AttemptLedger,
    attempt_from_pair,
    format_history_for_prompt,
)
from wscan.injection_point import InjectionPoint
from wscan.scanners.base import BaseScanner


# ---------------------------------------------------------------------------
# 純粋関数
# ---------------------------------------------------------------------------
class AttemptFromPairTests(unittest.TestCase):
    def _pair(self, status, body, req_ts=1.0, resp_ts=1.5):
        return {
            "request": {"timestamp": req_ts},
            "response": {"status": status, "body": body, "timestamp": resp_ts},
        }

    def test_reflected_and_metadata_captured(self):
        pair = self._pair(200, "hello <script>MARK</script> world")
        a = attempt_from_pair("<script>MARK</script>", pair["response"]["body"], pair)
        self.assertEqual(a.status, 200)
        self.assertTrue(a.reflected)
        self.assertFalse(a.error)
        self.assertAlmostEqual(a.elapsed, 0.5, places=6)
        self.assertEqual(a.body_len, len(pair["response"]["body"]))

    def test_not_reflected(self):
        pair = self._pair(403, "blocked by waf")
        a = attempt_from_pair("<script>MARK</script>", "blocked by waf", pair)
        self.assertEqual(a.status, 403)
        self.assertFalse(a.reflected)
        self.assertFalse(a.error)

    def test_transport_failure_is_error_not_silent(self):
        # 空 pair = transport 失敗。「エラーした攻撃」を「無反応」と混同しない。
        a = attempt_from_pair("payload", "", {})
        self.assertTrue(a.error)
        self.assertIsNone(a.status)
        self.assertIsNone(a.body_len)
        self.assertIsNone(a.elapsed)

    def test_none_payload_safe(self):
        a = attempt_from_pair(None, "", {})
        self.assertEqual(a.payload, "")
        self.assertTrue(a.error)


class LedgerTests(unittest.TestCase):
    def test_record_and_history_by_key_and_check(self):
        led = AttemptLedger()
        key = ("http://t", "q", "0", "u", "")
        led.record(key, "xss", Attempt("a", status=200))
        led.record(key, "xss", Attempt("b", status=403))
        led.record(key, "sqli", Attempt("c", status=500))
        self.assertEqual([a.payload for a in led.history(key, "xss")], ["a", "b"])
        self.assertEqual([a.payload for a in led.history(key, "sqli")], ["c"])
        self.assertEqual(led.history(("other",), "xss"), [])

    def test_history_is_copy(self):
        led = AttemptLedger()
        key = ("k",)
        led.record(key, "xss", Attempt("a"))
        h = led.history(key, "xss")
        h.append(Attempt("mutated"))
        self.assertEqual(len(led.history(key, "xss")), 1)

    def test_cap_drops_oldest(self):
        led = AttemptLedger(max_per_key=3)
        key = ("k",)
        for i in range(5):
            led.record(key, "xss", Attempt(str(i)))
        self.assertEqual([a.payload for a in led.history(key, "xss")], ["2", "3", "4"])


class FormatHistoryTests(unittest.TestCase):
    def test_empty_returns_empty(self):
        self.assertEqual(format_history_for_prompt([]), "")

    def test_block_contains_payloads_and_results(self):
        attempts = [
            Attempt("<script>", status=403, body_len=10, reflected=False, elapsed=0.2),
            Attempt("<svg/onload>", status=200, body_len=99, reflected=True, elapsed=1.3),
            Attempt("boom", error=True),
        ]
        block = format_history_for_prompt(attempts)
        self.assertIn("PREVIOUSLY TRIED", block)
        self.assertIn("<svg/onload>", block)
        self.assertIn("reflected", block)
        self.assertIn("status=403", block)
        self.assertIn("transport-error", block)

    def test_caps_to_max_items(self):
        attempts = [Attempt(f"p{i}", status=200) for i in range(30)]
        block = format_history_for_prompt(attempts, max_items=5)
        self.assertIn("p29", block)
        self.assertNotIn("p10", block)


# ---------------------------------------------------------------------------
# G2: _apply_ip 経由で台帳へ記録される
# ---------------------------------------------------------------------------
class _Engine:
    def __init__(self, transport):
        self.browser = None
        self.monitor = None
        self.payload_gen = None
        self.request_logger = None
        self.timeout = 5
        self.injection_templates = {}
        self._transport = transport
        self.attempt_ledger = AttemptLedger()

    def auth_headers(self, extra=None, *, include_cookie=True):
        return {**(extra or {})}

    def httpx_client_kwargs(self, **kwargs):
        return {**kwargs, "transport": self._transport}


class _JsonScanner(BaseScanner):
    CHECK_TYPE = "sqli"
    SUPPORTS_JSON_BODY = True

    async def scan_field(self, url, form_index, field, is_url_param=False):
        return []


class ApplyIpRecordsTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            val = body.get("q", "")
            # 反射する: payload を本文へ echo。
            return httpx.Response(200, json={"echo": val})

        self.engine = _Engine(httpx.MockTransport(handler))
        self.engine.injection_templates["t"] = {
            "method": "post",
            "url": "http://fixture.test/echo",
            "json_body": {"q": "seed"},
            "content_type": "application/json",
        }
        self.scanner = _JsonScanner(self.engine)

    async def test_apply_ip_records_attempt(self):
        ip = InjectionPoint.for_json_body(
            "POST", "http://fixture.test/echo", "/q", template_id="t"
        )
        source, pair = await self.scanner._apply_ip(ip, "MARKER123")
        hist = self.engine.attempt_ledger.history(ip.stable_key_parts(), "sqli")
        self.assertEqual(len(hist), 1)
        self.assertEqual(hist[0].payload, "MARKER123")
        self.assertEqual(hist[0].status, 200)
        self.assertTrue(hist[0].reflected)
        self.assertFalse(hist[0].error)

    async def test_unsupported_json_records_nothing(self):
        class _NoJson(_JsonScanner):
            SUPPORTS_JSON_BODY = False

        scanner = _NoJson(self.engine)
        ip = InjectionPoint.for_json_body(
            "POST", "http://fixture.test/echo", "/q", template_id="t"
        )
        source, pair = await scanner._apply_ip(ip, "X")
        self.assertEqual((source, pair), ("", {}))
        self.assertEqual(
            scanner.engine.attempt_ledger.history(ip.stable_key_parts(), "sqli"), []
        )


# ---------------------------------------------------------------------------
# G1: get_payloads が台帳履歴を generate へ渡す
# ---------------------------------------------------------------------------
class _CapturingPayloadGen:
    def __init__(self):
        self.captured_history = "unset"

    async def generate(self, *, check_type, field_name, url, custom_payloads=None,
                       attempt_history=None):
        self.captured_history = attempt_history
        return ["default1"]


class _GenEngine:
    def __init__(self):
        self.browser = None
        self.monitor = None
        self.payload_gen = None
        self.custom_payloads = {}
        self.payload_learner = None
        self.enable_payload_learning = False
        self.max_payloads = 0
        self.target_url = "http://fixture.test"
        self.attempt_ledger = AttemptLedger()


class _PlainScanner(BaseScanner):
    CHECK_TYPE = "xss"

    async def scan_field(self, url, form_index, field, is_url_param=False):
        return []


class GetPayloadsHistoryTests(unittest.IsolatedAsyncioTestCase):
    async def test_history_passed_to_generate(self):
        engine = _GenEngine()
        engine.payload_gen = _CapturingPayloadGen()
        scanner = _PlainScanner(engine)
        ip = InjectionPoint.for_url_param("http://fixture.test/p", "q")
        engine.attempt_ledger.record(
            ip.stable_key_parts(), "xss", Attempt("<script>", status=403)
        )
        payloads = await scanner.get_payloads("q", ip.url, ip=ip)
        self.assertEqual(payloads, ["default1"])
        self.assertIsNotNone(engine.payload_gen.captured_history)
        self.assertEqual(engine.payload_gen.captured_history[0].payload, "<script>")

    async def test_no_ip_means_no_history(self):
        engine = _GenEngine()
        engine.payload_gen = _CapturingPayloadGen()
        scanner = _PlainScanner(engine)
        await scanner.get_payloads("q", "http://fixture.test/p")
        self.assertIsNone(engine.payload_gen.captured_history)


if __name__ == "__main__":
    unittest.main()
