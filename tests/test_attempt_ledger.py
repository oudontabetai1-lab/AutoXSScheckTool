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
    unique_payloads,
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


class ResponseBodyPreferenceTests(unittest.TestCase):
    """Codex #91 指摘2: 反射/長さは DOM(source) でなく HTTP 応答本文を優先。"""

    def test_prefers_response_body_over_dom_source(self):
        # DOM(source) は payload を正規化して反射しているが、実 HTTP 本文には無い場合、
        # response body 側（反射なし）を採る＝DOM正規化由来の偽陽性を避ける。
        pair = {
            "request": {"timestamp": 1.0},
            "response": {"status": 200, "body": "escaped &lt;x&gt;", "timestamp": 1.2},
        }
        dom_source = "raw <x> reflected"
        a = attempt_from_pair("<x>", dom_source, pair)
        self.assertFalse(a.reflected)               # 応答本文には <x> 生では無い
        self.assertEqual(a.body_len, len("escaped &lt;x&gt;"))

    def test_falls_back_to_source_when_no_body(self):
        # 応答本文が無い（body キー欠落）ときは source を使う。
        pair = {
            "request": {"timestamp": 1.0},
            "response": {"status": 200, "timestamp": 1.2},
        }
        a = attempt_from_pair("<x>", "raw <x> here", pair)
        self.assertTrue(a.reflected)
        self.assertEqual(a.body_len, len("raw <x> here"))


class UniquePayloadsTests(unittest.TestCase):
    """Codex #91 指摘3: 台帳 payload を順序保持で重複除去（truncation前）。"""

    def test_order_preserving_dedup_and_excludes_already(self):
        attempts = [
            Attempt("a"), Attempt("b"), Attempt("a"),  # 重複 a
            Attempt("c"), Attempt("b"),                # 重複 b
        ]
        self.assertEqual(unique_payloads(attempts, {"c"}), ["a", "b"])

    def test_empty_payload_skipped(self):
        self.assertEqual(unique_payloads([Attempt(""), Attempt("x")], set()), ["x"])


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
                       attempt_history=None, learning_summary=None):
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


# ---------------------------------------------------------------------------
# Codex #91 r3: checkpoint 永続化（resume で adaptive 履歴を失わない）
# ---------------------------------------------------------------------------
class LedgerSerializationTests(unittest.TestCase):
    def test_roundtrip_preserves_entries(self):
        led = AttemptLedger()
        key = ("http://t", "q", "0", "u", "")
        led.record(key, "xss", Attempt("<script>", status=403, body_len=10,
                                        reflected=False, error=False, elapsed=0.2))
        led.record(key, "xss", Attempt("<svg>", status=200, reflected=True))
        led.record(("k2",), "sqli", Attempt("' OR 1=1", error=True))
        data = led.to_dict()
        # JSON 直列化可能であること
        json.dumps(data)
        back = AttemptLedger.from_dict(data)
        h = back.history(key, "xss")
        self.assertEqual([a.payload for a in h], ["<script>", "<svg>"])
        self.assertEqual(h[0].status, 403)
        self.assertTrue(h[1].reflected)
        self.assertTrue(back.history(("k2",), "sqli")[0].error)

    def test_from_dict_tolerates_garbage(self):
        self.assertEqual(AttemptLedger.from_dict({}).history(("k",), "x"), [])
        self.assertEqual(AttemptLedger.from_dict("nope").history(("k",), "x"), [])
        # 壊れたレコードは飛ばす
        led = AttemptLedger.from_dict({"records": [{"bad": 1}, {"key": ["k"], "check": "x", "attempts": [{"payload": "p"}]}]})
        self.assertEqual([a.payload for a in led.history(("k",), "x")], ["p"])


# ---------------------------------------------------------------------------
# Codex #91 r2: _apply_ip を通らない直送(form/URL)でも記録される
# ---------------------------------------------------------------------------
class DirectPathRecordingTests(unittest.IsolatedAsyncioTestCase):
    async def test_record_form_url_attempt_builds_key_and_records(self):
        engine = _GenEngine()
        engine.payload_gen = _CapturingPayloadGen()
        scanner = _PlainScanner(engine)  # CHECK_TYPE = "xss"
        pair = {
            "request": {"timestamp": 1.0},
            "response": {"status": 200, "body": "echo <script>", "timestamp": 1.1},
        }
        scanner._record_form_url_attempt(
            "http://t/p", 0, "q", True, "<script>", "dom-source", pair
        )
        from wscan.injection_point import InjectionPoint
        key = InjectionPoint.for_url_param("http://t/p", "q").stable_key_parts()
        hist = engine.attempt_ledger.history(key, "xss")
        self.assertEqual(len(hist), 1)
        self.assertEqual(hist[0].payload, "<script>")
        self.assertTrue(hist[0].reflected)   # 応答本文に <script> 反射
        self.assertEqual(hist[0].status, 200)


# ---------------------------------------------------------------------------
# 指摘1: adaptive generate が rich metadata 履歴(extra_observations)をプロンプトへ載せる
# ---------------------------------------------------------------------------
class AdaptiveExtraObservationsTests(unittest.IsolatedAsyncioTestCase):
    async def test_extra_observations_reaches_prompt(self):
        import wscan.adaptive_payload as ap
        from wscan.payload_gen import PayloadGenerator

        captured = {}

        async def fake_complete_text(pg, prompt, **kwargs):
            captured["prompt"] = prompt
            return ('["<svg/onload=1>"]', "ok")

        pg = PayloadGenerator(provider="ollama")
        # LLM 可用性チェックや実呼び出しを避けるため complete_text を差し替え。
        orig = ap.llm_client.complete_text
        ap.llm_client.complete_text = fake_complete_text
        try:
            engine = ap.AdaptivePayloadEngine(pg)
            note = "PREVIOUSLY TRIED payloads ...\n- `<script>` -> status=403, not-reflected"
            await engine.generate(
                check_type="xss",
                field_name="q",
                url="http://t/",
                payloads_tried=["<script>"],
                page_html="<html></html>",
                extra_observations=note,
                return_status=True,
            )
        finally:
            ap.llm_client.complete_text = orig
        self.assertIn("PREVIOUSLY TRIED", captured.get("prompt", ""))
        self.assertIn("status=403", captured["prompt"])


if __name__ == "__main__":
    unittest.main()
