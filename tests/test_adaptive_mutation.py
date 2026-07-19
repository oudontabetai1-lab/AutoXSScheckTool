"""AdaptivePayloadEngine.mutate_payload（LLM 版ペイロード変異）のゲーティング回帰テスト。

LLM プロバイダが ``none`` のとき、または LLM 不在のときは空 list を返し、
呼び出し側（BaseScanner.mutated_payloads）が LLM 非依存の変異へフォールバックできる
ことを保証する。実 API 呼び出しはここでは行わない（キー不要）。
"""
from contextlib import contextmanager
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from wscan.adaptive_payload import AdaptivePayloadEngine, _MUTATION_PROMPT, _parse_payload_lines


class _FakePG:
    """provider だけを持つ最小の PayloadGenerator スタブ。"""
    def __init__(self, provider="none"):
        self.provider = provider

    async def _check_llm_available(self):  # pragma: no cover - 呼ばれない想定
        return False


class _RetryPG:
    """adaptive の共通 LLM クライアント経路を通す最小スタブ。"""

    provider = "openai"
    openai_api_key = "test-key"
    openai_base_url = "https://openai.example/v1"
    openai_model = "test-model"
    llm_timeout_seconds = 3
    llm_max_retries = 1

    @contextmanager
    def use_role(self, role):
        yield


class MutatePayloadGatingTests(unittest.IsolatedAsyncioTestCase):
    async def test_provider_none_returns_empty(self):
        eng = AdaptivePayloadEngine(_FakePG(provider="none"))
        out = await eng.mutate_payload("sqli", ["1 AND 1=1"], field_name="rx", url="http://x")
        self.assertEqual(out, [])

    async def test_empty_seeds_returns_empty(self):
        eng = AdaptivePayloadEngine(_FakePG(provider="claude"))
        out = await eng.mutate_payload("sqli", [], field_name="rx", url="http://x")
        self.assertEqual(out, [])

    async def test_llm_unavailable_returns_empty(self):
        # provider はあるが _check_llm_available が False → 空。
        eng = AdaptivePayloadEngine(_FakePG(provider="claude"))
        out = await eng.mutate_payload("sqli", ["1 AND 1=1"])
        self.assertEqual(out, [])


class MutationPromptParseTests(unittest.TestCase):
    def test_prompt_includes_seeds_and_type(self):
        prompt = _MUTATION_PROMPT.format(
            check_type="sqli", field_name="rx", url="http://x",
            cheatsheet="(cheatsheet)", seeds="  1 AND 1=1",
        )
        self.assertIn("1 AND 1=1", prompt)
        self.assertIn("sqli", prompt)

    def test_parser_extracts_payloads_block(self):
        raw = "<analysis>x</analysis>\n<payloads>\n%2527\n1/**/AND/**/1=1\n</payloads>"
        out = _parse_payload_lines(raw, already_tried=["1 AND 1=1"])
        self.assertIn("%2527", out)
        self.assertIn("1/**/AND/**/1=1", out)


class AdaptiveGenerationRetryTests(unittest.IsolatedAsyncioTestCase):
    async def test_failure_none_and_successful_empty_response_are_distinct(self):
        engine = AdaptivePayloadEngine(_RetryPG())
        with patch(
            "wscan.adaptive_payload.llm_client.complete_text",
            new_callable=AsyncMock,
            side_effect=[None, ""],
        ) as complete:
            failed = await engine.generate(
                "xss", "q", "https://example.test", [], "<html></html>"
            )
            empty = await engine.generate(
                "xss", "q", "https://example.test", [], "<html></html>"
            )

        self.assertIsNone(failed)
        self.assertEqual(empty, [])
        self.assertEqual(complete.await_count, 2)
        self.assertEqual(complete.await_args.kwargs["max_tokens"], 1000)
        self.assertNotIn("timeout", complete.await_args.kwargs)
        self.assertNotIn("retries", complete.await_args.kwargs)

    async def test_complete_text_retries_read_error_then_returns_payloads(self):
        calls = 0

        async def handler(request):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise httpx.ReadError("temporary read failure", request=request)
            return httpx.Response(
                200,
                json={
                    "choices": [{
                        "message": {"content": "<payloads>\n%2527\n</payloads>"}
                    }]
                },
            )

        transport = httpx.MockTransport(handler)
        real_async_client = httpx.AsyncClient

        def client_factory(*, timeout):
            return real_async_client(timeout=timeout, transport=transport)

        engine = AdaptivePayloadEngine(_RetryPG())
        with patch("wscan.llm_client.httpx.AsyncClient", side_effect=client_factory), \
             patch("wscan.llm_client.asyncio.sleep", new_callable=AsyncMock):
            payloads = await engine.generate(
                check_type="sqli",
                field_name="q",
                url="https://example.test/search",
                payloads_tried=["' OR 1=1--"],
                page_html="<html><input name='q'></html>",
            )

        self.assertEqual(payloads, ["%2527"])
        self.assertEqual(calls, 2)


if __name__ == "__main__":
    unittest.main()
