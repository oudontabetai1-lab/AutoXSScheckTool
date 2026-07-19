"""LLM ペイロード生成のリトライとフォールバックを検証する。"""
import asyncio
import json
import os
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from wscan.payload_encoder import expand_payloads
from wscan.payload_gen import PayloadGenerator


class _Response:
    def __init__(self, status_code, data=None):
        self.status_code = status_code
        self._data = data or {}

    def json(self):
        return self._data


def _mock_async_client(responses):
    client = MagicMock()
    client.post = AsyncMock(side_effect=responses)
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=client)
    context.__aexit__ = AsyncMock(return_value=None)
    return client, context


class PayloadGenerationRetryTests(unittest.TestCase):
    def _generator(self):
        return PayloadGenerator(
            provider="openai",
            openai_model="gpt-test",
            default_payloads={"xss": ["default-payload"]},
            prompt_templates={"xss": "Generate for {field_name} at {url}"},
            llm_timeout_seconds=1.25,
            llm_max_retries=1,
        )

    def test_429_retries_and_uses_generated_payloads(self):
        generated = "<svg/onload=alert(1)>"
        client, context = _mock_async_client([
            _Response(429),
            _Response(200, {
                "choices": [{"message": {"content": json.dumps([generated])}}]
            }),
        ])

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}, clear=False):
            generator = self._generator()
        with patch("wscan.llm_client.httpx.AsyncClient", return_value=context) as factory, \
             patch("wscan.llm_client.asyncio.sleep", new_callable=AsyncMock) as sleep:
            payloads = asyncio.run(generator.generate(
                "xss", "query", "https://target.test/"
            ))

        self.assertIn(generated, payloads)
        self.assertEqual(client.post.await_count, 2)
        self.assertEqual(factory.call_count, 2)
        factory.assert_called_with(timeout=1.25)
        sleep.assert_awaited_once_with(0.5)

    def test_400_falls_back_to_default_without_retry(self):
        client, context = _mock_async_client([_Response(400)])

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}, clear=False):
            generator = self._generator()
        with patch("wscan.llm_client.httpx.AsyncClient", return_value=context), \
             patch("wscan.llm_client.asyncio.sleep", new_callable=AsyncMock) as sleep:
            payloads = asyncio.run(generator.generate(
                "xss", "query", "https://target.test/"
            ))

        expected = expand_payloads(
            ["default-payload"],
            "xss",
            max_variants_per_payload=1,
            max_total=40,
        )
        self.assertEqual(payloads, expected)
        self.assertEqual(client.post.await_count, 1)
        sleep.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
