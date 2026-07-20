"""生テキスト LLM クライアントの振り分け・リトライ検証。"""
import asyncio
import os
import types
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from wscan.llm_client import backoff_seconds, complete_text, is_retryable
from wscan.remediation import generate_fix


class _Response:
    def __init__(self, status_code, data=None, *, headers=None, json_error=None):
        self.status_code = status_code
        self._data = data or {}
        self.headers = headers or {}
        self._json_error = json_error

    def json(self):
        if self._json_error:
            raise self._json_error
        return self._data


def _payload_generator(provider, **overrides):
    values = {
        "provider": provider,
        "openai_api_key": "openai-key",
        "openai_base_url": "https://openai.example/v1",
        "openai_model": "gpt-test",
        "gemini_model": "gemini-test",
        "ollama_model": "llama-test",
        "ollama_url": "http://ollama.test:11434",
        "claude_model": "claude-test",
        "llm_timeout_seconds": 12,
        "llm_max_retries": 2,
        "_get_anthropic_client": lambda: None,
    }
    values.update(overrides)
    return types.SimpleNamespace(**values)


def _mock_async_client(responses):
    client = MagicMock()
    client.post = AsyncMock(side_effect=responses)
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=client)
    context.__aexit__ = AsyncMock(return_value=None)
    return client, context


class RetryPolicyTests(unittest.TestCase):
    def test_retryable_status_and_httpx_exceptions(self):
        for status in (408, 429, 500, 502, 503, 504, 529):
            self.assertTrue(is_retryable(status), status)
        for status in (200, 400, 401, 403, 404):
            self.assertFalse(is_retryable(status), status)

        request = httpx.Request("POST", "https://example.test")
        self.assertTrue(is_retryable(httpx.ReadTimeout("timeout", request=request)))
        self.assertTrue(is_retryable(httpx.ConnectError("connect", request=request)))
        self.assertTrue(is_retryable(httpx.ReadError("read", request=request)))
        self.assertTrue(is_retryable(httpx.WriteError("write", request=request)))
        self.assertTrue(is_retryable(httpx.CloseError("close", request=request)))
        self.assertTrue(is_retryable(httpx.RemoteProtocolError("protocol", request=request)))
        self.assertFalse(is_retryable(ValueError("permanent")))

    def test_backoff_is_exponential_and_capped(self):
        self.assertEqual(backoff_seconds(0), 0.5)
        self.assertEqual(backoff_seconds(1), 1.0)
        self.assertEqual(backoff_seconds(2), 2.0)
        self.assertEqual(backoff_seconds(8), 8.0)
        self.assertEqual(backoff_seconds(-1), 0.5)


class CompleteTextTests(unittest.TestCase):
    def test_openai_success(self):
        client, context = _mock_async_client([
            _Response(200, {"choices": [{"message": {"content": "openai text"}}]}),
        ])
        pg = _payload_generator("openai")

        with patch("wscan.llm_client.httpx.AsyncClient", return_value=context) as factory:
            result = asyncio.run(complete_text(pg, "prompt", max_tokens=321))

        self.assertEqual(result, "openai text")
        factory.assert_called_once_with(timeout=12.0)
        url, = client.post.await_args.args
        self.assertEqual(url, "https://openai.example/v1/chat/completions")
        self.assertEqual(client.post.await_args.kwargs["json"]["max_tokens"], 321)

    def test_gemini_success(self):
        client, context = _mock_async_client([
            _Response(200, {
                "candidates": [{"content": {"parts": [{"text": "gemini text"}]}}]
            }),
        ])
        pg = _payload_generator("gemini")

        with patch.dict(os.environ, {"GEMINI_API_KEY": "gemini-key"}, clear=False), \
             patch("wscan.llm_client.httpx.AsyncClient", return_value=context):
            result = asyncio.run(complete_text(pg, "prompt", temperature=0.1))

        self.assertEqual(result, "gemini text")
        url, = client.post.await_args.args
        self.assertIn("gemini-test:generateContent?key=gemini-key", url)
        generation = client.post.await_args.kwargs["json"]["generationConfig"]
        self.assertEqual(generation, {"maxOutputTokens": 400, "temperature": 0.1})

    def test_ollama_success(self):
        client, context = _mock_async_client([
            _Response(200, {"response": "ollama text"}),
        ])
        pg = _payload_generator("ollama")

        with patch("wscan.llm_client.httpx.AsyncClient", return_value=context):
            result = asyncio.run(complete_text(pg, "prompt"))

        self.assertEqual(result, "ollama text")
        url, = client.post.await_args.args
        self.assertEqual(url, "http://ollama.test:11434/api/generate")

    def test_429_retries_then_succeeds(self):
        client, context = _mock_async_client([
            _Response(429),
            _Response(200, {"choices": [{"message": {"content": "recovered"}}]}),
        ])
        pg = _payload_generator("openai")

        with patch("wscan.llm_client.httpx.AsyncClient", return_value=context), \
             patch("wscan.llm_client.asyncio.sleep", new_callable=AsyncMock) as sleep:
            result = asyncio.run(complete_text(pg, "prompt"))

        self.assertEqual(result, "recovered")
        self.assertEqual(client.post.await_count, 2)
        sleep.assert_awaited_once_with(0.5)

    def test_408_and_529_retry_then_succeed(self):
        for status in (408, 529):
            with self.subTest(status=status):
                client, context = _mock_async_client([
                    _Response(status),
                    _Response(200, {"choices": [{"message": {"content": "recovered"}}]}),
                ])
                pg = _payload_generator("openai")

                with patch("wscan.llm_client.httpx.AsyncClient", return_value=context), \
                     patch("wscan.llm_client.asyncio.sleep", new_callable=AsyncMock) as sleep:
                    result = asyncio.run(complete_text(pg, "prompt"))

                self.assertEqual(result, "recovered")
                self.assertEqual(client.post.await_count, 2)
                sleep.assert_awaited_once_with(0.5)

    def test_close_error_retries_then_succeeds(self):
        request = httpx.Request("POST", "https://example.test")
        client, context = _mock_async_client([
            httpx.CloseError("temporary close failure", request=request),
            _Response(200, {"choices": [{"message": {"content": "recovered"}}]}),
        ])
        pg = _payload_generator("openai")

        with patch("wscan.llm_client.httpx.AsyncClient", return_value=context), \
             patch("wscan.llm_client.asyncio.sleep", new_callable=AsyncMock) as sleep:
            result = asyncio.run(complete_text(pg, "prompt"))

        self.assertEqual(result, "recovered")
        self.assertEqual(client.post.await_count, 2)
        sleep.assert_awaited_once_with(0.5)

    def test_broken_200_json_and_missing_key_retry_then_succeed(self):
        broken_responses = [
            _Response(200, json_error=ValueError("broken json")),
            _Response(200, {}),
        ]
        for broken in broken_responses:
            with self.subTest(broken=broken._json_error or broken._data):
                client, context = _mock_async_client([
                    broken,
                    _Response(200, {"choices": [{"message": {"content": "recovered"}}]}),
                ])
                pg = _payload_generator("openai")

                with patch("wscan.llm_client.httpx.AsyncClient", return_value=context), \
                     patch("wscan.llm_client.asyncio.sleep", new_callable=AsyncMock) as sleep:
                    result = asyncio.run(complete_text(pg, "prompt"))

                self.assertEqual(result, "recovered")
                self.assertEqual(client.post.await_count, 2)
                sleep.assert_awaited_once_with(0.5)

    def test_retry_after_seconds_is_preferred_and_capped(self):
        client, context = _mock_async_client([
            _Response(429, headers={"Retry-After": "30"}),
            _Response(200, {"choices": [{"message": {"content": "recovered"}}]}),
        ])
        pg = _payload_generator("openai")

        with patch("wscan.llm_client.httpx.AsyncClient", return_value=context), \
             patch("wscan.llm_client.asyncio.sleep", new_callable=AsyncMock) as sleep:
            result = asyncio.run(complete_text(pg, "prompt"))

        self.assertEqual(result, "recovered")
        sleep.assert_awaited_once_with(8.0)

    def test_permanent_statuses_return_none_without_retry(self):
        for status in (400, 401, 403):
            with self.subTest(status=status):
                client, context = _mock_async_client([_Response(status)])
                pg = _payload_generator("openai")

                with patch("wscan.llm_client.httpx.AsyncClient", return_value=context), \
                     patch("wscan.llm_client.asyncio.sleep", new_callable=AsyncMock) as sleep:
                    result = asyncio.run(complete_text(pg, "prompt"))

                self.assertIsNone(result)
                self.assertEqual(client.post.await_count, 1)
                sleep.assert_not_awaited()

    def test_claude_sdk_success(self):
        messages = MagicMock()
        messages.create.return_value = types.SimpleNamespace(
            content=[types.SimpleNamespace(text="claude text")]
        )
        anthropic_client = types.SimpleNamespace(messages=messages)
        pg = _payload_generator(
            "claude", _get_anthropic_client=lambda: anthropic_client
        )

        result = asyncio.run(complete_text(pg, "prompt", timeout=9, retries=0))

        self.assertEqual(result, "claude text")
        messages.create.assert_called_once_with(
            model="claude-test",
            max_tokens=400,
            temperature=0.3,
            timeout=9.0,
            messages=[{"role": "user", "content": "prompt"}],
        )

    def test_none_and_missing_keys_do_not_call_http(self):
        with patch("wscan.llm_client.httpx.AsyncClient") as factory:
            self.assertIsNone(asyncio.run(complete_text(_payload_generator("none"), "p")))
            self.assertIsNone(asyncio.run(complete_text(
                _payload_generator("openai", openai_api_key=None), "p"
            )))
        factory.assert_not_called()


class GeminiRemediationRegressionTests(unittest.TestCase):
    def test_generate_fix_uses_gemini_response(self):
        _client, context = _mock_async_client([
            _Response(200, {
                "candidates": [{"content": {"parts": [{
                    "text": "Gemini が生成した具体的な修正案です。入力値を適切にエスケープしてください。"
                }]}}]
            }),
        ])
        finding = types.SimpleNamespace(
            check_type="xss",
            url="https://target.test/",
            field_name="q",
            payload="<script>alert(1)</script>",
            evidence="reflected",
        )
        pg = _payload_generator("gemini")

        with patch.dict(os.environ, {"GEMINI_API_KEY": "gemini-key"}, clear=False), \
             patch("wscan.llm_client.httpx.AsyncClient", return_value=context):
            text, is_ai = asyncio.run(generate_fix(finding, pg))

        self.assertTrue(is_ai)
        self.assertIn("Gemini が生成", text)


if __name__ == "__main__":
    unittest.main()
