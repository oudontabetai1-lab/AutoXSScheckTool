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

    def test_gemini_safety_block_is_blocked_not_transient(self):
        # 安全ブロック時は HTTP 200 だが本文が無い。再試行せず blocked(収束)を返す。
        for payload in (
            {"promptFeedback": {"blockReason": "SAFETY"}},
            {"candidates": [{"finishReason": "SAFETY", "content": {"parts": []}}]},
            {"candidates": []},
        ):
            client, context = _mock_async_client([_Response(200, payload)])
            pg = _payload_generator("gemini")
            with patch.dict(os.environ, {"GEMINI_API_KEY": "k"}, clear=False), \
                 patch("wscan.llm_client.httpx.AsyncClient", return_value=context):
                text, status = asyncio.run(
                    complete_text(pg, "prompt", return_status=True)
                )
            self.assertIsNone(text)
            self.assertEqual(status, "blocked")
            # 1回で確定し、再試行しない。
            self.assertEqual(client.post.await_count, 1)

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

    def test_return_status_classifies_openai_results(self):
        cases = [
            (
                "permanent",
                [_Response(401)],
                (None, "permanent"),
                1,
            ),
            (
                "transient",
                [_Response(500), _Response(500), _Response(500)],
                (None, "transient"),
                3,
            ),
            (
                "empty",
                [_Response(200, {"choices": [{"message": {"content": "  \n"}}]})],
                (None, "empty"),
                1,
            ),
            (
                "ok",
                [_Response(200, {"choices": [{"message": {"content": "text"}}]})],
                ("text", "ok"),
                1,
            ),
        ]
        for name, responses, expected, post_count in cases:
            with self.subTest(name=name):
                client, context = _mock_async_client(responses)
                with patch("wscan.llm_client.httpx.AsyncClient", return_value=context), \
                     patch("wscan.llm_client.asyncio.sleep", new_callable=AsyncMock):
                    result = asyncio.run(complete_text(
                        _payload_generator("openai"),
                        "prompt",
                        return_status=True,
                    ))

                self.assertEqual(result, expected)
                self.assertEqual(client.post.await_count, post_count)

    def test_return_status_reports_unavailable_without_http(self):
        with patch("wscan.llm_client.httpx.AsyncClient") as factory:
            result = asyncio.run(complete_text(
                _payload_generator("none"), "prompt", return_status=True
            ))

        self.assertEqual(result, (None, "unavailable"))
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


class LLMObservabilityTests(unittest.TestCase):
    """complete_text が LLM 呼び出しを本文なしで記録する（0065）。"""

    def _run_openai_ok(self, **pg_over):
        pg = _payload_generator("openai", **pg_over)
        resp = _Response(200, {"choices": [{"message": {"content": "HELLO"}}]})
        _client, context = _mock_async_client([resp])
        with patch("wscan.llm_client.httpx.AsyncClient", return_value=context):
            return asyncio.run(complete_text(pg, "PROMPTBODY"))

    def test_logs_call_metadata_without_body(self):
        logger = MagicMock()
        result = self._run_openai_ok(request_logger=logger, current_role=lambda: "payload")
        self.assertEqual(result, "HELLO")
        logger.log_llm_call.assert_called_once()
        kw = logger.log_llm_call.call_args.kwargs
        self.assertEqual(kw["provider"], "openai")
        self.assertEqual(kw["role"], "payload")
        self.assertEqual(kw["status"], "ok")
        self.assertEqual(kw["model"], "gpt-test")
        self.assertEqual(kw["prompt_chars"], len("PROMPTBODY"))
        self.assertEqual(kw["response_chars"], len("HELLO"))
        self.assertGreaterEqual(kw["elapsed_seconds"], 0.0)
        # 本文（prompt/response）は kwargs に一切含めない。
        blob = repr(kw)
        self.assertNotIn("PROMPTBODY", blob)
        self.assertNotIn("HELLO", blob)

    def test_records_transient_status_on_retryable_failure(self):
        logger = MagicMock()
        pg = _payload_generator("openai", request_logger=logger,
                                current_role=lambda: "payload", llm_max_retries=0)
        resp = _Response(503, {})
        _client, context = _mock_async_client([resp])
        with patch("wscan.llm_client.httpx.AsyncClient", return_value=context):
            asyncio.run(complete_text(pg, "p"))
        logger.log_llm_call.assert_called_once()
        self.assertEqual(logger.log_llm_call.call_args.kwargs["status"], "transient")

    def test_no_request_logger_does_not_crash(self):
        # request_logger 未配線（既存の SimpleNamespace）でも従来どおり動く（回帰）。
        self.assertEqual(self._run_openai_ok(), "HELLO")


class RequestLoggerLLMTests(unittest.TestCase):
    def test_log_llm_call_writes_jsonl_without_body(self):
        import json
        import tempfile
        from wscan.request_logger import RequestLogger
        with tempfile.TemporaryDirectory() as d:
            rl = RequestLogger(d)
            rl.log_llm_call(provider="claude", role="adaptive", model="m",
                            timeout_seconds=30.0, elapsed_seconds=1.5, status="ok",
                            retries=0, prompt_chars=100, response_chars=20, caller="complete_text")
            self.assertEqual(rl.llm_call_count, 1)
            rec = json.loads(rl.llm_path.read_text(encoding="utf-8").strip())
        self.assertEqual(rec["provider"], "claude")
        self.assertEqual(rec["status"], "ok")
        self.assertEqual(rec["prompt_chars"], 100)
        self.assertNotIn("prompt", rec)      # 本文キーは持たない
        self.assertNotIn("response", rec)

    def test_log_llm_call_disabled_is_noop(self):
        import tempfile
        from wscan.request_logger import RequestLogger
        with tempfile.TemporaryDirectory() as d:
            rl = RequestLogger(d, enabled=False)
            rl.log_llm_call(provider="ollama", status="ok")
            self.assertFalse(rl.llm_path.exists())
            self.assertEqual(rl.llm_call_count, 0)


class RecordLLMCallHelperTests(unittest.TestCase):
    def test_record_llm_call_forwards_to_logger(self):
        from wscan.llm_client import record_llm_call
        logger = MagicMock()
        pg = types.SimpleNamespace(request_logger=logger)
        record_llm_call(pg, provider="ollama", role="planner", model="m",
                        timeout_seconds=None, elapsed_seconds=2.0, status="ok",
                        prompt_chars=10, response_chars=5, caller="attack_planner._llm_plan")
        logger.log_llm_call.assert_called_once()
        self.assertEqual(logger.log_llm_call.call_args.kwargs["role"], "planner")

    def test_record_llm_call_without_logger_is_noop(self):
        from wscan.llm_client import record_llm_call
        pg = types.SimpleNamespace()  # request_logger 属性なし
        record_llm_call(pg, provider="ollama", role="planner", model="m",
                        timeout_seconds=None, elapsed_seconds=1.0, status="empty")  # 例外を出さない
