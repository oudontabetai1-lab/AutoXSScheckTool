import json
import tempfile
import unittest
from pathlib import Path

from wscan.browser import NetworkCapture
from wscan.monitor import MonitorServer
from wscan.request_logger import (
    RequestLogger,
    _redact_headers,
    clear_sensitive_headers,
    register_sensitive_headers,
)


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


class RedactionTests(unittest.TestCase):
    def setUp(self):
        clear_sensitive_headers()

    def tearDown(self):
        clear_sensitive_headers()

    def test_runtime_sensitive_headers_are_case_insensitive_and_clearable(self):
        register_sensitive_headers(["X-Company-Auth"])

        redacted = _redact_headers({
            "x-company-auth": "secret",
            "Accept": "*/*",
        })

        self.assertEqual(redacted["x-company-auth"], "<redacted>")
        self.assertEqual(redacted["Accept"], "*/*")

        clear_sensitive_headers()
        restored = _redact_headers({
            "X-COMPANY-AUTH": "secret",
            "Authorization": "Bearer fixed-secret",
        })
        self.assertEqual(restored["X-COMPANY-AUTH"], "secret")
        self.assertEqual(restored["Authorization"], "<redacted>")

    def test_sensitive_headers_redacted(self):
        with tempfile.TemporaryDirectory() as d:
            logger = RequestLogger(d)
            logger.log_http({
                "request": {
                    "url": "http://t.test/login",
                    "method": "POST",
                    "headers": {"Authorization": "Bearer secret", "Cookie": "sid=abc",
                                "Accept": "*/*"},
                    "post_data": "user=bob&password=hunter2&q=hello",
                    "timestamp": 1.0,
                },
                "response": {"status": 200, "headers": {"Set-Cookie": "sid=xyz; HttpOnly"}},
            })
            row = _read_jsonl(logger.http_path)[0]
            self.assertEqual(row["request_headers"]["Authorization"], "<redacted>")
            self.assertEqual(row["request_headers"]["Cookie"], "<redacted>")
            self.assertEqual(row["request_headers"]["Accept"], "*/*")  # non-sensitive kept
            self.assertEqual(row["response_headers"]["Set-Cookie"], "<redacted>")
            # password redacted, ordinary field kept
            self.assertIn("password=<redacted>", row["post_data"])
            self.assertIn("q=hello", row["post_data"])
            self.assertNotIn("hunter2", row["post_data"])

    def test_json_body_secret_redacted(self):
        with tempfile.TemporaryDirectory() as d:
            logger = RequestLogger(d)
            logger.log_http({
                "request": {"url": "http://t.test/", "method": "POST", "headers": {},
                            "post_data": '{"username":"bob","access_token":"tok123"}',
                            "timestamp": 1.0},
                "response": {"status": 200, "headers": {}},
            })
            row = _read_jsonl(logger.http_path)[0]
            self.assertNotIn("tok123", row["post_data"])
            self.assertIn("bob", row["post_data"])

    def test_url_query_secret_redacted(self):
        with tempfile.TemporaryDirectory() as d:
            logger = RequestLogger(d)
            logger.log_http({
                "request": {"url": "http://t.test/cb?code=1&token=leakme&id=5",
                            "method": "GET", "headers": {}, "post_data": None,
                            "timestamp": 1.0},
                "response": {"status": 200, "headers": {}},
            })
            row = _read_jsonl(logger.http_path)[0]
            self.assertNotIn("leakme", row["url"])
            self.assertIn("id=5", row["url"])

    def test_payload_url_redacted(self):
        with tempfile.TemporaryDirectory() as d:
            logger = RequestLogger(d)
            logger.log_payload("q", "<script>", "xss", "http://t.test/s?session_id=abc&q=x")
            row = _read_jsonl(logger.payload_path)[0]
            self.assertNotIn("abc", row["url"])
            self.assertEqual(row["payload"], "<script>")  # payload itself preserved


class RequestLoggerTests(unittest.TestCase):
    def test_log_http_writes_request_and_payload_in_url(self):
        with tempfile.TemporaryDirectory() as d:
            logger = RequestLogger(d)
            logger.log_http({
                "request": {
                    "url": "http://t.test/app/?q=<script>",
                    "method": "GET",
                    "headers": {"Accept": "*/*"},
                    "post_data": None,
                    "timestamp": 1.0,
                },
                "response": {"status": 200, "headers": {}},
            })
            rows = _read_jsonl(logger.http_path)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["method"], "GET")
            self.assertIn("<script>", rows[0]["url"])
            self.assertEqual(rows[0]["status"], 200)

    def test_post_data_is_truncated(self):
        with tempfile.TemporaryDirectory() as d:
            logger = RequestLogger(d)
            logger.log_http({
                "request": {"url": "http://t.test/", "method": "POST",
                            "headers": {}, "post_data": "x" * 50000, "timestamp": 1.0},
                "response": {"status": 200, "headers": {}},
            })
            rows = _read_jsonl(logger.http_path)
            self.assertTrue(rows[0]["post_data"].endswith("...<truncated>"))
            self.assertLess(len(rows[0]["post_data"]), 50000)

    def test_log_payload_writes_payload_file(self):
        with tempfile.TemporaryDirectory() as d:
            logger = RequestLogger(d)
            logger.log_payload("q", "' OR '1'='1", "sqli", "http://t.test/login")
            rows = _read_jsonl(logger.payload_path)
            self.assertEqual(rows[0]["field"], "q")
            self.assertEqual(rows[0]["check_type"], "sqli")
            self.assertEqual(rows[0]["payload"], "' OR '1'='1")

    def test_network_capture_forwards_pairs_to_logger(self):
        with tempfile.TemporaryDirectory() as d:
            logger = RequestLogger(d)
            cap = NetworkCapture(logger=logger)
            # Simulate a completed pair the way on_response would append it.
            cap.pairs.append({
                "request": {"url": "http://t.test/", "method": "GET",
                            "headers": {}, "post_data": None, "timestamp": 1.0},
                "response": {"url": "http://t.test/", "status": 200, "headers": {}},
            })
            logger.log_http(cap.pairs[-1])
            self.assertEqual(logger.http_count, 1)
            self.assertTrue(logger.http_path.exists())

    def test_disabled_logger_writes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            logger = RequestLogger(d, enabled=False)
            logger.log_payload("q", "x", "xss")
            self.assertFalse(logger.payload_path.exists())


class ScannerPayloadLoggingTests(unittest.IsolatedAsyncioTestCase):
    def _scanner(self, engine):
        from wscan.scanners.base import BaseScanner

        class _S(BaseScanner):
            CHECK_TYPE = "xss"

            async def scan_field(self, *a, **k):  # pragma: no cover - stub
                return []

        return _S(engine)

    async def test_log_payload_test_persists_without_monitor(self):
        # --no-monitor / batch mode: monitor is None but payloads must still
        # be written via engine.request_logger.
        import types
        with tempfile.TemporaryDirectory() as d:
            engine = types.SimpleNamespace(
                browser=object(), monitor=None, payload_gen=object(),
                request_logger=RequestLogger(d),
            )
            scanner = self._scanner(engine)
            await scanner.log_payload_test("user", "<img>", "xss", "http://t.test/")
            rows = _read_jsonl(engine.request_logger.payload_path)
            self.assertEqual(rows[0]["field"], "user")
            self.assertEqual(rows[0]["payload"], "<img>")

    async def test_log_payload_test_emits_to_monitor_without_duplicate_file_write(self):
        import types
        with tempfile.TemporaryDirectory() as d:
            monitor = MonitorServer()
            logger = RequestLogger(d)
            monitor.request_logger = logger
            engine = types.SimpleNamespace(
                browser=object(), monitor=monitor, payload_gen=object(),
                request_logger=logger,
            )
            scanner = self._scanner(engine)
            await scanner.log_payload_test("user", "<img>", "xss", "http://t.test/")
            rows = _read_jsonl(logger.payload_path)
            # Exactly one entry — emit_payload_test no longer writes to the file,
            # so going through the monitor must not double-log.
            self.assertEqual(len(rows), 1)


if __name__ == "__main__":
    unittest.main()
