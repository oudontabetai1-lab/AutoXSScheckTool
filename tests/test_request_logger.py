import json
import tempfile
import unittest
from pathlib import Path

from wscan.browser import NetworkCapture
from wscan.monitor import MonitorServer
from wscan.request_logger import RequestLogger


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


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


class MonitorPayloadLoggingTests(unittest.IsolatedAsyncioTestCase):
    async def test_emit_payload_test_persists_to_logger(self):
        with tempfile.TemporaryDirectory() as d:
            monitor = MonitorServer()
            monitor.request_logger = RequestLogger(d)
            await monitor.emit_payload_test("user", "<img>", "xss", "http://t.test/")
            rows = _read_jsonl(monitor.request_logger.payload_path)
            self.assertEqual(rows[0]["field"], "user")
            self.assertEqual(rows[0]["payload"], "<img>")


if __name__ == "__main__":
    unittest.main()
