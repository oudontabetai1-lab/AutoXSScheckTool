"""未配線 JSON transport のフィクスチャ往復テスト。"""
import json
import unittest

import httpx

from wscan.injection_point import InjectionPoint
from wscan.scanners.base import BaseScanner


class _Browser:
    async def screenshot_b64(self, label=""):
        return ""


class _Engine:
    def __init__(self, transport):
        self.browser = _Browser()
        self.monitor = None
        self.payload_gen = None
        self.request_logger = None
        self.timeout = 5
        self.injection_templates = {}
        self._transport = transport

    def auth_headers(self, extra=None, *, include_cookie=True):
        return {"Authorization": "Bearer current", **(extra or {})}

    def httpx_client_kwargs(self, **kwargs):
        return {**kwargs, "transport": self._transport}


class _Scanner(BaseScanner):
    CHECK_TYPE = "sqli"

    async def scan_field(self, url, form_index, field, is_url_param=False):
        return []


class JsonTransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.received = []

        def fixture_pair(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            self.received.append((request, body))
            if request.url.path == "/echo":
                return httpx.Response(200, json={"received": body})
            if request.url.path == "/safe":
                # 安全ツインは payload を反射せず、常に固定応答を返す。
                return httpx.Response(200, json={"result": "fixed"})
            return httpx.Response(404, json={"error": "not found"})

        self.engine = _Engine(httpx.MockTransport(fixture_pair))
        self.scanner = _Scanner(self.engine)
        common_body = {
            "profile": {"email": "old@example.test", "name": "Alice"},
            "password": "observed-secret",
        }
        for template_id, path in (("echo", "echo"), ("safe", "safe")):
            self.engine.injection_templates[template_id] = {
                "method": "post",
                "url": f"http://fixture.test/{path}",
                "json_body": common_body,
                "content_type": "application/json",
                "headers": {
                    "Authorization": "Bearer stale-template",
                    "X-Tenant": "fixture",
                },
            }

    async def test_echo_roundtrip_preserves_siblings_and_pair_shape(self):
        ip = InjectionPoint.for_json_body(
            "POST",
            "http://fixture.test/echo",
            "/profile/email",
            template_id="echo",
        )
        source, pair = await self.scanner._apply_json_payload(ip, "wscan-marker")

        sent = self.received[-1][1]
        self.assertEqual(sent["profile"]["email"], "wscan-marker")
        self.assertEqual(sent["profile"]["name"], "Alice")
        self.assertEqual(sent["password"], "observed-secret")
        self.assertEqual(
            self.engine.injection_templates["echo"]["json_body"]["profile"]["email"],
            "old@example.test",
        )
        self.assertEqual(pair["request"]["method"], "POST")
        self.assertEqual(json.loads(pair["request"]["post_data"]), sent)
        self.assertEqual(pair["request"]["headers"]["Authorization"], "Bearer current")
        self.assertEqual(pair["request"]["headers"]["X-Tenant"], "fixture")
        self.assertGreater(pair["request"]["timestamp"], 0)
        self.assertEqual(pair["response"]["status"], 200)
        self.assertEqual(pair["response"]["body"], source)
        self.assertGreaterEqual(
            pair["response"]["timestamp"], pair["request"]["timestamp"]
        )
        self.assertEqual(
            self.scanner.check_response_for_patterns(source, [r"wscan-marker"]),
            "wscan-marker",
        )

    async def test_safe_twin_does_not_reflect_payload(self):
        ip = InjectionPoint.for_json_body(
            "POST",
            "http://fixture.test/safe",
            "/profile/email",
            template_id="safe",
        )
        source, pair = await self.scanner._apply_json_payload(ip, "wscan-marker")
        self.assertEqual(pair["response"]["status"], 200)
        self.assertIsNone(
            self.scanner.check_response_for_patterns(source, [r"wscan-marker"])
        )

    async def test_log_records_only_injected_value_not_siblings(self):
        class _Logger:
            def __init__(self):
                self.entries = []

            def log_payload(self, field_name, payload, check_type, url):
                self.entries.append((field_name, payload, check_type, url))

        logger = _Logger()
        self.engine.request_logger = logger
        ip = InjectionPoint.for_json_body(
            "POST",
            "http://fixture.test/echo",
            "/profile/email",
            template_id="echo",
        )
        await self.scanner._apply_json_payload(ip, "wscan-marker")
        # 監査ログには注入値のみ。テンプレの兄弟(password=observed-secret)は現れない。
        self.assertTrue(logger.entries)
        logged_payloads = [payload for _f, payload, _c, _u in logger.entries]
        self.assertIn("wscan-marker", logged_payloads)
        for _f, payload, _c, _u in logger.entries:
            self.assertNotIn("observed-secret", payload)

    async def test_missing_template_returns_empty_result(self):
        ip = InjectionPoint.for_json_body(
            "POST", "http://fixture.test/echo", "/email", template_id="missing"
        )
        self.assertEqual(await self.scanner._apply_json_payload(ip, "x"), ("", {}))


if __name__ == "__main__":
    unittest.main()
