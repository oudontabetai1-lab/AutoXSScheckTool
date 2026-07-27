"""Tests for the HeaderManager (custom headers + periodic refresh)."""
import asyncio
import unittest
from unittest.mock import AsyncMock

from wscan.header_manager import (
    HeaderManager,
    apply_bearer,
    load_header_file,
    parse_header_args,
    parse_header_lines,
)
from wscan.request_logger import _redact_headers, clear_sensitive_headers


class ParseTests(unittest.TestCase):
    def test_apply_bearer_only_when_authorization_is_absent(self):
        original = {"X-Tenant": "acme"}
        self.assertEqual(
            apply_bearer(original, " token "),
            {"X-Tenant": "acme", "Authorization": "Bearer token"},
        )
        self.assertEqual(original, {"X-Tenant": "acme"})

    def test_apply_bearer_preserves_existing_authorization_case_insensitively(self):
        headers = {"authorization": "Basic existing"}
        self.assertEqual(apply_bearer(headers, "new-token"), headers)

    def test_parse_header_args_basic(self):
        self.assertEqual(
            parse_header_args(["Authorization: Bearer abc", "X-Foo: bar"]),
            {"Authorization": "Bearer abc", "X-Foo": "bar"},
        )

    def test_parse_header_args_skips_garbage(self):
        # Lines without ":" or with empty name are ignored, not raised.
        self.assertEqual(parse_header_args(["", "no-colon", ": value"]), {})

    def test_parse_header_lines_text_and_json(self):
        self.assertEqual(parse_header_lines("A: 1\n# comment\nB:2"), {"A": "1", "B": "2"})
        self.assertEqual(parse_header_lines('{"A":"1","B":"2"}'), {"A": "1", "B": "2"})
        # HAR-style list of {name, value}
        self.assertEqual(
            parse_header_lines('[{"name":"A","value":"1"},{"name":"B","value":"2"}]'),
            {"A": "1", "B": "2"},
        )


class HeaderManagerTests(unittest.IsolatedAsyncioTestCase):
    async def test_update_is_case_insensitive(self):
        hm = HeaderManager(headers={"Authorization": "Bearer old"})
        await hm.update({"authorization": "Bearer new", "X-Foo": "bar"})
        # Old casing should be replaced, not duplicated.
        current = hm.current()
        self.assertEqual(current.get("authorization"), "Bearer new")
        self.assertEqual(current.get("X-Foo"), "bar")
        auth_keys = [k for k in current if k.lower() == "authorization"]
        self.assertEqual(len(auth_keys), 1)

    async def test_refresh_command_parses_output(self):
        hm = HeaderManager(refresh_cmd="printf 'Authorization: Bearer fresh\\nX-Tenant: acme'")
        self.assertTrue(await hm.refresh())
        self.assertEqual(hm.current()["Authorization"], "Bearer fresh")
        self.assertEqual(hm.current()["X-Tenant"], "acme")

    async def test_on_change_fires(self):
        received: list[dict] = []

        async def listener(snapshot: dict):
            received.append(snapshot)

        hm = HeaderManager(on_change=listener)
        await hm.update({"A": "1"})
        self.assertEqual(received, [{"A": "1"}])

    async def test_background_refresh_runs_and_stops(self):
        # Each invocation produces the same headers; we just verify the loop
        # fires at least once and stops cleanly without leaving a task behind.
        hm = HeaderManager(
            refresh_cmd="echo 'X-Counter: 1'",
            refresh_interval=0.05,
        )
        hm.start_background_refresh()
        await asyncio.sleep(0.15)
        await hm.stop_background_refresh()
        self.assertEqual(hm.current().get("X-Counter"), "1")
        self.assertIsNone(hm._task)


class EngineIntegrationTests(unittest.TestCase):
    def setUp(self):
        clear_sensitive_headers()

    def tearDown(self):
        clear_sensitive_headers()

    def test_engine_auth_headers_merges_custom_and_cookie(self):
        from wscan.engine import ScanEngine

        eng = ScanEngine(
            url="http://example.test",
            headers={"Authorization": "Bearer xyz", "X-Foo": "bar"},
        )
        eng.cookies = "session=abc"
        merged = eng.auth_headers()
        self.assertEqual(merged["Authorization"], "Bearer xyz")
        self.assertEqual(merged["X-Foo"], "bar")
        self.assertEqual(merged["Cookie"], "session=abc")
        # include_cookie=False suppresses the Cookie header.
        self.assertNotIn("Cookie", eng.auth_headers(include_cookie=False))

    def test_engine_registers_initial_custom_header_name_for_redaction(self):
        from wscan.engine import ScanEngine

        ScanEngine(
            url="http://example.test",
            headers={"X-Company-Auth": "initial-secret"},
        )

        self.assertEqual(
            _redact_headers({"x-company-auth": "initial-secret"}),
            {"x-company-auth": "<redacted>"},
        )

    def test_engine_registers_header_name_added_by_refresh(self):
        from wscan.engine import ScanEngine

        eng = ScanEngine(url="http://example.test")
        eng._browser.update_extra_headers = AsyncMock()

        asyncio.run(
            eng.header_manager.update({
                "X-Access-Credential": "rotated-secret",
            })
        )

        self.assertEqual(
            _redact_headers({"x-access-credential": "rotated-secret"}),
            {"x-access-credential": "<redacted>"},
        )


if __name__ == "__main__":
    unittest.main()
