"""Tests for the HeaderManager (custom headers + periodic refresh)."""
import asyncio
import unittest

from wscan.header_manager import (
    HeaderManager,
    load_header_file,
    parse_header_args,
    parse_header_lines,
)


class ParseTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
