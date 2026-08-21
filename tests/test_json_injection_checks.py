"""SPA 収穫 JSON body の攻撃ループと再開キーのテスト。"""
import unittest

from wscan.engine import ScanEngine
from wscan.injection_point import InjectionPoint


class _Controller:
    async def checkpoint(self):
        return None


class _Scanner:
    SUPPORTS_JSON_BODY = True

    def __init__(self):
        self.calls = []

    async def scan_injection_point(self, ip, field):
        self.calls.append((ip, field))
        return []


class _Engine:
    _run_json_injection_checks = ScanEngine._run_json_injection_checks

    def __init__(self, points, templates):
        self.json_injection_points = list(points)
        self.injection_templates = dict(templates)
        self.controller = _Controller()
        self.browser = object()
        self.scanner = _Scanner()
        self.scanners = {"sqli": self.scanner}
        self.done = set()
        self.marked = []
        self.saved = 0

    async def _maybe_relogin_for_page(self, url):
        return None

    async def _sync_cookies_from_browser(self, browser, *, for_url):
        return None

    async def _api_session_looks_expired(self, url):
        return False

    async def _force_relogin(self, *, for_url):
        return False

    def _checkpoint_is_done_ip(self, ip, check):
        return (ip.stable_key_parts(), check) in self.done

    def _checkpoint_mark_done_ip(self, ip, check):
        key = (ip.stable_key_parts(), check)
        self.done.add(key)
        self.marked.append(key)

    def _record_finding(self, finding, source=""):
        raise AssertionError("このテストでは Finding を返さない")

    def _save_checkpoint(self):
        self.saved += 1


class JsonInjectionCheckTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_template_is_not_marked_done(self):
        ip = InjectionPoint.for_json_body(
            "POST", "http://h/api/login", "/email", template_id="missing"
        )
        engine = _Engine([ip], {})

        await engine._run_json_injection_checks()

        self.assertEqual(len(engine.scanner.calls), 1)
        self.assertEqual(engine.marked, [])
        self.assertEqual(engine.saved, 1)

    async def test_registered_template_is_marked_done(self):
        ip = InjectionPoint.for_json_body(
            "POST", "http://h/api/login", "/email", template_id="login"
        )
        engine = _Engine([ip], {"login": {}})

        await engine._run_json_injection_checks()

        self.assertEqual(len(engine.scanner.calls), 1)
        self.assertEqual(len(engine.marked), 1)

    async def test_distinct_templates_with_same_pointer_are_both_scanned(self):
        first = InjectionPoint.for_json_body(
            "POST", "http://h/api/rpc", "/params/name", template_id="op-a"
        )
        second = InjectionPoint.for_json_body(
            "POST", "http://h/api/rpc", "/params/name", template_id="op-b"
        )
        self.assertNotEqual(first.stable_key_parts(), second.stable_key_parts())
        engine = _Engine([first, second], {"op-a": {}, "op-b": {}})

        await engine._run_json_injection_checks()

        self.assertEqual(
            [call[0].template_id for call in engine.scanner.calls],
            ["op-a", "op-b"],
        )
        self.assertEqual(len(engine.marked), 2)

    def test_legacy_keys_and_empty_template_json_key_are_unchanged(self):
        form = InjectionPoint.for_form("http://h/form/", "email", 2)
        url_param = InjectionPoint.for_url_param("http://h/search/", "q")
        json_ip = InjectionPoint.for_json_body(
            "POST", "http://h/api/login/", "/email"
        )

        self.assertEqual(
            form.stable_key_parts(),
            ("http://h/form", "email", "2", "f", ""),
        )
        self.assertEqual(
            url_param.stable_key_parts(),
            ("http://h/search", "q", "0", "u", ""),
        )
        self.assertEqual(
            json_ip.stable_key_parts(),
            ("http://h/api/login", "email", "0", "j:POST", "/email"),
        )


if __name__ == "__main__":
    unittest.main()
