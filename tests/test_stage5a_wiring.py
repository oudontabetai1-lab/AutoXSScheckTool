"""段階5a の純配線と既存互換性を固定する安全ツインテスト。"""
import types
import unittest

from wscan.checkpoint import CheckpointState, unit_key
from wscan.injection_point import InjectionPoint
from wscan.scanners.base import BaseScanner, Finding


class InjectionPointLegacyAdapterTests(unittest.TestCase):
    def test_legacy_is_url_param_is_tri_state_safe(self):
        self.assertTrue(
            InjectionPoint.for_url_param("https://example.test/search", "q")
            .legacy_is_url_param()
        )
        self.assertFalse(
            InjectionPoint.for_form("https://example.test/login", "user", 2)
            .legacy_is_url_param()
        )
        with self.assertRaisesRegex(ValueError, "json_body"):
            InjectionPoint.for_json_body(
                "POST", "https://example.test/api", "/user/name"
            ).legacy_is_url_param()


class CheckpointKeyCompatibilityTests(unittest.TestCase):
    def test_form_and_url_param_keys_are_byte_identical_to_legacy_api(self):
        cases = [
            (
                InjectionPoint.for_form("https://example.test/form/", "email", 3),
                False,
            ),
            (
                InjectionPoint.for_url_param("https://example.test/search/", "q"),
                True,
            ),
        ]
        for ip, is_url_param in cases:
            for check in ("xss", "(adaptive:xss)"):
                with self.subTest(location=ip.location, check=check):
                    url, field_name, form_index, location_token, pointer = (
                        ip.stable_key_parts()
                    )
                    legacy_key = unit_key(
                        ip.url,
                        ip.display_name,
                        ip.form_index,
                        check,
                        is_url_param,
                    )
                    ip_key = unit_key(
                        url,
                        field_name,
                        int(form_index),
                        check,
                        location_token=location_token,
                        pointer=pointer,
                    )
                    self.assertEqual(ip_key.encode(), legacy_key.encode())

                    legacy_to_ip = CheckpointState()
                    legacy_to_ip.mark_done(
                        ip.url,
                        ip.display_name,
                        ip.form_index,
                        check,
                        is_url_param,
                    )
                    self.assertTrue(legacy_to_ip.is_done_ip(ip, check))

                    ip_to_legacy = CheckpointState()
                    ip_to_legacy.mark_done_ip(ip, check)
                    self.assertTrue(
                        ip_to_legacy.is_done(
                            ip.url,
                            ip.display_name,
                            ip.form_index,
                            check,
                            is_url_param,
                        )
                    )


class _RecordingBrowser:
    def __init__(self):
        self.calls = []

    async def test_url_param(self, url, field_name, payload):
        self.calls.append(("test_url_param", url, field_name, payload))
        return "", {}

    async def navigate(self, url):
        self.calls.append(("navigate", url))
        return True

    async def fill_and_submit_form(self, form_index, field_name, payload):
        self.calls.append(
            ("fill_and_submit_form", form_index, field_name, payload)
        )
        return "", {}


class _MinimalScanner(BaseScanner):
    async def scan_field(self, url, form_index, field, is_url_param=False):
        payload = "stage5a-payload"
        if is_url_param:
            await self.browser.test_url_param(url, field["name"], payload)
        else:
            await self.browser.navigate(url)
            await self.browser.fill_and_submit_form(
                form_index, field["name"], payload
            )
        return []


class ScannerAdapterEquivalenceTests(unittest.IsolatedAsyncioTestCase):
    async def test_form_and_url_param_browser_calls_match_legacy_scan_field(self):
        browser = _RecordingBrowser()
        engine = types.SimpleNamespace(
            browser=browser,
            monitor=None,
            payload_gen=types.SimpleNamespace(),
        )
        scanner = _MinimalScanner(engine)
        field = {"name": "q", "type": "text"}
        cases = [
            InjectionPoint.for_form("https://example.test/form", "q", 2),
            InjectionPoint.for_url_param("https://example.test/search", "q"),
        ]

        for ip in cases:
            with self.subTest(location=ip.location):
                await scanner.scan_field(
                    ip.url,
                    ip.form_index,
                    field,
                    ip.legacy_is_url_param(),
                )
                legacy_calls = list(browser.calls)
                browser.calls.clear()

                await scanner.scan_injection_point(ip, field)
                self.assertEqual(browser.calls, legacy_calls)
                browser.calls.clear()


class FindingRoundTripTests(unittest.TestCase):
    @staticmethod
    def _finding(**kwargs):
        return Finding(
            check_type="xss",
            severity="high",
            url="https://example.test/form",
            field_name="q",
            payload="payload",
            evidence="evidence",
            **kwargs,
        )

    def test_injection_form_index_round_trip(self):
        restored = Finding.from_dict(
            self._finding(injection_form_index=4).to_dict()
        )
        self.assertEqual(restored.injection_form_index, 4)

    def test_injection_form_index_defaults_to_zero(self):
        data = self._finding().to_dict()
        data.pop("injection_form_index")
        self.assertEqual(Finding.from_dict(data).injection_form_index, 0)


if __name__ == "__main__":
    unittest.main()
