"""段階5b-3 ブラウザ実行型スキャナ移行の安全ツインテスト。"""
import inspect
import unittest
from unittest.mock import AsyncMock, patch

from wscan.injection_point import InjectionPoint
from wscan.scanners.dom_xss import DOMXSSScanner
from wscan.scanners.xss import XSSScanner, _HANDLER_BASELINE_VALUE


_XSS_PAYLOAD = "<svg onload=alert(1)>"
_DOM_UID = "abc12345"
_DOM_PAYLOAD = f"__WSCAN_DOMXSS__{_DOM_UID}<img src=x onerror=alert(1)>"


class _PayloadGenerator:
    async def generate(self, **_kwargs):
        return [_XSS_PAYLOAD]


class _Page:
    def __init__(self, browser):
        self._browser = browser
        self.url = "https://example.test/current"

    async def content(self):
        return "<html><body>safe</body></html>"

    async def add_init_script(self, _script):
        return None

    async def evaluate(self, _script):
        if self._browser.dom_sink and self._browser.last_payload:
            return [
                {
                    "sink": "innerHTML",
                    "data": self._browser.last_payload,
                }
            ]
        return []


class _RecordingBrowser:
    def __init__(self, *, reflect=False, dom_sink=False):
        self.calls = []
        self.reflect = reflect
        self.dom_sink = dom_sink
        self.last_payload = ""
        self.dialog_fired = False
        self.dialog_message = ""
        self.dialog_screenshot_b64 = ""
        self.page = _Page(self)

    def _result(self, payload):
        body = f"<html><body>{payload}</body></html>" if self.reflect else ""
        return body, {"response": {"body": body}}

    async def test_url_param(self, url, field_name, payload):
        self.calls.append(("test_url_param", url, field_name, payload))
        self.last_payload = payload
        self.page.url = url
        return self._result(payload)

    async def navigate(self, url):
        self.calls.append(("navigate", url))
        self.page.url = url
        return True

    async def fill_and_submit_form(self, form_index, field_name, payload):
        self.calls.append(
            ("fill_and_submit_form", form_index, field_name, payload)
        )
        self.last_payload = payload
        return self._result(payload)

    async def snapshot_dialog_handlers(self):
        return []

    async def trigger_injected_handlers(self, *_args):
        return False

    async def screenshot_b64(self, label=""):
        return ""

    def reset_dialog(self):
        self.dialog_fired = False
        self.dialog_message = ""


class _Engine:
    def __init__(self, browser=None):
        self.browser = browser or _RecordingBrowser()
        self.monitor = None
        self.payload_gen = _PayloadGenerator()
        self.request_logger = None
        self.custom_payloads = {}
        self.sleep_factor = 0
        self.max_payloads = 0
        self.enable_payload_evolution = False
        self.enable_payload_mutation = False
        self._finding_dedup = set()
        self.all_findings = []
        self.injection_templates = {}
        self.timeout = 5


def _legacy_xss_calls(ip: InjectionPoint) -> list[tuple]:
    """移行前 XSS の baseline と payload 投入が作る呼出し列。"""
    calls = [("navigate", ip.url)]
    for payload in (_HANDLER_BASELINE_VALUE, _XSS_PAYLOAD):
        if ip.location == "url_param":
            calls.append(
                ("test_url_param", ip.url, ip.parameter_id, payload)
            )
        else:
            calls.extend(
                [
                    ("navigate", ip.url),
                    (
                        "fill_and_submit_form",
                        ip.form_index,
                        ip.parameter_id,
                        payload,
                    ),
                ]
            )
    return calls


def _legacy_dom_xss_calls(ip: InjectionPoint) -> list[tuple]:
    """移行前 DOM XSS の初回 payload 投入が作る呼出し列。"""
    if ip.location == "url_param":
        return [("test_url_param", ip.url, ip.parameter_id, _DOM_PAYLOAD)]
    return [
        ("navigate", ip.url),
        ("fill_and_submit_form", ip.form_index, ip.parameter_id, _DOM_PAYLOAD),
    ]


class BrowserCallParityTests(unittest.IsolatedAsyncioTestCase):
    async def test_xss_form_and_url_param_calls_match_legacy(self):
        field = {"name": "target", "type": "text"}
        cases = (
            InjectionPoint.for_form("https://example.test/form", "target", 3),
            InjectionPoint.for_url_param(
                "https://example.test/search?target=old", "target"
            ),
        )

        for ip in cases:
            with self.subTest(location=ip.location):
                browser = _RecordingBrowser()
                scanner = XSSScanner(_Engine(browser))
                # 等価性 probe 自体のテストではなく、移行した既存送信列だけを比較する。
                scanner.run_equivalence_probe = AsyncMock(return_value=None)

                findings = await scanner.scan_injection_point(ip, field)

                self.assertEqual(findings, [])
                self.assertEqual(browser.calls, _legacy_xss_calls(ip))

    async def test_dom_xss_form_and_url_param_calls_match_legacy(self):
        field = {"name": "target", "type": "text"}
        cases = (
            InjectionPoint.for_form("https://example.test/form", "target", 0),
            InjectionPoint.for_url_param(
                "https://example.test/search?target=old", "target"
            ),
        )

        for ip in cases:
            with self.subTest(location=ip.location):
                browser = _RecordingBrowser()
                scanner = DOMXSSScanner(_Engine(browser))

                with patch("wscan.scanners.dom_xss.uuid.uuid4") as uuid4:
                    uuid4.return_value.hex = _DOM_UID
                    findings = await scanner.scan_injection_point(ip, field)

                self.assertEqual(findings, [])
                self.assertEqual(browser.calls, _legacy_dom_xss_calls(ip))

    async def test_dom_xss_uses_selected_form_index(self):
        # 旧 scan 本体は fill_and_submit_form(form_index, ...) を使っていた。form_index>0 の
        # 注入点を form 0 で潰さない（provenance 不整合・検出取りこぼし防止）。
        browser = _RecordingBrowser()
        scanner = DOMXSSScanner(_Engine(browser))
        ip = InjectionPoint.for_form("https://example.test/form", "target", 2)
        await scanner._apply_payload(
            ip.url, ip.parameter_id, "x", ip.form_index, ip.legacy_is_url_param()
        )
        self.assertIn(("fill_and_submit_form", 2, "target", "x"), browser.calls)

    async def test_dom_xss_form_field_named_like_query_param_submits_form(self):
        # form field 'q' が /search?q=old と同名でも、明示種別(form)で form 送信する
        # （URL クエリ推測に戻すと test_url_param へ誤経路し form-only DOM XSS を取りこぼす）。
        browser = _RecordingBrowser()
        scanner = DOMXSSScanner(_Engine(browser))
        ip = InjectionPoint.for_form("https://example.test/search?q=old", "q", 0)
        await scanner._apply_payload(
            ip.url, ip.parameter_id, "x", ip.form_index, ip.legacy_is_url_param()
        )
        self.assertIn(("fill_and_submit_form", 0, "q", "x"), browser.calls)
        self.assertNotIn(
            ("test_url_param", "https://example.test/search?q=old", "q", "x"),
            browser.calls,
        )


class InjectionPointRoutingTests(unittest.IsolatedAsyncioTestCase):
    def test_both_scanners_explicitly_reject_json_body(self):
        self.assertIs(XSSScanner.SUPPORTS_JSON_BODY, False)
        self.assertIs(DOMXSSScanner.SUPPORTS_JSON_BODY, False)

    async def test_json_body_is_guarded_without_browser_submission(self):
        ip = InjectionPoint.for_json_body(
            "POST",
            "https://example.test/api",
            "/target",
            template_id="unused",
        )
        field = {"name": "target", "type": "text"}

        for scanner_cls in (XSSScanner, DOMXSSScanner):
            with self.subTest(scanner=scanner_cls.__name__):
                browser = _RecordingBrowser()
                scanner = scanner_cls(_Engine(browser))

                self.assertEqual(await scanner._apply_ip(ip, "marker"), ("", {}))
                self.assertEqual(await scanner.scan_injection_point(ip, field), [])
                self.assertEqual(browser.calls, [])


class ProvenanceAndCompatibilityTests(unittest.IsolatedAsyncioTestCase):
    def test_apply_payload_signatures_remain_unchanged(self):
        self.assertEqual(
            list(inspect.signature(XSSScanner._apply_payload).parameters),
            [
                "self",
                "url",
                "form_index",
                "field_name",
                "payload",
                "is_url_param",
            ],
        )
        # dom_xss は非標準 transport。form_index と**明示の is_url_param** を引数で受け、
        # 選択フォーム/明示種別へ送る（URL クエリ推測はしない。エンジン汎用 verify は
        # dom_xss._apply_payload を呼ばないので engine 互換の制約外）。
        self.assertEqual(
            list(inspect.signature(DOMXSSScanner._apply_payload).parameters),
            ["self", "url", "field_name", "payload", "form_index", "is_url_param"],
        )

    async def test_xss_form_finding_stamps_location_and_form_index(self):
        browser = _RecordingBrowser(reflect=True)
        scanner = XSSScanner(_Engine(browser))
        ip = InjectionPoint.for_form(
            "https://example.test/form", "target", 4
        )

        findings = await scanner.scan_injection_point(
            ip, {"name": "target", "type": "text"}
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].injection_location, "form")
        self.assertEqual(findings[0].injection_form_index, 4)

    async def test_dom_xss_form_finding_stamps_location_and_form_index(self):
        browser = _RecordingBrowser(dom_sink=True)
        scanner = DOMXSSScanner(_Engine(browser))
        ip = InjectionPoint.for_form(
            "https://example.test/form", "target", 6
        )

        with patch("wscan.scanners.dom_xss.uuid.uuid4") as uuid4:
            uuid4.return_value.hex = _DOM_UID
            findings = await scanner.scan_injection_point(
                ip, {"name": "target", "type": "text"}
            )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].injection_location, "form")
        self.assertEqual(findings[0].injection_form_index, 6)


if __name__ == "__main__":
    unittest.main()
