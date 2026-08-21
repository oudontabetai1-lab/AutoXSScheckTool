"""_evolution_probe が navigate 失敗時に probe 投入をスキップすることの回帰テスト（G7/P1）。

navigate() が False（timeout/HTTP エラー）のまま fill_and_submit_form を送ると、
前 scanner の残存ページや別フォームへ probe が入り、観測を誤ったフィールドへ
帰属してしまう。navigate 失敗時は空値を返し、注入を行わないことを保証する。
"""
import unittest

from wscan.scanners.base import BaseScanner


class _Scanner(BaseScanner):
    CHECK_TYPE = "xss"

    async def scan_field(self, url, form_index, field, is_url_param=False):  # pragma: no cover
        return []


class _FakeBrowser:
    def __init__(self, navigate_ok: bool):
        self._navigate_ok = navigate_ok
        self.submitted = False

    async def navigate(self, url, *a, **kw):
        return self._navigate_ok

    async def fill_and_submit_form(self, form_index, field_name, payload, *a, **kw):
        self.submitted = True
        return "<html></html>", {"response": {"body": ""}}

    async def test_url_param(self, url, param, payload):  # pragma: no cover
        return "<html></html>", {"response": {"body": ""}}


class _FakeEngine:
    def __init__(self, navigate_ok: bool):
        self.browser = _FakeBrowser(navigate_ok)
        self.monitor = None
        self.payload_gen = None
        self.controller = None
        self.request_logger = None
        self.enable_payload_evolution = True
        self.enable_payload_mutation = True
        self.max_payloads = 8


class EvolutionProbeNavigateGuardTests(unittest.IsolatedAsyncioTestCase):
    async def test_skips_submit_when_navigation_fails(self):
        engine = _FakeEngine(navigate_ok=False)
        scanner = _Scanner(engine)
        src, surviving, context = await scanner._evolution_probe(
            "http://x/", 0, "q", is_url_param=False
        )
        self.assertEqual((src, surviving, context), ("", set(), {}))
        self.assertFalse(engine.browser.submitted)  # 注入していない

    async def test_submits_when_navigation_succeeds(self):
        engine = _FakeEngine(navigate_ok=True)
        scanner = _Scanner(engine)
        await scanner._evolution_probe("http://x/", 0, "q", is_url_param=False)
        self.assertTrue(engine.browser.submitted)


    async def test_browser_override_is_used_instead_of_scanner_browser(self):
        # concurrency>1 では scanner.browser は main(stale)。呼び出し側が現 worker の
        # browser を渡せば、そちらへ probe が入る（self.browser は使われない）。
        engine = _FakeEngine(navigate_ok=True)   # scanner.browser = engine.browser
        scanner = _Scanner(engine)
        worker_browser = _FakeBrowser(navigate_ok=True)
        await scanner._evolution_probe(
            "http://x/", 0, "q", is_url_param=False, browser=worker_browser
        )
        self.assertTrue(worker_browser.submitted)       # worker へ入った
        self.assertFalse(engine.browser.submitted)      # main(stale) には入らない


if __name__ == "__main__":
    unittest.main()
