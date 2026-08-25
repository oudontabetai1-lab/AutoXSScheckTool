import asyncio
import unittest

from wscan.engine import ScanEngine


class _FakePage:
    def __init__(self, content, url=""):
        self._content = content
        self.url = url

    async def content(self):
        return self._content


class _FakeBrowser:
    """Minimal async stand-in for the Playwright browser wrapper."""

    def __init__(
        self,
        forms,
        url_params=None,
        content="<html></html>",
        navigate_ok=True,
        landed_url=None,
    ):
        self._forms = forms
        self._url_params = url_params or []
        self._navigate_ok = navigate_ok
        self._landed_url = landed_url
        self.navigated = []
        self.page = _FakePage(content)

    async def navigate(self, url, retries=2):
        self.navigated.append(url)
        self.page.url = self._landed_url or url
        return self._navigate_ok

    async def find_forms(self):
        return self._forms

    async def get_url_params(self):
        return list(self._url_params)


class PreAuthLoginScanTests(unittest.TestCase):
    def _engine(self, **kwargs):
        return ScanEngine(
            "http://app.test/root",
            checks=["xss"],
            llm_provider="none",
            open_report=False,
            enable_waf_detection=False,
            enable_ai_analysis=False,
            enable_payload_learning=False,
            enable_adaptive_payloads=False,
            **kwargs,
        )

    @staticmethod
    def _login_form():
        return [{
            "action": "/login",
            "inputs": [
                {"name": "username", "type": "text"},
                {"name": "password", "type": "password"},
            ],
        }]

    def _run_preauth(self, engine):
        captured = {}

        async def fake_attack(page, plans):
            captured["page"] = page
            captured["plans"] = plans

        engine._attack_one_page = fake_attack
        asyncio.run(engine._scan_login_form_preauth())
        return captured

    def test_login_form_is_scanned_before_auth(self):
        engine = self._engine(login_url="http://app.test/login")
        engine._browser = _FakeBrowser(forms=self._login_form())

        captured = self._run_preauth(engine)

        # The login form must be handed to the attack routine.
        self.assertIn("page", captured)
        self.assertEqual(captured["page"].url, "http://app.test/login")
        self.assertTrue(captured["page"].forms)
        # Navigated to the login page in the (still unauthenticated) context.
        self.assertIn("http://app.test/login", engine._browser.navigated)
        # Marked visited so the authenticated crawl won't re-record it.
        self.assertIn("http://app.test/login", engine.visited_urls)
        # A successfully attacked pre-auth page is also part of reached coverage.
        self.assertIn("http://app.test/login", engine.reached_urls)

    def test_skipped_when_no_login_url(self):
        engine = self._engine()
        engine._browser = _FakeBrowser(forms=self._login_form())

        captured = self._run_preauth(engine)

        self.assertNotIn("page", captured)
        self.assertEqual(engine._browser.navigated, [])

    def test_skipped_when_login_is_cross_origin(self):
        # A cross-origin IdP login is access-only, not an attack target.
        engine = self._engine(login_url="http://auth.test/login")
        engine._browser = _FakeBrowser(forms=self._login_form())

        captured = self._run_preauth(engine)

        self.assertNotIn("page", captured)
        self.assertNotIn("http://auth.test/login", engine.visited_urls)

    def test_no_attack_when_login_page_has_no_inputs(self):
        engine = self._engine(login_url="http://app.test/login")
        engine._browser = _FakeBrowser(forms=[])

        captured = self._run_preauth(engine)

        self.assertNotIn("page", captured)
        # No form to test → do not suppress the authenticated crawl of the page.
        self.assertNotIn("http://app.test/login", engine.visited_urls)
        # Successful navigation is reached even when the page is form-less (SPA/button UI).
        self.assertIn("http://app.test/login", engine.reached_urls)

    def test_redirected_formless_login_seed_is_not_reached(self):
        engine = self._engine(login_url="http://app.test/login")
        engine._browser = _FakeBrowser(
            forms=[], landed_url="http://app.test/account"
        )

        captured = self._run_preauth(engine)

        self.assertNotIn("page", captured)
        self.assertNotIn("http://app.test/login", engine.reached_urls)


if __name__ == "__main__":
    unittest.main()
