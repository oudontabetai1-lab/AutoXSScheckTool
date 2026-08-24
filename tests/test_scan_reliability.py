import tempfile
import unittest

from wscan.browser import BrowserManager
from wscan.engine import ScanEngine


class _Response:
    def __init__(self, status=200):
        self.status = status


class _FlakyPage:
    def __init__(self, failures_before_success=0, status=200):
        self.failures_before_success = failures_before_success
        self.status = status
        self.goto_calls = 0

    async def goto(self, url, wait_until="domcontentloaded", timeout=30000):
        self.goto_calls += 1
        if self.goto_calls <= self.failures_before_success:
            raise TimeoutError("temporary timeout")
        return _Response(self.status)


class _UnsettledPage:
    def __init__(self):
        self.calls = []

    async def wait_for_load_state(self, state, *, timeout):
        self.calls.append(("load", state, timeout))
        raise TimeoutError("network never became idle")

    async def wait_for_function(self, expression, *, timeout, polling):
        self.calls.append(("ready", timeout, polling))
        raise RuntimeError("root never became ready")


class BrowserNavigationReliabilityTests(unittest.IsolatedAsyncioTestCase):
    async def test_settle_spa_swallows_each_timeout_and_runs_both_waits(self):
        browser = BrowserManager(headless=True, timeout=1)
        browser.page = _UnsettledPage()

        await browser.settle_spa(timeout_ms=125)

        self.assertEqual(
            browser.page.calls,
            [("load", "networkidle", 125), ("ready", 125, 200)],
        )

    async def test_navigate_retries_transient_page_load_failures(self):
        browser = BrowserManager(headless=True, timeout=1)
        browser.page = _FlakyPage(failures_before_success=2)

        ok = await browser.navigate("http://fixture.test/flaky", retries=2, retry_delay=0)

        self.assertTrue(ok)
        self.assertEqual(browser.page.goto_calls, 3)
        self.assertEqual(browser.last_navigation_error, "")
        self.assertEqual(browser.last_navigation_status, 200)

    async def test_navigate_reports_final_failure_reason(self):
        browser = BrowserManager(headless=True, timeout=1)
        browser.page = _FlakyPage(failures_before_success=3)

        ok = await browser.navigate("http://fixture.test/down", retries=1, retry_delay=0)

        self.assertFalse(ok)
        self.assertEqual(browser.page.goto_calls, 2)
        self.assertIn("TimeoutError", browser.last_navigation_error)

    async def test_navigate_treats_http_client_error_as_unreachable(self):
        browser = BrowserManager(headless=True, timeout=1)
        browser.page = _FlakyPage(status=403)

        ok = await browser.navigate("http://fixture.test/private", retries=2, retry_delay=0)

        self.assertFalse(ok)
        self.assertEqual(browser.page.goto_calls, 1)
        self.assertEqual(browser.last_navigation_status, 403)
        self.assertEqual(browser.last_navigation_error, "HTTP 403")


class _FakeCrawlBrowser:
    def __init__(self):
        self.page = self
        self.last_navigation_error = ""
        self.last_navigation_status = None

    async def navigate(self, url, **kwargs):
        if url.endswith("/down"):
            self.last_navigation_error = "TimeoutError: fixture timeout"
            return False
        self.last_navigation_error = ""
        self.last_navigation_status = 200
        return True

    async def content(self):
        return "<html><body><a href='/down'>down</a><form><input name='q'></form></body></html>"

    async def find_forms(self):
        return [{"action": "", "inputs": [{"name": "q", "type": "text"}]}]

    async def get_url_params(self):
        return []

    async def screenshot_b64(self, label=""):
        return ""

    async def collect_links(self, base_url, same_domain=False):
        return ["http://fixture.test/down"]

    async def collect_links_rich(self, base_url, same_domain=False):
        return [{
            "url": "http://fixture.test/down",
            "text": "down",
            "selector": "a",
            "rect": {"x": 0, "y": 0, "w": 10, "h": 10},
            "viewport": {"w": 1280, "h": 800},
        }]


class EngineScanGapTests(unittest.IsolatedAsyncioTestCase):
    def _engine(self):
        out = tempfile.TemporaryDirectory()
        self.addCleanup(out.cleanup)
        engine = ScanEngine(
            "http://fixture.test/",
            checks=["xss"],
            llm_provider="none",
            output_dir=out.name,
            open_report=False,
            enable_waf_detection=False,
            enable_ai_analysis=False,
            enable_payload_learning=False,
            enable_adaptive_payloads=False,
            enable_sitemap_crawl=False,
            depth=2,
        )
        engine._browser = _FakeCrawlBrowser()
        return engine

    async def test_crawl_records_unscannable_urls_in_scan_matrix(self):
        engine = self._engine()

        pages = await engine._phase_crawl()

        self.assertEqual(len(pages), 1)
        failures = [
            row for row in engine.scan_matrix
            if row["url"] == "http://fixture.test/down" and row["check"] == "access"
        ]
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["status"], "error")
        self.assertIn("fixture timeout", failures[0]["note"])
        self.assertIn("http://fixture.test/", engine.reached_urls)
        self.assertNotIn("http://fixture.test/down", engine.reached_urls)
        coverage = engine.coverage_summary()
        self.assertEqual(coverage["reached_count"], 1)
        self.assertEqual(coverage["reached_urls"], ["http://fixture.test/"])
        self.assertEqual(
            coverage["unreached"],
            [{
                "url": "http://fixture.test/down",
                "reason": failures[0]["note"],
            }],
        )


if __name__ == "__main__":
    unittest.main()
