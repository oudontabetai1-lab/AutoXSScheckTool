import tempfile
import unittest
from types import SimpleNamespace

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


class _CanonicalBlockedPage:
    def __init__(self, network):
        self.network = network

    async def goto(self, url, wait_until="domcontentloaded", timeout=30000):
        final_url = "https://www.FIXTURE.test:8443/private"
        request = SimpleNamespace(
            url=final_url,
            method="GET",
            headers={},
            post_data=None,
            resource_type="document",
        )
        response = SimpleNamespace(
            url=final_url,
            status=403,
            headers={},
            request=request,
        )
        self.network.on_request(request)
        self.network.on_response(response)
        return response


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

    async def test_failed_canonical_redirect_counts_known_host_block(self):
        browser = BrowserManager(headless=True, timeout=1)
        browser.network.allowed_hosts = {"fixture.test"}
        browser.page = _CanonicalBlockedPage(browser.network)

        ok = await browser.navigate("http://fixture.test/private", retries=0)

        self.assertFalse(ok)
        self.assertEqual(browser.network.status_counts, {403: 1})
        self.assertEqual(browser.network.status_summary()["blocked"], 1)


class _FakeCrawlBrowser:
    def __init__(self):
        self.page = self
        self.url = ""
        self.last_navigation_error = ""
        self.last_navigation_status = None
        self.auth_user = ""
        self.auth_pass = ""
        self.network = SimpleNamespace(allowed_hosts=None)

    async def navigate(self, url, **kwargs):
        if url.endswith("/down"):
            self.last_navigation_error = "TimeoutError: fixture timeout"
            return False
        self.url = url
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

    def is_on_login_page(self, login_url):
        return bool(login_url) and self.url.rstrip("/") == login_url.rstrip("/")


class _SessionExpiryBrowser(_FakeCrawlBrowser):
    def __init__(
        self,
        *,
        relogin_succeeds,
        renavigate_succeeds=True,
        login_url="http://auth.fixture.test/login",
    ):
        super().__init__()
        self.auth_user = "user"
        self.auth_pass = "pass"
        self.relogin_succeeds = relogin_succeeds
        self.renavigate_succeeds = renavigate_succeeds
        self.login_url = login_url
        self.private_navigations = 0

    async def navigate(self, url, **kwargs):
        if url.endswith("/private"):
            self.private_navigations += 1
            if self.private_navigations == 1:
                self.url = self.login_url
                return True
            if not self.renavigate_succeeds:
                self.last_navigation_error = "TimeoutError: reload failed"
                return False
        return await super().navigate(url, **kwargs)

    async def auto_login(self, *args, **kwargs):
        if self.relogin_succeeds:
            self.url = "http://fixture.test/dashboard"
        return self.relogin_succeeds


class _PostAuthSessionLossBrowser(_FakeCrawlBrowser):
    def __init__(self, login_url="http://auth.fixture.test/login"):
        super().__init__()
        self.login_url = login_url

    async def navigate(self, url, **kwargs):
        if url == "http://fixture.test/private":
            self.url = self.login_url
            return True
        return await super().navigate(url, **kwargs)

    async def collect_links_rich(self, base_url, same_domain=False):
        return [{
            "url": "http://fixture.test/private",
            "text": "private",
            "selector": "a",
            "rect": {"x": 0, "y": 0, "w": 10, "h": 10},
            "viewport": {"w": 1280, "h": 800},
        }]


class EngineScanGapTests(unittest.IsolatedAsyncioTestCase):
    def _engine(self, url="http://fixture.test/", **kwargs):
        out = tempfile.TemporaryDirectory()
        self.addCleanup(out.cleanup)
        depth = kwargs.pop("depth", 2)
        engine = ScanEngine(
            url,
            checks=["xss"],
            llm_provider="none",
            output_dir=out.name,
            open_report=False,
            enable_waf_detection=False,
            enable_ai_analysis=False,
            enable_payload_learning=False,
            enable_adaptive_payloads=False,
            enable_sitemap_crawl=False,
            depth=depth,
            **kwargs,
        )
        engine._browser = _FakeCrawlBrowser()
        return engine

    async def test_crawl_records_unscannable_urls_in_scan_matrix(self):
        from wscan.engine import _configure_network_coverage_hosts

        engine = self._engine()
        # run() は browser.init 直後に coverage origin を設定する。_phase_crawl を
        # 直接呼ぶこのテストでは同等のセットアップを明示的に行う。
        _configure_network_coverage_hosts(
            engine._browser, getattr(engine, "_coverage_hosts", set())
        )

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
        self.assertEqual(
            engine._browser.network.allowed_hosts,
            {"fixture.test"},
        )
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

    async def test_crawl_does_not_reach_page_when_relogin_fails(self):
        engine = self._engine(
            "http://fixture.test/private",
            login_url="http://auth.fixture.test/login",
            depth=1,
        )
        engine._browser = _SessionExpiryBrowser(relogin_succeeds=False)

        pages = await engine._phase_crawl()

        self.assertEqual(pages, [])
        self.assertNotIn("http://fixture.test/private", engine.reached_urls)
        self.assertEqual(
            engine.coverage_summary()["unreached"],
            [{
                "url": "http://fixture.test/private",
                "reason": "Re-login failed — authenticated content not accessible.",
            }],
        )

    async def test_crawl_no_relogin_records_login_redirect_as_unreached(self):
        engine = self._engine(
            "http://fixture.test/private",
            login_url="http://auth.fixture.test/login",
            relogin_on_expiry=False,
            depth=1,
        )
        engine._browser = _SessionExpiryBrowser(relogin_succeeds=False)

        pages = await engine._phase_crawl()

        self.assertEqual(pages, [])
        self.assertNotIn("http://fixture.test/private", engine.reached_urls)
        self.assertEqual(
            engine.coverage_summary()["unreached"],
            [{
                "url": "http://fixture.test/private",
                "reason": "Redirected to login (authenticated content not accessible).",
            }],
        )

    async def test_crawl_reaches_page_after_successful_relogin(self):
        engine = self._engine(
            "http://fixture.test/private",
            login_url="http://auth.fixture.test/login",
            depth=1,
        )
        engine._browser = _SessionExpiryBrowser(relogin_succeeds=True)

        pages = await engine._phase_crawl()

        self.assertEqual(len(pages), 1)
        self.assertIn("http://fixture.test/private", engine.reached_urls)
        self.assertEqual(engine.coverage_summary()["unreached"], [])

    async def test_crawl_counts_deliberate_login_target_as_reached(self):
        login_url = "http://fixture.test/login"
        engine = self._engine(login_url, login_url=login_url, depth=1)
        engine._browser = _FakeCrawlBrowser()

        pages = await engine._phase_crawl()

        self.assertEqual(len(pages), 1)
        self.assertIn(login_url, engine.reached_urls)
        self.assertEqual(engine.coverage_summary()["unreached"], [])

    async def test_crawl_reload_failure_is_unreached_only(self):
        engine = self._engine(
            "http://fixture.test/private",
            login_url="http://auth.fixture.test/login",
            depth=1,
        )
        engine._browser = _SessionExpiryBrowser(
            relogin_succeeds=True,
            renavigate_succeeds=False,
        )

        pages = await engine._phase_crawl()

        self.assertEqual(pages, [])
        self.assertNotIn("http://fixture.test/private", engine.reached_urls)
        self.assertEqual(
            engine.coverage_summary()["unreached"][0]["url"],
            "http://fixture.test/private",
        )

    async def test_postauth_crawl_records_successful_navigation_as_reached(self):
        engine = self._engine("http://fixture.test/private", depth=1)
        engine._browser = _FakeCrawlBrowser()

        pages = await engine._phase_crawl_postauth()

        self.assertEqual(len(pages), 1)
        self.assertIn("http://fixture.test/private", engine.reached_urls)

    async def test_postauth_login_redirect_is_unreached(self):
        protected_url = "http://fixture.test/private"
        engine = self._engine(
            "http://fixture.test/",
            login_url="http://auth.fixture.test/login",
            depth=2,
        )
        engine._browser = _PostAuthSessionLossBrowser()

        await engine._phase_crawl_postauth()

        self.assertNotIn(protected_url, engine.reached_urls)
        self.assertEqual(
            engine.coverage_summary()["unreached"],
            [{
                "url": protected_url,
                "reason": "Redirected to login during post-auth crawl (session lost).",
            }],
        )


if __name__ == "__main__":
    unittest.main()
