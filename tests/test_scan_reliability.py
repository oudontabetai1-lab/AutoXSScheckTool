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
        final_url = "https://www.FIXTURE.test/private"
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
        self.spa_settle = False
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

    async def clear_scope_route(self):
        return None


class _SpaMarkerCrawlBrowser(_FakeCrawlBrowser):
    def __init__(self):
        super().__init__()
        self.explore_calls = 0
        self.settle_calls = 0

    async def content(self):
        return "<html><body><app-root></app-root></body></html>"

    async def find_forms(self):
        return []

    async def collect_links_rich(self, base_url, same_domain=False):
        return []

    async def explore_spa_interactions(self, page, url, max_clicks=20, **kwargs):
        self.explore_calls += 1
        return []

    async def settle_spa(self):
        self.settle_calls += 1


class _SpaHydrationCrawlBrowser(_FakeCrawlBrowser):
    """本番シェル: hydration 前は空 <app-root>、settle 後にフォームが現れる。"""

    def __init__(self):
        super().__init__()
        self.events: list[str] = []
        self._settled = False

    async def content(self):
        if self._settled:
            return (
                "<html><body><app-root><form>"
                "<input name='q'></form></app-root></body></html>"
            )
        return "<html><body><app-root></app-root></body></html>"

    async def find_forms(self):
        self.events.append("find_forms")
        if self._settled:
            return [{"action": "", "inputs": [{"name": "q", "type": "text"}]}]
        return []

    async def explore_spa_interactions(self, page, url, max_clicks=20, **kwargs):
        self.events.append("explore")
        return []

    async def settle_spa(self):
        self.events.append("settle_spa")
        self._settled = True

    async def collect_links_rich(self, base_url, same_domain=False):
        return []


class _SpaRouteDiscoveryBrowser(_FakeCrawlBrowser):
    """SPA マーカー付きで、クリック探索が1つの動的ルートを返す。"""

    def __init__(self, route="http://fixture.test/dyn"):
        super().__init__()
        self.route = route

    async def content(self):
        return "<html><body><app-root></app-root></body></html>"

    async def find_forms(self):
        return []

    async def explore_spa_interactions(self, page, url, max_clicks=20, **kwargs):
        return [self.route]

    async def settle_spa(self):
        pass

    async def collect_links_rich(self, base_url, same_domain=False):
        return []


class _LateSpaTargetBrowser(_FakeCrawlBrowser):
    """主ページは通常サイト、リンク先 /page2 が SPA シェル。"""

    def _is_page2(self) -> bool:
        return self.url.rstrip("/").endswith("/page2")

    async def content(self):
        if self._is_page2():
            return "<html><body><app-root></app-root></body></html>"
        return (
            "<html><body><h1>Home</h1>"
            "<a href='http://fixture.test/page2'>next</a></body></html>"
        )

    async def find_forms(self):
        return []

    async def collect_links_rich(self, base_url, same_domain=False):
        if self._is_page2():
            return []
        return [{
            "url": "http://fixture.test/page2",
            "text": "next",
            "selector": "a",
            "rect": {"x": 0, "y": 0, "w": 10, "h": 10},
            "viewport": {"w": 1280, "h": 800},
        }]

    async def explore_spa_interactions(self, page, url, max_clicks=20, **kwargs):
        return []

    async def settle_spa(self):
        pass


class _SettleRedirectSpaBrowser(_SpaMarkerCrawlBrowser):
    """settle_spa 中に client-side redirect で out-of-scope へ移る本番シェル。"""

    async def settle_spa(self):
        await super().settle_spa()
        self.url = "https://idp.external.test/login"


class _RedirectRecordingSpaBrowser(_FakeCrawlBrowser):
    """queued URL から同一 origin の別パスへリダイレクトし、explore の base_url を記録する。"""

    def __init__(self):
        super().__init__()
        self.explore_base = None

    async def navigate(self, url, **kwargs):
        self.url = "http://fixture.test/landed"
        self.last_navigation_error = ""
        self.last_navigation_status = 200
        return True

    async def content(self):
        return "<html><body><app-root></app-root></body></html>"

    async def find_forms(self):
        return []

    async def collect_links_rich(self, base_url, same_domain=False):
        return []

    async def explore_spa_interactions(self, page, url, max_clicks=20, **kwargs):
        self.explore_base = url
        return []

    async def settle_spa(self):
        pass


class _ExternalRedirectSpaBrowser(_FakeCrawlBrowser):
    """in-scope URL が外部 IdP(SPA シェル) へリダイレクトした状況を模す。"""

    async def navigate(self, url, **kwargs):
        self.url = "https://idp.external.test/login"
        self.last_navigation_error = ""
        self.last_navigation_status = 200
        return True

    async def content(self):
        return "<html><body><app-root></app-root></body></html>"

    async def find_forms(self):
        return []

    async def collect_links_rich(self, base_url, same_domain=False):
        return []

    async def explore_spa_interactions(self, page, url, max_clicks=20, **kwargs):
        return []

    async def settle_spa(self):
        pass


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

    async def test_first_page_spa_marker_auto_enables_crawl_and_settle(self):
        engine = self._engine(depth=1)
        browser = _SpaMarkerCrawlBrowser()
        engine._browser = browser

        await engine._phase_crawl()

        self.assertTrue(engine.spa_crawl)
        self.assertTrue(browser.spa_settle)
        # 自動有効化（既定）はクリック探索を read-only 運用にするため、opt-in が無ければ
        # explore は呼ばない（Codex #104 P1）。settle と harvest は継続。
        self.assertEqual(browser.explore_calls, 0)
        # settle は初回ページで2回: 自動有効化直後の hydration 待ち＋harvest 前の XHR 待ち。
        self.assertEqual(browser.settle_calls, 2)

    async def test_auto_enabled_spa_click_exploration_requires_opt_in(self):
        # allow_state_changing_probes の opt-in があればクリック探索を行う（Codex #104 P1）。
        engine = self._engine(depth=1, allow_state_changing_probes=True)
        browser = _SpaMarkerCrawlBrowser()
        engine._browser = browser

        await engine._phase_crawl()

        self.assertTrue(engine.spa_crawl)
        self.assertEqual(browser.explore_calls, 1)

    async def test_explicit_spa_crawl_click_exploration_runs_without_probe_opt_in(self):
        # 明示 --spa-crawl は自動有効化ではないので opt-in 無しでもクリック探索する。
        engine = self._engine(depth=1, spa_crawl=True)
        browser = _SpaMarkerCrawlBrowser()
        engine._browser = browser

        await engine._phase_crawl()

        self.assertTrue(engine.spa_crawl)
        self.assertEqual(browser.explore_calls, 1)

    async def test_auto_spa_opt_out_keeps_crawl_disabled(self):
        engine = self._engine(depth=1, auto_spa_crawl=False)
        browser = _SpaMarkerCrawlBrowser()
        engine._browser = browser

        await engine._phase_crawl()

        self.assertFalse(engine.spa_crawl)
        self.assertFalse(browser.spa_settle)
        self.assertEqual(browser.explore_calls, 0)
        self.assertEqual(browser.settle_calls, 0)

    async def test_auto_enabled_spa_settles_first_page_before_form_extraction(self):
        # 初回 navigate は spa_settle=False で完了済み。自動有効化した本番シェルでは、
        # find_forms/get_url_params の前に settle して html を採り直さないと hydration
        # 前の空 DOM から 0 件になる（Codex #104 P1）。
        engine = self._engine(depth=1)
        browser = _SpaHydrationCrawlBrowser()
        engine._browser = browser

        pages = await engine._phase_crawl()

        self.assertTrue(engine.spa_crawl)
        # settle が初回ページの form 抽出より前に走る。
        self.assertIn("settle_spa", browser.events)
        self.assertIn("find_forms", browser.events)
        self.assertLess(
            browser.events.index("settle_spa"),
            browser.events.index("find_forms"),
        )
        # hydration 後のフォームが初回ページに反映される。
        target = engine.target_url.rstrip("/")
        first = next(
            (p for p in pages if p.url.rstrip("/") == target), None
        )
        self.assertIsNotNone(first)
        self.assertTrue(first.forms)

    async def test_spa_route_enqueue_respects_depth_limit(self):
        # --depth 1 では探索ルートを訪問しない（通常リンクと同じ深度ガード・Codex #104 P2）。
        engine = self._engine(depth=1, allow_state_changing_probes=True)
        engine._browser = _SpaRouteDiscoveryBrowser()

        await engine._phase_crawl()

        self.assertTrue(engine.spa_crawl)
        self.assertNotIn("http://fixture.test/dyn", engine.visited_urls)

    async def test_spa_route_enqueue_allowed_within_depth(self):
        # depth=2 なら初回ページ(depth0)の探索ルートは depth1 として巡回対象になる。
        engine = self._engine(depth=2, allow_state_changing_probes=True)
        engine._browser = _SpaRouteDiscoveryBrowser()

        await engine._phase_crawl()

        self.assertIn("http://fixture.test/dyn", engine.visited_urls)

    async def test_spa_detection_not_locked_to_first_page(self):
        # 主 URL が通常ページでも、後続のリンク先 SPA で自動有効化される
        # （検出は _first_page に縛られない・Codex #104 P1）。
        engine = self._engine(depth=2)
        engine._browser = _LateSpaTargetBrowser()

        await engine._phase_crawl()

        self.assertTrue(engine.spa_crawl)

    async def test_spa_detected_even_when_page_is_fingerprint_duplicate(self):
        # origin 非依存の _page_fingerprint で SPA シェルが既出ページと衝突して重複
        # スキップされても、検出は重複スキップより前に走り自動有効化される（Codex #104 P1）。
        engine = self._engine(depth=1)
        browser = _SpaMarkerCrawlBrowser()  # content()=<app-root></app-root>
        engine._browser = browser
        spa_html = "<html><body><app-root></app-root></body></html>"
        engine._seen_page_fingerprints = {
            engine._page_fingerprint(spa_html, engine.target_url)
        }

        await engine._phase_crawl()

        self.assertTrue(engine.spa_crawl)

    async def test_spa_explore_uses_landed_url_as_base(self):
        # 相対 href/routing 属性の解決基準に合わせ、explore の base_url は landed_url
        # （リダイレクト後）を渡す（Codex #104 P1）。
        engine = self._engine(
            "http://fixture.test/", depth=1, allow_state_changing_probes=True
        )
        b = _RedirectRecordingSpaBrowser()
        engine._browser = b

        await engine._phase_crawl()

        self.assertTrue(engine.spa_crawl)
        self.assertEqual(b.explore_base, "http://fixture.test/landed")

    async def test_settle_redirect_refreshes_landed_url_and_blocks_explore(self):
        # settle 中の client-side redirect で out-of-scope へ移ったら、landed_url を採り直して
        # explore ガードで弾く（古い in-scope 値でクリック探索しない・Codex #104 P1）。
        engine = self._engine(
            "http://fixture.test/", depth=1, allow_state_changing_probes=True
        )
        b = _SettleRedirectSpaBrowser()
        engine._browser = b

        await engine._phase_crawl()

        self.assertTrue(engine.spa_crawl)  # redirect 前に検出・有効化される
        self.assertEqual(b.explore_calls, 0)  # landed が out-of-scope なので探索しない

    async def test_settle_redirect_out_of_scope_skips_iteration(self):
        # settle 中に out-of-scope へリダイレクトしたら、外部ドキュメントを CrawledPage
        # として保存せず、そのイテレーションを中断する（Codex #104 P2）。
        engine = self._engine(
            "http://fixture.test/", depth=1, allow_state_changing_probes=True
        )
        engine._browser = _SettleRedirectSpaBrowser()

        pages = await engine._phase_crawl()

        target = engine.target_url.rstrip("/")
        self.assertFalse(
            any(p.url.rstrip("/") == target for p in pages)
        )

    async def test_active_spa_out_of_scope_landing_skips_iteration(self):
        # SPA モード有効時（明示 --spa-crawl 含む）は、検出イテレーションに限らず、
        # navigate 内 settle で out-of-scope へ出た全ページで外部ドキュメントを保存しない
        # （Codex #104 P2）。
        engine = self._engine("http://fixture.test/", depth=1, spa_crawl=True)
        engine._browser = _ExternalRedirectSpaBrowser()

        pages = await engine._phase_crawl()

        target = engine.target_url.rstrip("/")
        self.assertFalse(any(p.url.rstrip("/") == target for p in pages))

    def test_access_scope_allows_query_and_fragment_on_path_target(self):
        # path-scoped target に対し同一パスの ?query / #fragment は access 許可する
        # （pagination/hash ルート探索を落とさない・Codex #104 P2）。
        engine = self._engine("http://fixture.test/", depth=1)
        engine.target_urls = ["http://fixture.test/catalog"]
        self.assertTrue(engine._is_access_allowed_url("http://fixture.test/catalog?page=2"))
        self.assertTrue(engine._is_access_allowed_url("http://fixture.test/catalog#details"))
        # 別パスは許可しない。
        self.assertFalse(engine._is_access_allowed_url("http://fixture.test/other"))

    def test_access_scope_query_target_allows_fragment_variant(self):
        # query 付きで明示スコープした target の fragment 付き変種は許可（fragment は
        # サーバに送られない）。別 query は許可しない（Codex #104 P2）。
        engine = self._engine("http://fixture.test/", depth=1)
        engine.target_urls = ["http://fixture.test/action?op=save"]
        self.assertTrue(
            engine._is_access_allowed_url("http://fixture.test/action?op=save#details")
        )
        self.assertFalse(
            engine._is_access_allowed_url("http://fixture.test/action?op=delete")
        )

    async def test_out_of_scope_landing_does_not_auto_enable_spa(self):
        # in-scope URL が access スコープ外の外部 SPA へリダイレクトしたら、
        # マーカーがあっても自動有効化しない（外部ページを探索しない・Codex #104 P1）。
        engine = self._engine(depth=1)
        engine._browser = _ExternalRedirectSpaBrowser()

        await engine._phase_crawl()

        self.assertFalse(engine.spa_crawl)

    def test_page_fingerprint_is_origin_aware(self):
        # 別 origin の構造的に同一なページは別 fingerprint（重複スキップで落とさない・Codex #104 P1）。
        html = "<html><body><app-root></app-root><form><input name='q'></form></body></html>"
        fp_a = ScanEngine._page_fingerprint(html, "https://a.example/")
        fp_b = ScanEngine._page_fingerprint(html, "https://b.example/")
        self.assertNotEqual(fp_a, fp_b)
        # scheme も含める（同一ホストの HTTP/HTTPS アプリを区別・Codex #104 P2）。
        fp_http = ScanEngine._page_fingerprint(html, "http://a.example/")
        fp_https = ScanEngine._page_fingerprint(html, "https://a.example/")
        self.assertNotEqual(fp_http, fp_https)

    async def test_auto_spa_json_body_harvest_gated_on_probe_opt_in(self):
        # 自動有効化（既定 read-only）では非GET body の harvest→再送を行わない。
        # 明示 opt-in（allow_state_changing_probes）でのみ json_injection_points を積む（Codex #104 P1）。
        json_pair = {
            "request": {
                "method": "POST",
                "url": "http://fixture.test/api/save",
                "post_data": '{"note":"x"}',
                "headers": {"content-type": "application/json"},
            }
        }

        engine = self._engine(depth=1)
        b = _SpaMarkerCrawlBrowser()
        b.network = SimpleNamespace(allowed_hosts=None, pairs=[json_pair])
        engine._browser = b
        await engine._phase_crawl()
        self.assertTrue(engine.spa_crawl)
        self.assertEqual(engine.json_injection_points, [])

        engine2 = self._engine(depth=1, allow_state_changing_probes=True)
        b2 = _SpaMarkerCrawlBrowser()
        b2.network = SimpleNamespace(allowed_hosts=None, pairs=[json_pair])
        engine2._browser = b2
        await engine2._phase_crawl()
        self.assertTrue(engine2.spa_crawl)
        self.assertGreaterEqual(len(engine2.json_injection_points), 1)

    async def test_normal_first_page_never_auto_enables_spa_crawl(self):
        engine = self._engine(depth=1)
        browser = _FakeCrawlBrowser()
        engine._browser = browser

        await engine._phase_crawl()

        self.assertFalse(engine.spa_crawl)
        self.assertFalse(browser.spa_settle)

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

    async def test_postauth_landing_recorded_before_abort_at_first_wait(self):
        # 初回 post-auth ナビが成功した直後、BFS ループ先頭の abort でループ内 navigate に
        # 到達しなくても、実際に読めたランディングが reached に残る（Codex #102 P2）。
        from wscan.intervention import AbortScan

        engine = self._engine("http://fixture.test/private", depth=1)
        engine._browser = _FakeCrawlBrowser()

        async def _abort_immediately():
            raise AbortScan("Scan aborted by operator")

        engine.controller.wait_if_paused_or_abort = _abort_immediately

        with self.assertRaises(AbortScan):
            await engine._phase_crawl_postauth()

        self.assertIn("http://fixture.test/private", engine.reached_urls)
        self.assertEqual(engine.coverage_summary()["unreached"], [])

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
