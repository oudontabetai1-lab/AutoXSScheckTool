"""component_intel（EOL 照会）の単体テスト。

純粋関数（ヘッダ解析・cycle 一致・EOL 判定）はネットワーク非依存で検証し、ネットワーク層と
scanner は fake client / monkeypatch で外部 API を叩かずに検証する。
"""
import datetime as dt
import unittest

from wscan import component_intel as ci
from wscan.scanners import SCANNERS


class ParseComponentsTests(unittest.TestCase):
    def test_server_and_powered_by_banners(self):
        comps = ci.parse_components_from_headers({
            "Server": "nginx/1.18.0",
            "X-Powered-By": "PHP/7.4.3",
        })
        got = {(c.product, c.version, c.source) for c in comps}
        self.assertIn(("nginx", "1.18.0", "server"), got)
        self.assertIn(("php", "7.4.3", "x-powered-by"), got)

    def test_apache_with_extra_tokens(self):
        comps = ci.parse_components_from_headers({"Server": "Apache/2.4.29 (Ubuntu)"})
        self.assertEqual((comps[0].product, comps[0].version), ("apache", "2.4.29"))

    def test_x_aspnet_version_and_generator(self):
        comps = ci.parse_components_from_headers({
            "X-AspNet-Version": "4.0.30319",
            "X-Generator": "Drupal 7 (https://www.drupal.org)",
        })
        got = {(c.product, c.version) for c in comps}
        self.assertIn(("asp.net", "4.0.30319"), got)
        self.assertIn(("drupal", "7"), got)

    def test_banner_without_version_is_ignored(self):
        # バージョンを伴わないバナーは照会不能なので返さない。
        self.assertEqual(ci.parse_components_from_headers({"X-Powered-By": "ASP.NET"}), [])

    def test_dedup(self):
        comps = ci.parse_components_from_headers({"Server": "nginx/1.18.0, nginx/1.18.0"})
        self.assertEqual(len(comps), 1)


class SlugAndCycleTests(unittest.TestCase):
    def test_slug_mapping(self):
        self.assertEqual(ci.eol_product_slug("PHP"), "php")
        self.assertEqual(ci.eol_product_slug("httpd"), "apache")
        self.assertIsNone(ci.eol_product_slug("iis"))       # 除外
        self.assertIsNone(ci.eol_product_slug("unknownsw"))  # 未対応

    def test_match_cycle_picks_most_specific(self):
        cycles = [{"cycle": "7"}, {"cycle": "7.4"}, {"cycle": "8.0"}]
        self.assertEqual(ci.match_cycle(cycles, "7.4.3")["cycle"], "7.4")
        self.assertEqual(ci.match_cycle(cycles, "7")["cycle"], "7")
        self.assertIsNone(ci.match_cycle(cycles, "9.1.0"))

    def test_evaluate_eol_variants(self):
        today = dt.date(2026, 9, 9)
        self.assertTrue(ci.evaluate_eol({"eol": True}, today))
        self.assertFalse(ci.evaluate_eol({"eol": False}, today))
        self.assertTrue(ci.evaluate_eol({"eol": "2022-11-28"}, today))   # 過去=EOL
        self.assertFalse(ci.evaluate_eol({"eol": "2099-01-01"}, today))  # 未来=サポート中
        self.assertIsNone(ci.evaluate_eol({}, today))                    # 欠落=不明
        self.assertIsNone(ci.evaluate_eol({"eol": "not-a-date"}, today))


class _FakeResp:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class _FakeClient:
    """httpx.AsyncClient の最小ダブル（get(url, timeout=) を記録し canned JSON を返す）。"""

    def __init__(self, mapping):
        self._mapping = mapping
        self.calls = []

    async def get(self, url, timeout=None):
        self.calls.append(url)
        status, payload = self._mapping.get(url, (404, None))
        return _FakeResp(status, payload)


class NetworkLayerTests(unittest.IsolatedAsyncioTestCase):
    async def test_check_component_eol_reports_eol(self):
        client = _FakeClient({
            "https://endoflife.date/api/php.json": (200, [
                {"cycle": "8.3", "eol": "2027-12-31", "latest": "8.3.1"},
                {"cycle": "7.4", "eol": "2022-11-28", "latest": "7.4.33"},
            ]),
        })
        comp = ci.Component("php", "7.4.3", "x-powered-by")
        out = await ci.check_component_eol(
            comp, today=dt.date(2026, 9, 9), client=client,
        )
        self.assertIsNotNone(out)
        self.assertTrue(out["is_eol"])
        self.assertEqual(out["cycle"], "7.4")
        self.assertEqual(out["latest"], "7.4.33")
        # 外部へ送るのは product slug のみ（URL に version/target を含めない）。
        self.assertEqual(client.calls, ["https://endoflife.date/api/php.json"])

    async def test_supported_version_returns_none(self):
        client = _FakeClient({
            "https://endoflife.date/api/php.json": (200, [
                {"cycle": "8.3", "eol": "2027-12-31", "latest": "8.3.1"},
            ]),
        })
        out = await ci.check_component_eol(
            ci.Component("php", "8.3.0", "server"), today=dt.date(2026, 9, 9), client=client,
        )
        # サポート中は判定確定なので dict を返すが is_eol=False（scanner 側で報告しない）。
        self.assertIsNotNone(out)
        self.assertFalse(out["is_eol"])

    async def test_unknown_product_returns_none(self):
        # 未対応 slug は照会せず None（判定不能）。
        client = _FakeClient({})
        out = await ci.check_component_eol(
            ci.Component("unknownsw", "1.0", "server"), client=client,
        )
        self.assertIsNone(out)
        self.assertEqual(client.calls, [])  # 照会自体しない

    async def test_api_failure_is_graceful(self):
        client = _FakeClient({})  # 全 404
        out = await ci.check_component_eol(
            ci.Component("php", "7.4.3", "server"), client=client,
        )
        self.assertIsNone(out)  # raise せず None


class _FakeEngine:
    def __init__(self, component_intel=None):
        self.component_intel = component_intel
        self.browser = None
        self.monitor = None
        self.payload_gen = None
        self.wave_errors = []


class OutdatedComponentScannerTests(unittest.IsolatedAsyncioTestCase):
    def _scanner(self, enabled=True):
        cfg = {"enabled": enabled, "eol_base_url": "https://endoflife.date", "timeout": 8}
        engine = _FakeEngine(component_intel=cfg)
        return engine, SCANNERS["outdated_components"](engine)

    async def test_disabled_is_inert(self):
        engine, scanner = self._scanner(enabled=False)
        self.assertEqual(await scanner.scan_page("http://x/"), [])

    async def test_reports_eol_component(self):
        engine, scanner = self._scanner(enabled=True)

        async def _pair(url):
            return {"request": {"url": url},
                    "response": {"status": 200, "headers": {"Server": "nginx/1.18.0"}}}

        async def _check(comp, **kw):
            return {"product": comp.product, "version": comp.version, "source": comp.source,
                    "slug": "nginx", "cycle": "1.18", "eol": "2021-04-01", "is_eol": True,
                    "latest": "1.27.0"}

        recorded = []

        async def _rec(**kw):
            recorded.append(kw)
            return object()

        scanner._response_pair = _pair
        scanner.record_finding = _rec
        import wscan.component_intel as _ci
        orig = _ci.check_component_eol
        _ci.check_component_eol = _check
        try:
            out = await scanner.scan_page("http://x/")
        finally:
            _ci.check_component_eol = orig
        self.assertEqual(len(out), 1)
        self.assertEqual(recorded[0]["evidence_type"], "eol_component")
        self.assertEqual(recorded[0]["evidence_details"]["product"], "nginx")

    async def test_supported_component_yields_no_finding(self):
        engine, scanner = self._scanner(enabled=True)

        async def _pair(url):
            return {"request": {"url": url},
                    "response": {"status": 200, "headers": {"Server": "nginx/1.27.0"}}}

        async def _check(comp, **kw):
            return None  # サポート中/不明

        scanner._response_pair = _pair
        import wscan.component_intel as _ci
        orig = _ci.check_component_eol
        _ci.check_component_eol = _check
        try:
            out = await scanner.scan_page("http://x/")
        finally:
            _ci.check_component_eol = orig
        self.assertEqual(out, [])


if __name__ == "__main__":
    unittest.main()
