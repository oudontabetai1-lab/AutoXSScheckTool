"""component_intel（EOL 照会）の単体テスト。

純粋関数（ヘッダ解析・cycle 一致・EOL 判定）はネットワーク非依存で検証し、ネットワーク層と
scanner は fake client / monkeypatch で外部 API を叩かずに検証する。
"""
import datetime as dt
import types
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


class ParseJsLibrariesTests(unittest.TestCase):
    def test_cdn_patterns(self):
        html = (
            '<script src="https://cdn.jsdelivr.net/npm/jquery@3.4.1/dist/jquery.min.js"></script>'
            '<script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.10/lodash.min.js"></script>'
            '<script src="https://unpkg.com/vue@2.6.10/dist/vue.js"></script>'
            '<script src="/assets/angular-1.7.2.min.js"></script>'
        )
        libs = {(l.name, l.version) for l in ci.parse_js_libraries(html, "https://t.example/")}
        self.assertIn(("jquery", "3.4.1"), libs)
        self.assertIn(("lodash.js", "4.17.10"), libs)
        self.assertIn(("vue", "2.6.10"), libs)
        self.assertIn(("angular", "1.7.2"), libs)
        self.assertTrue(all(l.ecosystem == "npm" for l in ci.parse_js_libraries(html, "https://t.example/")))

    def test_no_version_and_dedup(self):
        html = (
            '<script src="https://example.com/app.js"></script>'  # version 無し→無視
            '<script src="https://cdn.jsdelivr.net/npm/jquery@3.4.1/x.js"></script>'
            '<script src="https://cdn.jsdelivr.net/npm/jquery@3.4.1/y.js"></script>'  # 重複
        )
        libs = ci.parse_js_libraries(html, "https://t.example/")
        self.assertEqual([(l.name, l.version) for l in libs], [("jquery", "3.4.1")])


class SummarizeOsvTests(unittest.TestCase):
    def test_summary_extracts_ids_cves_and_max_severity(self):
        vulns = [
            {"id": "GHSA-a", "aliases": ["CVE-2020-11022"], "summary": "XSS in jQuery",
             "database_specific": {"severity": "MODERATE"}},
            {"id": "GHSA-b", "aliases": ["CVE-2020-11023", "CVE-2020-11022"],
             "database_specific": {"severity": "HIGH"}},
        ]
        s = ci.summarize_osv_vulns(vulns)
        self.assertEqual(s["ids"], ["GHSA-a", "GHSA-b"])
        self.assertEqual(s["cves"], ["CVE-2020-11022", "CVE-2020-11023"])  # 重複排除
        self.assertEqual(s["max_severity"], "HIGH")
        self.assertEqual(s["summary"], "XSS in jQuery")


class NvdPureTests(unittest.TestCase):
    def test_cpe_map(self):
        self.assertEqual(ci.nvd_product_cpe("nginx"), "cpe:2.3:a:f5:nginx")
        self.assertEqual(ci.nvd_product_cpe("httpd"), "cpe:2.3:a:apache:http_server")
        self.assertIsNone(ci.nvd_product_cpe("wordpress"))  # NVD 対象外（保守側）

    def test_summarize_nvd(self):
        data = {"totalResults": 2, "vulnerabilities": [
            {"cve": {"id": "CVE-2021-1", "metrics": {"cvssMetricV31": [
                {"cvssData": {"baseSeverity": "HIGH"}}]}}},
            {"cve": {"id": "CVE-2021-2", "metrics": {"cvssMetricV31": [
                {"cvssData": {"baseSeverity": "CRITICAL"}}]}}},
        ]}
        s = ci.summarize_nvd(data)
        self.assertEqual(s["total"], 2)
        self.assertEqual(s["cve_ids"], ["CVE-2021-1", "CVE-2021-2"])
        self.assertEqual(s["max_severity"], "CRITICAL")


class _FakeResp:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class _FakeClient:
    """httpx.AsyncClient の最小ダブル（get/post を記録し canned JSON を返す）。"""

    def __init__(self, mapping=None, post_result=None):
        self._mapping = mapping or {}
        self._post_result = post_result  # (status, payload)
        self.calls = []
        self.posts = []

    async def get(self, url, timeout=None, params=None, headers=None):
        self.calls.append(url)
        self.last_get = {"params": params, "headers": headers}
        status, payload = self._mapping.get(url, (404, None))
        return _FakeResp(status, payload)

    async def post(self, url, json=None, timeout=None):
        self.posts.append((url, json))
        status, payload = self._post_result or (404, None)
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

    async def test_lookup_osv_returns_vulns(self):
        client = _FakeClient(post_result=(200, {"vulns": [
            {"id": "GHSA-x", "aliases": ["CVE-2020-11022"],
             "database_specific": {"severity": "MODERATE"}},
        ]}))
        vulns = await ci.lookup_osv("npm", "jquery", "3.4.1", client=client)
        self.assertEqual(len(vulns), 1)
        # 送信は package 名+version+ecosystem のみ（target 情報を含めない）。
        self.assertEqual(client.posts[0][1],
                         {"version": "3.4.1", "package": {"name": "jquery", "ecosystem": "npm"}})

    async def test_lookup_osv_no_vulns_vs_failure(self):
        ok = _FakeClient(post_result=(200, {"vulns": []}))
        self.assertEqual(await ci.lookup_osv("npm", "jquery", "3.99.0", client=ok), [])
        # 一時失敗（5xx）は例外を投げる（黙って None にせず observability/非キャッシュへ回す）。
        bad = _FakeClient(post_result=(500, None))
        with self.assertRaises(ci.ComponentIntelUnavailable):
            await ci.lookup_osv("npm", "jquery", "3.4.1", client=bad)

    async def test_lookup_nvd_with_and_without_key(self):
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        payload = {"totalResults": 1, "vulnerabilities": [
            {"cve": {"id": "CVE-2019-9511", "metrics": {"cvssMetricV31": [
                {"cvssData": {"baseSeverity": "HIGH"}}]}}}]}
        # API キーあり → apiKey ヘッダを送る。
        c1 = _FakeClient({url: (200, payload)})
        out = await ci.lookup_nvd("nginx", "1.18.0", api_key="KEY123", client=c1)
        self.assertEqual(out["total"], 1)
        self.assertEqual(c1.last_get["headers"], {"apiKey": "KEY123"})
        self.assertEqual(c1.last_get["params"]["cpeName"], "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*")
        # API キーなし → ヘッダ None でも動作。
        c2 = _FakeClient({url: (200, payload)})
        out2 = await ci.lookup_nvd("nginx", "1.18.0", client=c2)
        self.assertEqual(out2["total"], 1)
        self.assertIsNone(c2.last_get["headers"])

    async def test_lookup_nvd_unmapped_product_skips(self):
        c = _FakeClient({})
        self.assertIsNone(await ci.lookup_nvd("wordpress", "6.1", client=c))
        self.assertEqual(c.calls, [])


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

    async def test_reports_vulnerable_js_library(self):
        engine, scanner = self._scanner(enabled=True)
        html = '<script src="https://cdn.jsdelivr.net/npm/jquery@3.4.1/jquery.min.js"></script>'

        async def _pair(url):
            return {"request": {"url": url},
                    "response": {"status": 200, "headers": {}, "body": html}}

        async def _osv(ecosystem, name, version, **kw):
            return [{"id": "GHSA-x", "aliases": ["CVE-2020-11022"],
                     "summary": "XSS in jQuery", "database_specific": {"severity": "MODERATE"}}]

        recorded = []

        async def _rec(**kw):
            recorded.append(kw)
            return object()

        scanner._response_pair = _pair
        scanner.record_finding = _rec
        import wscan.component_intel as _ci
        orig = _ci.lookup_osv
        _ci.lookup_osv = _osv
        try:
            out = await scanner.scan_page("http://x/")
        finally:
            _ci.lookup_osv = orig
        self.assertEqual(len(out), 1)
        self.assertEqual(recorded[0]["evidence_type"], "vulnerable_library")
        self.assertEqual(recorded[0]["evidence_details"]["library"], "jquery")
        self.assertIn("CVE-2020-11022", recorded[0]["evidence_details"]["cves"])
        self.assertEqual(recorded[0]["severity"], "medium")  # MODERATE→medium

    async def test_reports_eol_cms(self):
        # クロールで検出した CMS（detected_cms）も EOL 照会対象にする。
        engine, scanner = self._scanner(enabled=True)

        class _Cms:
            name = "drupal"
            version = "7"
            is_known = True

        engine.detected_cms = _Cms()
        # CMS は検出元 origin と一致する URL でだけ付与される（cross-origin 誤検知防止）。
        from wscan.scanners.outdated_components import _origin_of
        engine._cms_origin = _origin_of("http://x/")

        async def _pair(url):
            return {"request": {"url": url}, "response": {"status": 200, "headers": {}, "body": ""}}

        async def _check(comp, **kw):
            if comp.source == "cms":
                return {"product": comp.product, "version": comp.version, "source": "cms",
                        "slug": "drupal", "cycle": "7", "eol": True, "is_eol": True, "latest": "11"}
            return None

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
        self.assertEqual(recorded[0]["evidence_details"]["source"], "cms")
        self.assertIn("CMS 検出", recorded[0]["evidence"])

    async def test_nvd_advisory_when_enabled(self):
        cfg = {"enabled": True, "eol_base_url": "https://endoflife.date",
               "osv_base_url": "https://api.osv.dev", "nvd_enabled": True,
               "nvd_base_url": "https://services.nvd.nist.gov", "timeout": 8}
        engine = _FakeEngine(component_intel=cfg)
        scanner = SCANNERS["outdated_components"](engine)

        async def _pair(url):
            return {"request": {"url": url},
                    "response": {"status": 200, "headers": {"Server": "nginx/1.18.0"}, "body": ""}}

        async def _eol(comp, **kw):
            return None  # EOL は別経路（ここでは無し）

        async def _nvd(product, version, **kw):
            return {"total": 6, "cve_ids": ["CVE-2019-9511"], "max_severity": "HIGH"}

        recorded = []

        async def _rec(**kw):
            recorded.append(kw)
            return object()

        scanner._response_pair = _pair
        scanner.record_finding = _rec
        import wscan.component_intel as _ci
        oe, on = _ci.check_component_eol, _ci.lookup_nvd
        _ci.check_component_eol, _ci.lookup_nvd = _eol, _nvd
        try:
            out = await scanner.scan_page("http://x/")
        finally:
            _ci.check_component_eol, _ci.lookup_nvd = oe, on
        adv = [r for r in recorded if r["evidence_type"] == "known_cve_advisory"]
        self.assertEqual(len(adv), 1)
        self.assertEqual(adv[0]["severity"], "low")  # 参考情報
        self.assertEqual(adv[0]["evidence_details"]["cve_count"], 6)

    async def test_nvd_skipped_when_disabled(self):
        # nvd_enabled=False（既定）なら NVD 照会しない。
        engine, scanner = self._scanner(enabled=True)  # nvd_enabled 未設定

        async def _pair(url):
            return {"request": {"url": url},
                    "response": {"status": 200, "headers": {"Server": "nginx/1.18.0"}, "body": ""}}

        async def _eol(comp, **kw):
            return None

        called = {"nvd": 0}

        async def _nvd(*a, **k):
            called["nvd"] += 1
            return {"total": 1, "cve_ids": [], "max_severity": ""}

        scanner._response_pair = _pair
        scanner.record_finding = lambda **kw: None
        import wscan.component_intel as _ci
        oe, on = _ci.check_component_eol, _ci.lookup_nvd
        _ci.check_component_eol, _ci.lookup_nvd = _eol, _nvd
        try:
            await scanner.scan_page("http://x/")
        finally:
            _ci.check_component_eol, _ci.lookup_nvd = oe, on
        self.assertEqual(called["nvd"], 0)

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

    async def test_cms_not_applied_cross_origin(self):
        # 検出元 origin と異なる URL では CMS を EOL 照会対象にしない（cross-origin 誤検知防止）。
        engine, scanner = self._scanner(enabled=True)

        class _Cms:
            name = "drupal"
            version = "7"
            is_known = True

        engine.detected_cms = _Cms()
        engine._cms_origin = "http://a.test"  # 検出は a.test

        async def _pair(url):
            return {"request": {"url": url}, "response": {"status": 200, "headers": {}, "body": ""}}

        called = {"eol": 0}

        async def _check(comp, **kw):
            called["eol"] += 1
            return None

        scanner._response_pair = _pair
        scanner.record_finding = lambda **kw: None
        import wscan.component_intel as _ci
        orig = _ci.check_component_eol
        _ci.check_component_eol = _check
        try:
            out = await scanner.scan_page("http://b.test/page")  # 走査は b.test
        finally:
            _ci.check_component_eol = orig
        self.assertEqual(out, [])
        self.assertEqual(called["eol"], 0)  # CMS が付与されず照会も起きない

    async def test_transient_pair_records_note_and_not_marked(self):
        # 空 pair（transient）は note を残し checked にしない（黙った偽陰性防止・再試行余地）。
        engine, scanner = self._scanner(enabled=True)

        async def _pair(url):
            return {}  # transient（408/429/5xx）

        scanner._response_pair = _pair
        out = await scanner.scan_page("http://x/")
        self.assertEqual(out, [])
        self.assertTrue(any("page_unavailable" in n for n in engine.wave_errors))
        self.assertNotIn("http://x/", scanner._checked_urls)

    async def test_filename_derived_library_is_tentative(self):
        engine, scanner = self._scanner(enabled=True)
        # 任意 origin のファイル名推測（CDN でない）。
        html = '<script src="/assets/jquery-3.4.1.min.js"></script>'

        async def _pair(url):
            return {"request": {"url": url},
                    "response": {"status": 200, "headers": {}, "body": html}}

        async def _osv(ecosystem, name, version, **kw):
            return [{"id": "GHSA-x", "aliases": ["CVE-2020-11022"],
                     "database_specific": {"severity": "MODERATE"}}]

        recorded = []

        async def _rec(**kw):
            recorded.append(kw)
            return object()

        scanner._response_pair = _pair
        scanner.record_finding = _rec
        import wscan.component_intel as _ci
        orig = _ci.lookup_osv
        _ci.lookup_osv = _osv
        try:
            out = await scanner.scan_page("http://x/")
        finally:
            _ci.lookup_osv = orig
        self.assertEqual(len(out), 1)
        self.assertEqual(recorded[0]["confidence"], "tentative")


class CvssAndSeverityTests(unittest.TestCase):
    def test_cvss3_known_vectors(self):
        # CVSS 3.1 仕様例: 9.8 Critical。
        self.assertEqual(ci.cvss3_base_severity(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), "CRITICAL")
        # 6.1 Medium（反射 XSS 典型・Scope Changed）。
        self.assertEqual(ci.cvss3_base_severity(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), "MEDIUM")
        # None 影響。
        self.assertEqual(ci.cvss3_base_severity(
            "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"), "NONE")

    def test_cvss3_garbage(self):
        self.assertEqual(ci.cvss3_base_severity(""), "")
        self.assertEqual(ci.cvss3_base_severity("not-a-vector"), "")
        self.assertEqual(ci.cvss3_base_severity("CVSS:3.1/AV:X"), "")

    def test_osv_toplevel_severity_fallback(self):
        # database_specific 無し・top-level CVSS ベクタから深刻度を導く。
        vulns = [{"id": "CVE-x", "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}]
        out = ci.summarize_osv_vulns(vulns)
        self.assertEqual(out["max_severity"], "CRITICAL")

    def test_osv_database_specific_takes_priority(self):
        vulns = [{"id": "GHSA-y", "database_specific": {"severity": "LOW"}}]
        self.assertEqual(ci.summarize_osv_vulns(vulns)["max_severity"], "LOW")


class CdnReliabilityTests(unittest.TestCase):
    def test_known_cdn_host_is_cdn(self):
        libs = ci.parse_js_libraries_from_urls(
            ["https://cdn.jsdelivr.net/npm/jquery@3.4.1/dist/jquery.min.js"])
        self.assertEqual(len(libs), 1)
        self.assertEqual(libs[0].reliability, "cdn")

    def test_self_hosted_npm_layout_is_filename(self):
        # 自己ホストが /npm/name@ver レイアウトを模しても cdn 扱いにしない（任意コードを含み得る）。
        libs = ci.parse_js_libraries_from_urls(
            ["https://app.test/npm/jquery@3.4.1/app.js"])
        self.assertEqual(len(libs), 1)
        self.assertEqual(libs[0].reliability, "filename")

    def test_filename_pattern_is_filename(self):
        libs = ci.parse_js_libraries_from_urls(["https://app.test/assets/jquery-3.4.1.min.js"])
        self.assertEqual(libs[0].reliability, "filename")

    def test_multiple_versions_all_kept(self):
        libs = ci.parse_js_libraries_from_urls([
            "https://cdn.jsdelivr.net/npm/jquery@3.4.1/jquery.min.js",
            "https://cdn.jsdelivr.net/npm/jquery@3.6.0/jquery.min.js",
        ])
        versions = sorted(l.version for l in libs)
        self.assertEqual(versions, ["3.4.1", "3.6.0"])


class ScanPageContextTests(unittest.IsolatedAsyncioTestCase):
    async def test_external_scripts_beyond_truncation_detected(self):
        # 50KB 打ち切り本文には無いが external_scripts に捕捉された lib を検出する（Codex #155）。
        cfg = {"enabled": True, "eol_base_url": "https://endoflife.date",
               "osv_base_url": "https://api.osv.dev", "timeout": 8}
        engine = _FakeEngine(component_intel=cfg)
        scanner = SCANNERS["outdated_components"](engine)

        async def _pair(url):
            return {"request": {"url": url},
                    "response": {"status": 200, "headers": {}, "body": "x" * 10}}

        async def _osv(ecosystem, name, version, **kw):
            return [{"id": "GHSA-x", "aliases": ["CVE-2020-11022"],
                     "database_specific": {"severity": "MODERATE"}}]

        recorded = []

        async def _rec(**kw):
            recorded.append(kw)
            return object()

        scanner._response_pair = _pair
        scanner.record_finding = _rec
        page = types.SimpleNamespace(
            url="http://x/", html="<html>truncated body without the script</html>",
            external_scripts={"https://cdn.jsdelivr.net/npm/jquery@3.4.1/jquery.min.js": "..."})
        import wscan.component_intel as _ci
        orig = _ci.lookup_osv
        _ci.lookup_osv = _osv
        try:
            out = await scanner.scan_page_context(page)
        finally:
            _ci.lookup_osv = orig
        self.assertEqual(len(out), 1)
        self.assertEqual(recorded[0]["evidence_details"]["library"], "jquery")
        self.assertIn("@3.4.1", recorded[0]["field_name"])  # 版を identity に含む
        self.assertGreater(recorded[0]["cvss_score"], 0)  # severity 整合 CVSS


class CliChecksTests(unittest.TestCase):
    def test_checks_outdated_components_is_accepted(self):
        import sys
        from unittest import mock
        import main as m
        argv = ["p", "scan", "http://x.test", "--checks", "outdated_components", "--no-monitor"]
        with mock.patch.object(sys, "argv", argv):
            args = m.parse_args()
        self.assertIn("outdated_components", args.checks)


if __name__ == "__main__":
    unittest.main()
