import unittest

from wscan.spa_harvest import harvest_get_targets, looks_like_spa_shell


def _pair(url: str, method: str = "GET") -> dict:
    return {
        "request": {"url": url, "method": method},
        "response": {"url": url, "status": 200},
    }


class HarvestGetTargetsTests(unittest.TestCase):
    def test_harvests_same_netloc_get_with_query_params(self):
        targets = harvest_get_targets(
            [_pair("http://fixture.test/rest/products/search?q=x&cat=1")],
            base_netlocs={"fixture.test"},
        )

        self.assertEqual(targets, [{
            "url": "http://fixture.test/rest/products/search?q=x&cat=1",
            "endpoint": "http://fixture.test/rest/products/search",
            "params": ["q", "cat"],
            "depth_hint": 0,
        }])

    def test_excludes_out_of_scope_post_queryless_and_static_assets(self):
        pairs = [
            _pair("/rest/products/search?q=x"),
            _pair("https://other.test/rest/products/search?q=x"),
            _pair("http://fixture.test/rest/products/search?q=x", method="POST"),
            _pair("http://fixture.test/rest/products/search"),
            _pair("http://fixture.test/static/app.js?v=1"),
            _pair("http://fixture.test/static/theme.css?v=1"),
        ]

        self.assertEqual(
            harvest_get_targets(pairs, base_netlocs={"fixture.test"}),
            [],
        )

    def test_deduplicates_same_endpoint_and_param_set_keeping_first_values(self):
        pairs = [
            _pair("http://fixture.test/api/search?q=x&cat=1#results"),
            _pair("http://fixture.test/api/search?cat=2&q=y&q=z"),
        ]

        targets = harvest_get_targets(pairs, base_netlocs={"fixture.test"})

        self.assertEqual(targets, [{
            "url": "http://fixture.test/api/search?q=x&cat=1",
            "endpoint": "http://fixture.test/api/search",
            "params": ["q", "cat"],
            "depth_hint": 0,
        }])

    def test_keeps_json_api_and_caps_unique_params(self):
        query = "&".join(["=ignored", *[f"p{i}=x" for i in range(35)]])

        targets = harvest_get_targets(
            [_pair(f"http://fixture.test/api/data.json?{query}")],
            base_netlocs={"fixture.test"},
        )

        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["params"], [f"p{i}" for i in range(30)])

    def test_accepts_configured_cross_origin_attack_scope(self):
        # app.example が別オリジン api.example の API を叩き、両方が攻撃スコープなら拾う。
        pairs = [
            _pair("http://api.example/rest/search?q=x"),
            _pair("http://analytics.example/collect?id=1"),  # 対象外 netloc
        ]

        targets = harvest_get_targets(
            pairs, base_netlocs={"app.example", "api.example"}
        )

        self.assertEqual(targets, [{
            "url": "http://api.example/rest/search?q=x",
            "endpoint": "http://api.example/rest/search",
            "params": ["q"],
            "depth_hint": 0,
        }])


class LooksLikeSpaShellTests(unittest.TestCase):
    def test_empty_app_root_is_shell(self):
        self.assertTrue(looks_like_spa_shell(
            "<html><body><app-root></app-root><script>boot()</script></body></html>"
        ))

    def test_empty_react_root_is_shell(self):
        self.assertTrue(looks_like_spa_shell(
            '<html><body><div id="root"></div></body></html>'
        ))

    def test_rendered_spa_with_normal_content_is_not_shell(self):
        rendered = (
            "<html><body><app-root><main>"
            "Products are ready. Browse the catalog and choose an item to inspect."
            "</main></app-root></body></html>"
        )
        self.assertFalse(looks_like_spa_shell(rendered))

    def test_empty_and_regular_html_are_not_shells(self):
        self.assertFalse(looks_like_spa_shell(""))
        self.assertFalse(looks_like_spa_shell("<html><body>Regular page</body></html>"))


if __name__ == "__main__":
    unittest.main()
