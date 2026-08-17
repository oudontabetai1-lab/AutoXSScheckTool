import json
import unittest

from wscan.spa_harvest import (
    harvest_get_targets,
    harvest_json_body_targets,
    looks_like_spa_shell,
)


def _pair(url: str, method: str = "GET") -> dict:
    return {
        "request": {"url": url, "method": method},
        "response": {"url": url, "status": 200},
    }


def _json_pair(
    url: str,
    body,
    method: str = "POST",
    headers: dict | None = None,
) -> dict:
    return {
        "request": {
            "url": url,
            "method": method,
            "post_data": body if isinstance(body, str) else json.dumps(body),
            "headers": headers or {},
        },
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


class HarvestJsonBodyTargetsTests(unittest.TestCase):
    def test_harvests_methods_normalizes_urls_and_filters_headers(self):
        pairs = [
            _json_pair(
                "https://api.test/v1/users?dry_run=1#form",
                {"profile": {"email": "a@test"}, "roles": ["user", 2]},
                method="post",
                headers={
                    "Content-Type": "application/json; charset=utf-8",
                    "Authorization": "Bearer secret",
                    "cookie": "sid=secret",
                    "X-Api-Key": "secret",
                    "X-Auth-Token": "secret",
                    "X-Access-Token": "secret",
                    "Proxy-Authorization": "secret",
                    "Content-Length": "99",
                    "Host": "api.test",
                    "X-Tenant": "acme",
                },
            ),
            _json_pair("https://api.test/v1/users/1", {"active": True}, method="PUT"),
            _json_pair("https://api.test/v1/users/1", {"name": None}, method="PATCH"),
        ]

        targets = harvest_json_body_targets(pairs, base_netlocs="api.test")

        self.assertEqual([target["method"] for target in targets], ["POST", "PUT", "PATCH"])
        self.assertEqual(targets[0]["url"], "https://api.test/v1/users?dry_run=1")
        self.assertEqual(targets[0]["endpoint"], "https://api.test/v1/users")
        self.assertEqual(
            targets[0]["pointers"],
            ["/profile/email", "/roles/0", "/roles/1"],
        )
        self.assertEqual(targets[0]["content_type"], "application/json; charset=utf-8")
        self.assertEqual(
            targets[0]["headers"],
            {"Content-Type": "application/json; charset=utf-8", "X-Tenant": "acme"},
        )
        self.assertEqual(targets[1]["content_type"], "application/json")

    def test_skips_invalid_non_json_static_and_out_of_scope_requests(self):
        pairs = [
            _json_pair("https://api.test/v1/search", {"q": "x"}, method="GET"),
            _json_pair("https://api.test/v1/search", "not-json"),
            _json_pair("https://api.test/v1/search", "123"),
            _json_pair("https://api.test/v1/search", "{}"),
            _json_pair("https://api.test/static/app.js", {"q": "x"}),
            _json_pair("https://other.test/v1/search", {"q": "x"}),
            {"request": {
                "url": "https://api.test/v1/search",
                "method": "POST",
                "post_data": {"q": "already-parsed"},
            }},
        ]

        self.assertEqual(
            harvest_json_body_targets(pairs, base_netlocs={"api.test"}),
            [],
        )

    def test_deduplicates_method_endpoint_and_pointer_set(self):
        pairs = [
            _json_pair("https://api.test/v1/search?page=1", {"q": "x", "limit": 10}),
            _json_pair("https://api.test/v1/search?page=2", {"limit": 20, "q": "y"}),
            _json_pair(
                "https://api.test/v1/search?page=3",
                {"q": "z", "limit": 30},
                method="PATCH",
            ),
        ]

        targets = harvest_json_body_targets(pairs, base_netlocs={"api.test"})

        self.assertEqual(len(targets), 2)
        self.assertEqual(targets[0]["url"], "https://api.test/v1/search?page=1")
        self.assertEqual(targets[1]["method"], "PATCH")

    def test_caps_pointers_per_body_and_total_targets(self):
        large_body = {f"field{i}": i for i in range(205)}
        pairs = [
            _json_pair(f"https://api.test/v1/items/{i}", {"value": i})
            for i in range(205)
        ]
        pairs.insert(0, _json_pair("https://api.test/v1/large", large_body))

        targets = harvest_json_body_targets(pairs, base_netlocs={"api.test"})

        self.assertEqual(len(targets), 200)
        self.assertEqual(len(targets[0]["pointers"]), 200)
        self.assertEqual(targets[0]["pointers"][0], "/field0")
        self.assertEqual(targets[0]["pointers"][-1], "/field199")


if __name__ == "__main__":
    unittest.main()
