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
        # content-type/cookie/proxy-auth/content-length/host は落とす。Authorization 等の
        # JS 取得トークンは replay 認証のため残す（Codex #90 R3・merge_template_headers が
        # configured を優先し、Finding では redact される）。非認証(X-Tenant)も残る。
        self.assertEqual(
            targets[0]["headers"],
            {
                "Authorization": "Bearer secret",
                "X-Api-Key": "secret",
                "X-Auth-Token": "secret",
                "X-Access-Token": "secret",
                "X-Tenant": "acme",
            },
        )
        self.assertNotIn("Content-Type", targets[0]["headers"])
        self.assertNotIn("cookie", targets[0]["headers"])
        self.assertNotIn("Proxy-Authorization", targets[0]["headers"])
        self.assertNotIn("Host", targets[0]["headers"])
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

    def test_deduplicates_same_url_method_and_normalized_body(self):
        # 同一 url+method、**値も同じ**でキー順違いだけは 1 つに collapse。method 違いは別。
        pairs = [
            _json_pair("https://api.test/v1/search", {"q": "x", "limit": 10}),
            _json_pair("https://api.test/v1/search", {"limit": 10, "q": "x"}),  # 同値・キー順違い
            _json_pair("https://api.test/v1/search", {"q": "x", "limit": 10}, method="PATCH"),
        ]

        targets = harvest_json_body_targets(pairs, base_netlocs={"api.test"})

        self.assertEqual(len(targets), 2)
        self.assertEqual(targets[0]["url"], "https://api.test/v1/search")
        self.assertEqual(targets[1]["method"], "PATCH")

    def test_ordinary_value_changes_collapse_to_one_target(self):
        # timestamp/id/nonce 等の通常値変化は同一注入 shape として collapse（重複 probe しない・#90 R9）。
        pairs = [
            _json_pair("https://api.test/save", {"id": 1, "ts": 100, "csrf": "aaa"}),
            _json_pair("https://api.test/save", {"id": 2, "ts": 200, "csrf": "bbb"}),
            _json_pair("https://api.test/save", {"id": 3, "ts": 300, "csrf": "ccc"}),
        ]
        targets = harvest_json_body_targets(pairs, base_netlocs={"api.test"})
        self.assertEqual(len(targets), 1)

    def test_body_value_differentiated_operations_kept_separate(self):
        # 同 pointer 集合でも body の**値**で operation を多重化する場合（JSON-RPC method /
        # GraphQL operationName）は別ターゲットに保つ（#90 R8）。
        pairs = [
            _json_pair("https://api.test/rpc", {"method": "create", "params": {"id": 1}}),
            _json_pair("https://api.test/rpc", {"method": "delete", "params": {"id": 2}}),
        ]
        targets = harvest_json_body_targets(pairs, base_netlocs={"api.test"})
        self.assertEqual(len(targets), 2)
        self.assertNotEqual(targets[0]["body_signature"], targets[1]["body_signature"])

    def test_semantic_duplicate_refreshes_headers(self):
        # 値変化なしのキー順違い（raw は別だが正規化 body 同一）でも headers を最新化する（#90 R8 C2）。
        pairs = [
            _json_pair("https://api.test/v1/x", {"a": 1, "b": 2},
                       headers={"Authorization": "Bearer OLD"}),
            _json_pair("https://api.test/v1/x", {"b": 2, "a": 1},  # 同値・キー順違い＝semantic dup
                       headers={"Authorization": "Bearer NEW"}),
        ]
        targets = harvest_json_body_targets(pairs, base_netlocs={"api.test"})
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["headers"]["Authorization"], "Bearer NEW")

    def test_skips_oversized_body_before_parse(self):
        # 巨大 body は parse 前に skip（メモリ/CPU ガード・#90 R8 C3）。
        big = {"blob": "x" * (300 * 1024)}
        pairs = [_json_pair("https://api.test/v1/big", big)]
        self.assertEqual(
            harvest_json_body_targets(pairs, base_netlocs={"api.test"}), []
        )

    def test_non_json_content_type_does_not_consume_budget(self):
        # 明示非 JSON(form 等)は budget を消費せず skip。後続の valid JSON が飢餓しない（#90 R8 C4）。
        forms = [
            _json_pair(f"https://api.test/form{i}", "a=1&b=2",
                       headers={"Content-Type": "application/x-www-form-urlencoded"})
            for i in range(5)
        ]
        js = [_json_pair("https://api.test/v1/ok", {"q": "x"})]
        targets = harvest_json_body_targets(forms + js, base_netlocs={"api.test"}, max_targets=1)
        self.assertEqual([t["endpoint"] for t in targets], ["https://api.test/v1/ok"])

    def test_query_differentiated_operations_kept_separate(self):
        # 1 パスが query で別 operation を出す場合（?op=create/?op=delete）は別ターゲットとして残す
        # （identity に observed query を含める・#90 R7）。replay は query 付き URL を保つ。
        pairs = [
            _json_pair("https://api.test/action?op=create", {"id": 1}),
            _json_pair("https://api.test/action?op=delete", {"id": 2}),
        ]
        targets = harvest_json_body_targets(pairs, base_netlocs={"api.test"})
        self.assertEqual(len(targets), 2)
        self.assertEqual(
            {t["url"] for t in targets},
            {"https://api.test/action?op=create", "https://api.test/action?op=delete"},
        )

    def test_repeated_request_refreshes_replay_headers(self):
        # 同一 (method,url,body) の再観測で、refresh された Authorization を最新に更新する（#90 R7）。
        pairs = [
            _json_pair("https://api.test/v1/x", {"a": 1},
                       headers={"Authorization": "Bearer OLD"}),
            _json_pair("https://api.test/v1/x", {"a": 1},
                       headers={"Authorization": "Bearer NEW"}),
        ]
        targets = harvest_json_body_targets(pairs, base_netlocs={"api.test"})
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["headers"]["Authorization"], "Bearer NEW")

    def test_same_endpoint_different_key_order_yields_same_sorted_pointers(self):
        # engine の大域 dedup キーは pointer を sorted で持つ。JSON キーの挿入順が違うだけの
        # 同一エンドポイントを別ページで観測しても、sorted 表現が一致し重複キュー化しない。
        a = harvest_json_body_targets(
            [_json_pair("https://api.test/v1/u", {"email": "x", "name": "y"})],
            base_netlocs={"api.test"},
        )[0]
        b = harvest_json_body_targets(
            [_json_pair("https://api.test/v1/u", {"name": "y", "email": "x"})],
            base_netlocs={"api.test"},
        )[0]
        self.assertEqual(a["endpoint"], b["endpoint"])
        self.assertEqual(sorted(a["pointers"]), sorted(b["pointers"]))
        # 順序非依存キー（method, endpoint, sorted(pointers)）が一致する。
        self.assertEqual(
            (a["method"], a["endpoint"], tuple(sorted(a["pointers"]))),
            (b["method"], b["endpoint"], tuple(sorted(b["pointers"]))),
        )

    def test_scope_predicate_filters_before_materializing(self):
        # is_in_scope を渡すと、対象外 URL は body を parse/materialize せずに落ちる。
        # 有効ターゲットのみ残り、除外パスが有効を飢餓させない。
        pairs = [
            _json_pair("https://api.test/v1/excluded", {"a": 1}),
            _json_pair("https://api.test/v1/ok", {"b": 2}),
        ]
        targets = harvest_json_body_targets(
            pairs,
            base_netlocs={"api.test"},
            is_in_scope=lambda u: "/v1/ok" in u,
        )
        self.assertEqual([t["endpoint"] for t in targets], ["https://api.test/v1/ok"])

    def test_max_targets_bounds_processed_observations(self):
        # max_targets は**処理数**（スコープ通過＋raw-unique 観測）の上限。ユニーク body でも有界。
        pairs = [_json_pair(f"https://api.test/v1/x{i}", {"v": i}) for i in range(10)]
        targets = harvest_json_body_targets(
            pairs, base_netlocs={"api.test"}, max_targets=3,
        )
        self.assertEqual(len(targets), 3)

    def test_repeated_identical_body_deduped_before_parse_and_not_counted(self):
        # 同一 body の連投(polling/autosave)は pre-parse dedup で1つに潰れ、parse 予算を食わない。
        # 同一 body ×20 + ユニーク3件・cap=3 → 同一は 1 処理、ユニーク3件が残り全部通る。
        polling = [_json_pair("https://api.test/v1/poll", {"t": 1}) for _ in range(20)]
        uniques = [_json_pair(f"https://api.test/v1/u{i}", {"v": i}) for i in range(3)]
        targets = harvest_json_body_targets(
            polling + uniques, base_netlocs={"api.test"}, max_targets=3,
        )
        endpoints = {t["endpoint"] for t in targets}
        # polling は 1 つだけ（20 連投が重複潰し）＋ ユニークが cap 内で拾える。
        self.assertIn("https://api.test/v1/poll", endpoints)
        self.assertLessEqual(len(targets), 3)

    def test_drops_stale_body_integrity_and_encoding_headers(self):
        # Content-MD5/Digest/Content-Encoding 等は body 再直列化で無効になるため落とす（#90 R6）。
        pairs = [_json_pair(
            "https://api.test/v1/x", {"a": 1},
            headers={
                "Content-MD5": "abc==", "Digest": "sha-256=xxx",
                "Content-Encoding": "gzip", "Transfer-Encoding": "chunked",
                "X-Keep": "yes",
            },
        )]
        headers = harvest_json_body_targets(pairs, base_netlocs={"api.test"})[0]["headers"]
        self.assertNotIn("Content-MD5", headers)
        self.assertNotIn("Digest", headers)
        self.assertNotIn("Content-Encoding", headers)
        self.assertNotIn("Transfer-Encoding", headers)
        self.assertEqual(headers.get("X-Keep"), "yes")

    def test_caps_pointers_per_body_not_total_targets(self):
        # 1 body の pointer 数は cap（enumerate 側 200）。ただし**総ターゲット数は harvester で
        # cap しない**（精密スコープ判定後に engine が json_ip_cap を掛ける＝除外パスばかりの観測が
        # 有効ターゲットを飢餓させないため。Codex #90 R2）。
        large_body = {f"field{i}": i for i in range(205)}
        pairs = [
            _json_pair(f"https://api.test/v1/items/{i}", {"value": i})
            for i in range(205)
        ]
        pairs.insert(0, _json_pair("https://api.test/v1/large", large_body))

        targets = harvest_json_body_targets(pairs, base_netlocs={"api.test"})

        # 総数は 200 で打ち切られない（large + items/0..204 = 206）。
        self.assertEqual(len(targets), 206)
        # 1 body の pointer は 200 で cap。
        self.assertEqual(len(targets[0]["pointers"]), 200)
        self.assertEqual(targets[0]["pointers"][0], "/field0")
        self.assertEqual(targets[0]["pointers"][-1], "/field199")


if __name__ == "__main__":
    unittest.main()
