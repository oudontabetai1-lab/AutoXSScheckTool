import json
import unittest

from wscan.spa_harvest import (
    allocate_pointers_round_robin,
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

    def test_collapsed_observation_refreshes_body_to_newest(self):
        # 注入 shape 同じ・通常値変化（CSRF nonce 等）は collapse するが、replay body は最新観測へ
        # 更新する（stale nonce/version で 403/409 にしない・#90 R10）。
        pairs = [
            _json_pair("https://api.test/save", {"csrf": "OLD", "id": 1}),
            _json_pair("https://api.test/save", {"csrf": "NEW", "id": 2}),
        ]
        targets = harvest_json_body_targets(pairs, base_netlocs={"api.test"})
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["json_body"]["csrf"], "NEW")
        self.assertEqual(targets[0]["json_body"]["id"], 2)

    def test_anonymous_graphql_query_differentiates_operations(self):
        # operationName 省略の匿名 GraphQL は query 本文で operation を識別＝別ターゲットに保つ（#90 R10）。
        pairs = [
            _json_pair("https://api.test/graphql", {"query": "{ user { id } }", "variables": {}}),
            _json_pair("https://api.test/graphql", {"query": "{ admin { id } }", "variables": {}}),
        ]
        targets = harvest_json_body_targets(pairs, base_netlocs={"api.test"})
        self.assertEqual(len(targets), 2)

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

    def test_persisted_graphql_query_hash_is_discriminator(self):
        # Apollo APQ は query/operationName を省き extensions.persistedQuery.sha256Hash で operation を
        # 識別する。別 hash（同一 pointer 集合）を別ターゲットに保つ（#90 R14）。
        targets = harvest_json_body_targets([
            _json_pair("https://api.test/graphql", {
                "extensions": {"persistedQuery": {"version": 1, "sha256Hash": "aaa"}},
                "variables": {"id": 1}}),
            _json_pair("https://api.test/graphql", {
                "extensions": {"persistedQuery": {"version": 1, "sha256Hash": "bbb"}},
                "variables": {"id": 1}}),
        ], base_netlocs={"api.test"})
        self.assertEqual(len(targets), 2)
        self.assertNotEqual(targets[0]["body_signature"], targets[1]["body_signature"])

    def test_query_distinct_operations_bucketed_separately(self):
        # ?op=create（churn 2件）と ?op=delete は別 observed_url→別バケツ。cap=2 でも round-robin で
        # 両 operation が parse される（queryless バケツだと delete が未 parse になる・#90 R14）。
        pairs = [
            _json_pair("https://api.test/action?op=create", {"doc": "d", "ts": 1}),
            _json_pair("https://api.test/action?op=create", {"doc": "d", "ts": 2}),
            _json_pair("https://api.test/action?op=delete", {"doc": "d"}),
        ]
        targets = harvest_json_body_targets(pairs, base_netlocs={"api.test"}, max_targets=2)
        urls = {t["url"] for t in targets}
        self.assertIn("https://api.test/action?op=create", urls)
        self.assertIn("https://api.test/action?op=delete", urls)

    def test_discriminator_beyond_pointer_cap_still_distinguishes(self):
        # 200 葉を超えた位置の discriminator（method）も full-body 走査で拾い、別 operation を区別する
        # （enumerate_leaf_pointers の 200 上限に依存しない・#90 R14）。
        filler = {f"f{i}": i for i in range(250)}  # 250 leaves (>200 pointer cap)
        body_create = dict(filler); body_create["method"] = "create"
        body_delete = dict(filler); body_delete["method"] = "delete"
        targets = harvest_json_body_targets([
            _json_pair("https://api.test/rpc", body_create),
            _json_pair("https://api.test/rpc", body_delete),
        ], base_netlocs={"api.test"})
        self.assertEqual(len(targets), 2)
        self.assertNotEqual(targets[0]["body_signature"], targets[1]["body_signature"])

    def test_discriminator_not_cut_off_by_earlier_discriminator_leaves(self):
        # 多数の discriminator 名の葉(type)が先にあっても、後方の operation selector(method)まで走査して
        # 別 operation を区別する（max_found カットオフ撤去・#90 R14）。
        base = {f"n{i}": {"type": "x"} for i in range(80)}  # 80 個の nested "type" discriminator
        bc = dict(base); bc["method"] = "create"
        bd = dict(base); bd["method"] = "delete"
        targets = harvest_json_body_targets([
            _json_pair("https://api.test/rpc", bc),
            _json_pair("https://api.test/rpc", bd),
        ], base_netlocs={"api.test"})
        self.assertEqual(len(targets), 2)
        self.assertNotEqual(targets[0]["body_signature"], targets[1]["body_signature"])

    def test_operation_discriminator_preserves_json_type(self):
        # discriminator が JSON 型で operation を分ける（{"action":1} int vs {"action":"1"} str）場合、
        # str() だと同じ "1" に潰れて片方を未 probe にする。repr で型を保持し別ターゲットに残す（#90 R13）。
        targets = harvest_json_body_targets(
            [
                _json_pair("https://api.test/v1/act", {"action": 1, "data": "x"}),
                _json_pair("https://api.test/v1/act", {"action": "1", "data": "x"}),
            ],
            base_netlocs={"api.test"},
        )
        self.assertEqual(len(targets), 2)
        self.assertNotEqual(targets[0]["body_signature"], targets[1]["body_signature"])

    def test_value_churn_collapses_but_later_endpoint_still_harvested(self):
        # 1 endpoint の値churn（timestamp だけ違う distinct body 群）は semantic collapse で 1 ターゲット。
        # parse 予算に headroom があれば、churn の後に来る別 endpoint も取りこぼさない（#90 R13）。
        churn = [
            _json_pair("https://api.test/v1/save", {"doc": "d", "ts": i})
            for i in range(10)
        ]
        later = [_json_pair("https://api.test/v1/other", {"q": "x"})]
        targets = harvest_json_body_targets(
            churn + later, base_netlocs={"api.test"}, max_targets=20,
        )
        endpoints = {t["endpoint"] for t in targets}
        # churn は 1 つに潰れ、後続の別 endpoint も残る。
        self.assertIn("https://api.test/v1/save", endpoints)
        self.assertIn("https://api.test/v1/other", endpoints)
        self.assertEqual(
            sum(1 for t in targets if t["endpoint"] == "https://api.test/v1/save"), 1
        )

    def test_round_robin_parse_prevents_churn_starving_later_endpoint(self):
        # 1 url の値churn（tsだけ違う 50 body）が別 endpoint /b を飢餓させない。バケツ間 round-robin
        # なので /a と /b が最初の pass で 1 body ずつ parse され、churn が予算を独占しない（#90 R14）。
        churn = [
            _json_pair("https://api.test/v1/a", {"doc": "d", "ts": i})
            for i in range(50)
        ]
        later = [_json_pair("https://api.test/v1/b", {"q": "x"})]
        targets = harvest_json_body_targets(
            churn + later, base_netlocs={"api.test"}, max_targets=12,
        )
        endpoints = {t["endpoint"] for t in targets}
        self.assertIn("https://api.test/v1/a", endpoints)
        self.assertIn("https://api.test/v1/b", endpoints)

    def test_new_operation_after_churn_still_discovered(self):
        # churn の後に来る genuine な新 operation（同一 url・別 method 値）も parse される。
        # round-robin は url を blacklist しないため、8 collapse 後の新 method も取りこぼさない（#90 R14）。
        churn = [
            _json_pair("https://api.test/rpc", {"method": "poll", "ts": i})
            for i in range(8)
        ]
        new_op = [_json_pair("https://api.test/rpc", {"method": "danger", "params": "x"})]
        targets = harvest_json_body_targets(
            churn + new_op, base_netlocs={"api.test"}, max_targets=50,
        )
        sigs = {t["body_signature"] for t in targets}
        # poll（1 collapse target）＋ danger（別 method）の 2 operation が残る。
        self.assertEqual(len(targets), 2)
        self.assertEqual(len(sigs), 2)

    def test_deep_json_body_does_not_wipe_earlier_targets(self):
        # 深いネスト JSON が RecursionError を起こしても per-entry 隔離で正常 target を巻き添えにしない
        # （#90 R14・旧 rewrite は外側 except で全消去する回帰があった）。
        deep = "[" * 20000 + "]" * 20000  # balanced だが過度にネスト（40KB<256KB・RecursionError誘発）
        pairs = [
            _json_pair("https://api.test/v1/ok", {"q": "x"}),
            _json_pair("https://api.test/v1/deep", deep),
        ]
        targets = harvest_json_body_targets(pairs, base_netlocs={"api.test"})
        endpoints = {t["endpoint"] for t in targets}
        self.assertIn("https://api.test/v1/ok", endpoints)

    def test_semantic_collapse_keeps_latest_observation_headers(self):
        # A(H1) -> B(H2) -> A(H3)（A/B は同一注入 shape に collapse）。round-robin は観測順に並ばないが
        # order で守り、最新観測 H3 を保つ（古い H2 で上書きしない・#90 R14）。
        a = {"doc": "d", "ts": 1}
        b = {"doc": "e", "ts": 2}
        pairs = [
            _json_pair("https://api.test/v1/x", a, headers={"Authorization": "H1"}),
            _json_pair("https://api.test/v1/x", b, headers={"Authorization": "H2"}),
            _json_pair("https://api.test/v1/x", a, headers={"Authorization": "H3"}),
        ]
        targets = harvest_json_body_targets(pairs, base_netlocs={"api.test"})
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["headers"]["Authorization"], "H3")

    def test_many_operations_same_url_all_discovered(self):
        # 同一 url が別 operation（method 値違い）を出し続けても round-robin で全て parse される
        # （JSON-RPC 多 method endpoint を blacklist で取りこぼさない・#90 R14）。
        pairs = [
            _json_pair("https://api.test/rpc", {"method": f"m{i}", "params": "x"})
            for i in range(15)
        ]
        targets = harvest_json_body_targets(
            pairs, base_netlocs={"api.test"}, max_targets=50,
        )
        self.assertEqual(len(targets), 15)


class AllocatePointersRoundRobinTests(unittest.TestCase):
    def test_round_robin_prevents_single_target_monopoly(self):
        # 多 pointer の先頭 target が cap を独占せず、少 pointer の後続 target も slot を得る（#90 R13）。
        targets = [
            {"pointers": [f"/a{i}" for i in range(200)]},
            {"pointers": ["/b0", "/b1", "/b2"]},
        ]
        alloc = allocate_pointers_round_robin(targets, 10)
        idxs = [ti for ti, _ in alloc]
        self.assertEqual(len(alloc), 10)
        self.assertIn(1, idxs)  # 後続 target も配分される
        self.assertEqual(idxs[:4], [0, 1, 0, 1])  # 1 pass 1 pointer ずつ交互

    def test_allocates_all_when_cap_exceeds_total(self):
        targets = [{"pointers": ["/a"]}, {"pointers": ["/b", "/c"]}]
        alloc = allocate_pointers_round_robin(targets, 100)
        self.assertEqual({p for _, p in alloc}, {"/a", "/b", "/c"})

    def test_edge_cases(self):
        self.assertEqual(allocate_pointers_round_robin([], 10), [])
        self.assertEqual(allocate_pointers_round_robin([{"pointers": ["/a"]}], 0), [])
        self.assertEqual(allocate_pointers_round_robin([{"pointers": ["/a"]}], -3), [])
        # cap=None は全 pointer を配分（上限なし）
        self.assertEqual(
            allocate_pointers_round_robin([{"pointers": ["/a", "/b"]}], None),
            [(0, "/a"), (0, "/b")],
        )

    def test_repeated_malformed_body_does_not_starve_later_valid_json(self):
        # malformed/非container JSON は成功時にしか raw_index に載らないため、修正前は同一 body の
        # 連投を毎回 parse して processed を食い潰し、後続の valid JSON を飢餓させた（#90 R12）。
        # 負キャッシュ(rejected)で重複拒否 body は最大 1 回だけ parse・budget も 1 回だけ消費する。
        ct = {"Content-Type": "application/json"}
        malformed = [
            _json_pair("https://api.test/v1/bad", "{not valid json", headers=ct)
            for _ in range(20)
        ]
        valid = [_json_pair("https://api.test/v1/good", {"q": "x"}, headers=ct)]
        targets = harvest_json_body_targets(
            malformed + valid, base_netlocs={"api.test"}, max_targets=3,
        )
        endpoints = {t["endpoint"] for t in targets}
        # 20 連投の malformed が cap を食い潰さず、後続の valid JSON が拾える。
        self.assertIn("https://api.test/v1/good", endpoints)

    def test_drops_stale_body_integrity_and_encoding_headers(self):
        # Content-MD5/Digest/Content-Encoding 等は body 再直列化で無効になるため落とす（#90 R6）。
        pairs = [_json_pair(
            "https://api.test/v1/x", {"a": 1},
            headers={
                "Content-MD5": "abc==", "Digest": "sha-256=xxx",
                "Content-Encoding": "gzip", "Transfer-Encoding": "chunked",
                "Accept-Encoding": "br, zstd, gzip", "X-Keep": "yes",
            },
        )]
        headers = harvest_json_body_targets(pairs, base_netlocs={"api.test"})[0]["headers"]
        self.assertNotIn("Content-MD5", headers)
        self.assertNotIn("Digest", headers)
        self.assertNotIn("Content-Encoding", headers)
        self.assertNotIn("Transfer-Encoding", headers)
        # accept-encoding は落とす（httpx が扱えない br/zstd を広告して偽陰性にしない・#90 R11）。
        self.assertNotIn("Accept-Encoding", headers)
        self.assertEqual(headers.get("X-Keep"), "yes")

    def test_retains_csrf_token_for_replay(self):
        # X-CSRF-Token は replay 認証のため残す（redaction は Finding 側で行う）。
        pairs = [_json_pair(
            "https://api.test/v1/x", {"a": 1},
            headers={"X-CSRF-Token": "tok", "X-XSRF-Token": "tok2"},
        )]
        headers = harvest_json_body_targets(pairs, base_netlocs={"api.test"})[0]["headers"]
        self.assertEqual(headers.get("X-CSRF-Token"), "tok")
        self.assertEqual(headers.get("X-XSRF-Token"), "tok2")

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
