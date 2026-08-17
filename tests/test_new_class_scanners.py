"""新クラススキャナの検知ロジック（純粋関数）のテスト。

ブラウザ/HTTP 非依存で、誤検知ゼロ方針（反射のみ・保護ありは非検出）を守れるか
を検証する。
"""
import asyncio
import types
import unittest

from wscan.scanners.graphql import (
    build_alias_amplification_query,
    build_deep_introspection_query,
    detect_alias_amplification,
    detect_no_depth_limit,
)
from wscan.scanners.prototype_pollution import (
    proto_query_variants,
    proto_json_bodies,
    is_polluted,
    server_pollution_reflected,
    pollution_persisted,
)
from urllib.parse import urlparse
from wscan.scanners.cache_poisoning import (
    is_cacheable,
    cache_hit,
    reflected,
    deception_succeeded,
    _build_deception_url,
)
from wscan.scanners.mass_assignment import (
    augment_body,
    injectable_sentinels,
    detect_mass_assignment,
    make_sentinels,
    acceptance_ok,
)


class GraphQLDosTests(unittest.TestCase):
    def test_alias_query_shape(self):
        q = build_alias_amplification_query(3)
        self.assertIn("a0: __typename", q)
        self.assertIn("a2: __typename", q)

    def test_deep_query_nests(self):
        q = build_deep_introspection_query(3)
        self.assertEqual(q.count("ofType"), 3)

    def test_detect_accepts_when_no_limit(self):
        data = {"data": {f"a{i}": "Query" for i in range(100)}}
        self.assertTrue(detect_alias_amplification(data, 100))

    def test_detect_rejects_when_complexity_error(self):
        data = {"errors": [{"message": "Query exceeds maximum complexity of 50"}]}
        self.assertFalse(detect_alias_amplification(data, 100))

    def test_detect_rejects_partial(self):
        data = {"data": {"a0": "Query"}}  # only first alias present
        self.assertFalse(detect_alias_amplification(data, 100))

    def test_detect_non_dict(self):
        self.assertFalse(detect_alias_amplification("[]", 100))

    def test_depth_limit_present_rejected(self):
        # 深いクエリが depth-limit エラーで弾かれた → 制限あり → 非検出
        data = {"errors": [{"message": "Query depth limit of 10 exceeded"}]}
        self.assertFalse(detect_no_depth_limit(data))

    def test_depth_no_limit_accepted(self):
        data = {"data": {"__schema": {"types": []}}}
        self.assertTrue(detect_no_depth_limit(data))

    def test_depth_other_error_rejected(self):
        # 何らかのエラーが返るなら（制限の可能性）報告しない
        self.assertFalse(detect_no_depth_limit({"errors": [{"message": "nope"}]}))


class PrototypePollutionTests(unittest.TestCase):
    def test_variants(self):
        v = proto_query_variants("m", "x")
        self.assertIn("__proto__[m]=x", v)
        self.assertIn("constructor[prototype][m]=x", v)

    def test_json_bodies(self):
        bodies = proto_json_bodies("m", "x")
        self.assertEqual(bodies[0], {"__proto__": {"m": "x"}})

    def test_is_polluted(self):
        self.assertTrue(is_polluted("x", "x"))
        self.assertFalse(is_polluted(None, "x"))
        self.assertFalse(is_polluted("y", "x"))

    def test_server_reflection_requires_new_value(self):
        # value present only after injection → vulnerable
        self.assertTrue(server_pollution_reflected("ok", "ok polluted1", "polluted1"))
        # value already in baseline → just reflection, not pollution
        self.assertFalse(server_pollution_reflected("polluted1", "polluted1", "polluted1"))
        self.assertFalse(server_pollution_reflected("a", "b", ""))

    def test_pollution_persisted_requires_clean_followup_leak(self):
        # 汚染後の CLEAN 応答に value が現れ、ベースラインには無い → 汚染（エコー不可）
        self.assertTrue(pollution_persisted("baseline", "baseline polluted1", "polluted1"))
        # CLEAN 応答に value が無い（=エコーのみ、波及していない）→ 非検出
        self.assertFalse(pollution_persisted("baseline", "baseline clean", "polluted1"))
        # value が汚染前ベースラインにもある → 偶然一致として除外
        self.assertFalse(pollution_persisted("polluted1", "polluted1", "polluted1"))
        self.assertFalse(pollution_persisted("a", "b", ""))


class MergeTemplateHeadersTests(unittest.TestCase):
    def test_user_auth_not_overridden_by_template(self):
        from wscan.scanners.base import merge_template_headers
        base = {"Authorization": "Bearer real-token", "X-API-Key": "user-key"}
        tmpl = {"Authorization": "Bearer spec-placeholder",
                "x-api-key": "spec-key", "X-API-Version": "v2"}
        out = merge_template_headers(base, tmpl)
        # 認証情報は base（利用者）の値を維持（大小無視で照合）
        self.assertEqual(out["Authorization"], "Bearer real-token")
        self.assertEqual(out["X-API-Key"], "user-key")
        self.assertNotIn("x-api-key", out)  # 重複キーを増やさない
        # 非認証の必須ヘッダはテンプレ値で補完する
        self.assertEqual(out["X-API-Version"], "v2")

    def test_template_auth_used_when_base_missing(self):
        from wscan.scanners.base import merge_template_headers
        # base に認証情報が無ければテンプレの値を採用する（spec 提供キーの救済）
        out = merge_template_headers({}, {"Authorization": "Bearer spec"})
        self.assertEqual(out["Authorization"], "Bearer spec")

    def test_non_credential_template_overrides(self):
        from wscan.scanners.base import merge_template_headers
        out = merge_template_headers({"X-API-Version": "v1"}, {"X-API-Version": "v2"})
        self.assertEqual(out["X-API-Version"], "v2")

    def test_api_key_alias_spellings_treated_as_credential(self):
        # Api-Key/ApiKey（x- 無し綴り）も request_logger の機密集合と同期し、base の実キーを
        # 観測/テンプレ値で上書きしない・evidence で redact する（#90 R13）。
        from wscan.scanners.base import (
            merge_template_headers, _redact_json_evidence_pair,
        )
        base = {"Api-Key": "user-real", "ApiKey": "user-real2"}
        out = merge_template_headers(base, {"Api-Key": "captured", "ApiKey": "captured2"})
        self.assertEqual(out["Api-Key"], "user-real")
        self.assertEqual(out["ApiKey"], "user-real2")
        # evidence redaction も綴り違いを伏せる
        pair = {"request": {"headers": {"Api-Key": "live", "ApiKey": "live2"}}}
        red = _redact_json_evidence_pair(pair, "")
        self.assertEqual(red["request"]["headers"]["Api-Key"], "***")
        self.assertEqual(red["request"]["headers"]["ApiKey"], "***")

    def test_credential_judgment_delegates_to_request_logger_canon(self):
        # base は独自集合を持たず request_logger の正典（静的＋runtime）へ委譲する（#90 R13）。
        from wscan.scanners.base import merge_template_headers, _mask_credential_headers
        from wscan import request_logger
        # set-cookie（旧 base 集合に無かった）と x-access-token（旧 logger 集合に無かった）を
        # 双方向で同期し、base 側 evidence redaction で伏せる。
        masked = _mask_credential_headers({"Set-Cookie": "sid=abc", "X-Access-Token": "t"})
        self.assertEqual(masked["Set-Cookie"], "***")
        self.assertEqual(masked["X-Access-Token"], "***")
        # runtime 登録したカスタム認証ヘッダも保護（テンプレで上書きしない）。
        request_logger.register_sensitive_headers(["X-Company-Auth"])
        try:
            out = merge_template_headers({"X-Company-Auth": "real"},
                                         {"X-Company-Auth": "tmpl"})
            self.assertEqual(out["X-Company-Auth"], "real")
        finally:
            request_logger.clear_sensitive_headers()


class CachePoisoningTests(unittest.TestCase):
    def test_is_cacheable_public(self):
        self.assertTrue(is_cacheable({"Cache-Control": "public, max-age=60"}))

    def test_is_cacheable_nostore(self):
        self.assertFalse(is_cacheable({"Cache-Control": "no-store"}))
        self.assertFalse(is_cacheable({"Cache-Control": "private, max-age=60"}))

    def test_is_cacheable_maxage_zero(self):
        self.assertFalse(is_cacheable({"Cache-Control": "max-age=0"}))

    def test_is_cacheable_via_cdn_hit(self):
        self.assertTrue(is_cacheable({"X-Cache": "HIT", "Cache-Control": ""}))

    def test_cache_hit(self):
        self.assertTrue(cache_hit({"Age": "5"}))
        self.assertTrue(cache_hit({"CF-Cache-Status": "HIT"}))
        self.assertFalse(cache_hit({"Age": "0"}))
        self.assertFalse(cache_hit({}))

    def test_reflected(self):
        self.assertTrue(reflected("<a href=//evil.com>", "evil.com"))
        self.assertFalse(reflected("clean", "evil.com"))

    def test_deception_success(self):
        body = "<html>secret dashboard</html>" * 5
        self.assertTrue(deception_succeeded(
            base_status=200, base_body=body,
            css_status=200, css_body=body,
            css_headers={"Cache-Control": "public, max-age=600"},
        ))

    def test_deception_404_safe(self):
        self.assertFalse(deception_succeeded(
            base_status=200, base_body="x" * 100,
            css_status=404, css_body="not found",
            css_headers={"Cache-Control": "public"},
        ))

    def test_build_deception_url_with_query(self):
        # クエリ付き URL でも拡張子はパス側へ、クエリは保持
        u = _build_deception_url(urlparse("http://h/account?tab=1"), "x.css")
        self.assertEqual(u, "http://h/account/x.css?tab=1")

    def test_build_deception_url_no_query(self):
        u = _build_deception_url(urlparse("http://h/account/"), "x.css")
        self.assertEqual(u, "http://h/account/x.css")

    def test_deception_not_cacheable_safe(self):
        body = "dashboard" * 20
        self.assertFalse(deception_succeeded(
            base_status=200, base_body=body,
            css_status=200, css_body=body,
            css_headers={"Cache-Control": "no-store"},
        ))


class MassAssignmentTests(unittest.TestCase):
    def test_augment_adds_fields(self):
        s = {"role": "r1", "isAdmin": "a1"}
        out = augment_body({"name": "x"}, s)
        self.assertEqual(out["name"], "x")
        self.assertEqual(out["role"], "r1")

    def test_augment_does_not_overwrite_documented_field(self):
        # base に既出のフィールドは sentinel で上書きしない（文書化フィールド保護）
        out = augment_body({"role": "user"}, {"role": "sentinel", "isAdmin": "a1"})
        self.assertEqual(out["role"], "user")
        self.assertEqual(out["isAdmin"], "a1")

    def test_injectable_skips_documented_fields(self):
        # base に既出の特権フィールドは注入対象から外す（2xx エコー誤検知の回避）
        s = {"role": "r1", "isAdmin": "a1", "verified": "v1"}
        out = injectable_sentinels({"role": "user", "name": "x"}, s)
        self.assertNotIn("role", out)        # 文書化済み → 除外
        self.assertIn("isAdmin", out)        # 未文書 → 注入対象
        self.assertIn("verified", out)
        # 全フィールドが文書化済みなら空（→ scanner はそのテンプレをスキップ）
        self.assertEqual(injectable_sentinels({"role": "x", "isAdmin": "y"},
                                              {"role": "r", "isAdmin": "a"}), {})

    def test_detect_reflected_privilege(self):
        s = {"role": "wscanMA_role", "isAdmin": "wscanMA_admin"}
        baseline = '{"name":"x"}'
        polluted = '{"name":"x","role":"wscanMA_role"}'
        hit = detect_mass_assignment(baseline, polluted, s)
        self.assertEqual(hit, ("role", "wscanMA_role"))

    def test_detect_none_when_not_reflected(self):
        s = {"role": "wscanMA_role"}
        self.assertIsNone(detect_mass_assignment('{"name":"x"}', '{"name":"x"}', s))

    def test_detect_ignores_baseline_value(self):
        # sentinel already echoed in baseline → not evidence of acceptance
        s = {"role": "wscanMA_role"}
        self.assertIsNone(
            detect_mass_assignment('{"role":"wscanMA_role"}', '{"role":"wscanMA_role"}', s)
        )

    def test_sentinels_unique(self):
        s = make_sentinels(("role", "isAdmin"))
        self.assertEqual(len(set(s.values())), 2)

    def test_acceptance_ok(self):
        # 受理(2xx)のみ過剰割り当てとみなす。400/422 のエコーは誤検知になるため除外
        self.assertTrue(acceptance_ok(200))
        self.assertTrue(acceptance_ok(201))
        self.assertFalse(acceptance_ok(400))
        self.assertFalse(acceptance_ok(422))
        self.assertFalse(acceptance_ok(500))


class MassAssignmentUrlFilterTests(unittest.TestCase):
    """scan_page(url) は URL 一致の POST/PUT/PATCH テンプレートのみ検査すること
    （resume 時の全テンプレート再送を防ぐ Codex P2 回帰）。"""

    def _scanner(self, templates):
        from wscan.scanners.mass_assignment import MassAssignmentScanner

        engine = types.SimpleNamespace(
            browser=None, monitor=None, payload_gen=None,
            api_seed_requests=templates,
        )
        return MassAssignmentScanner(engine)

    def test_empty_templates_noop(self):
        sc = self._scanner([])
        self.assertEqual(asyncio.run(sc.scan_page("http://h/")), [])

    def test_non_matching_url_noop(self):
        # URL が一致しないテンプレートは検査しない（HTTP も送らない）
        sc = self._scanner([
            types.SimpleNamespace(method="POST", url="http://h/api/users",
                                  json_body={}, content_type="application/json")
        ])
        self.assertEqual(asyncio.run(sc.scan_page("http://h/other")), [])

    def test_get_only_template_noop(self):
        # GET 操作は対象外（mass assignment は本文系のみ）
        sc = self._scanner([
            types.SimpleNamespace(method="GET", url="http://h/api",
                                  json_body=None, content_type="application/json")
        ])
        self.assertEqual(asyncio.run(sc.scan_page("http://h/api")), [])


class GraphQLAuthFailureTests(unittest.TestCase):
    """保護 GraphQL の POST が 401 のとき engine._api_auth_failed を立てること
    （GET プレフライトで検知できない失効を救済する Codex P2 回帰）。"""

    def _scanner(self):
        from wscan.scanners.graphql import GraphQLScanner
        engine = types.SimpleNamespace(
            browser=None, monitor=None, payload_gen=None,
            login_url="https://h/login", logged_in_marker="",
            _api_auth_failed=False,
        )
        return GraphQLScanner(engine), engine

    def test_401_post_sets_auth_failed(self):
        sc, engine = self._scanner()
        resp = types.SimpleNamespace(status_code=401, url="https://h/gql", text="unauthorized")
        self.assertTrue(sc._note_auth_failure(resp, "https://h/gql"))
        self.assertTrue(engine._api_auth_failed)

    def test_200_does_not_set_auth_failed(self):
        sc, engine = self._scanner()
        resp = types.SimpleNamespace(status_code=200, url="https://h/gql",
                                     text='{"data": {"__typename": "Query"}}')
        self.assertFalse(sc._note_auth_failure(resp, "https://h/gql"))
        self.assertFalse(engine._api_auth_failed)


class GraphQLExactUrlGateTests(unittest.TestCase):
    """具体 URL probe は API スペック由来 or GraphQL らしいパスのみ
    （全クロールページへ probe を撒かない Codex P2 回帰）。"""

    def _scanner(self, api_urls=(), templates=()):
        from wscan.scanners.graphql import GraphQLScanner
        engine = types.SimpleNamespace(
            browser=None, monitor=None, payload_gen=None,
            api_seed_urls=set(api_urls), api_seed_requests=list(templates),
        )
        return GraphQLScanner(engine)

    def test_graphql_looking_path_allowed(self):
        sc = self._scanner()
        self.assertTrue(sc._is_api_or_graphql_url("https://h/graphql"))
        self.assertTrue(sc._is_api_or_graphql_url("https://h/api/graphql"))
        self.assertTrue(sc._is_api_or_graphql_url("https://h/gql"))

    def test_plain_html_route_rejected(self):
        sc = self._scanner()
        self.assertFalse(sc._is_api_or_graphql_url("https://h/about"))
        self.assertFalse(sc._is_api_or_graphql_url("https://h/account"))

    def test_api_spec_url_allowed(self):
        sc = self._scanner(api_urls=["https://h/custom-endpoint"])
        self.assertTrue(sc._is_api_or_graphql_url("https://h/custom-endpoint"))
        # テンプレート URL も許可
        sc2 = self._scanner(
            templates=[types.SimpleNamespace(url="https://h/tmpl-ep")]
        )
        self.assertTrue(sc2._is_api_or_graphql_url("https://h/tmpl-ep"))


class PrototypePollutionMultiTemplateTests(unittest.TestCase):
    """server-side proto は URL 一致の全 body テンプレートを試すこと
    （POST/PATCH で必須フィールドが異なるケースの取りこぼし防止 Codex P2 回帰）。"""

    def _scanner(self, templates):
        from wscan.scanners.prototype_pollution import PrototypePollutionScanner
        engine = types.SimpleNamespace(
            browser=None, monitor=None, payload_gen=None,
            api_seed_requests=templates, _api_auth_failed=False,
        )
        return PrototypePollutionScanner(engine)

    def _tmpl(self, method):
        return types.SimpleNamespace(url="http://h/x", method=method,
                                     json_body={}, content_type="application/json",
                                     headers={})

    def test_iterates_all_matching_templates(self):
        t1, t2 = self._tmpl("POST"), self._tmpl("PATCH")
        sc = self._scanner([t1, t2])
        seen = []

        async def fake(url, tmpl):
            seen.append(tmpl)
            return None
        sc._probe_server_template = fake
        asyncio.run(sc._scan_server_side("http://h/x"))
        self.assertEqual(seen, [t1, t2])

    def test_stops_on_first_finding(self):
        t1, t2 = self._tmpl("POST"), self._tmpl("PATCH")
        sc = self._scanner([t1, t2])
        seen = []

        async def fake(url, tmpl):
            seen.append(tmpl)
            return "FINDING"
        sc._probe_server_template = fake
        out = asyncio.run(sc._scan_server_side("http://h/x"))
        self.assertEqual(seen, [t1])
        self.assertEqual(out, ["FINDING"])

    def test_no_template_uses_bare_post(self):
        sc = self._scanner([])
        seen = []

        async def fake(url, tmpl):
            seen.append(tmpl)
            return None
        sc._probe_server_template = fake
        asyncio.run(sc._scan_server_side("http://h/y"))
        self.assertEqual(seen, [None])


if __name__ == "__main__":
    unittest.main()
