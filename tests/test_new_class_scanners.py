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


if __name__ == "__main__":
    unittest.main()
