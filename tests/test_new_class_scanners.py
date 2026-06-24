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
)
from wscan.scanners.prototype_pollution import (
    proto_query_variants,
    proto_json_bodies,
    is_polluted,
    server_pollution_reflected,
)
from wscan.scanners.cache_poisoning import (
    is_cacheable,
    cache_hit,
    reflected,
    deception_succeeded,
)
from wscan.scanners.mass_assignment import (
    augment_body,
    detect_mass_assignment,
    make_sentinels,
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


class MassAssignmentDoneGatingTests(unittest.TestCase):
    """テンプレート未取込（認証付きスキャンの未認証ページレベル検査）の段階で
    _done を立てて以降の本来の検査を飛ばさないこと（Codex P2 回帰）。"""

    def _scanner(self, templates):
        from wscan.scanners.mass_assignment import MassAssignmentScanner

        engine = types.SimpleNamespace(
            browser=None, monitor=None, payload_gen=None,
            api_seed_requests=templates,
        )
        return MassAssignmentScanner(engine)

    def test_empty_templates_does_not_set_done(self):
        sc = self._scanner([])
        result = asyncio.run(sc.scan_page("http://h/"))
        self.assertEqual(result, [])
        # スペックが後から読まれる可能性があるので _done は立てない
        self.assertFalse(sc._done)

    def test_second_call_after_templates_appear_runs(self):
        sc = self._scanner([])
        asyncio.run(sc.scan_page("http://h/login"))  # pre-auth page, no templates
        self.assertFalse(sc._done)
        # スペック取込後（GET 操作だけ → POST/PUT/PATCH 無し）でも _done は立つ
        sc.engine.api_seed_requests = [
            types.SimpleNamespace(method="GET", url="http://h/api", json_body=None,
                                  content_type="application/json")
        ]
        asyncio.run(sc.scan_page("http://h/dashboard"))
        self.assertTrue(sc._done)


if __name__ == "__main__":
    unittest.main()
