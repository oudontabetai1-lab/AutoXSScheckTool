"""0009 C1: JS 資産由来のゴミ URL 除去（純粋関数）の回帰テスト。

誤抽出0（regex/式片を弾く）と実ルート維持（到達性を落とさない）を同時に守る。
"""
import unittest

from wscan.url_extraction import (
    is_plausible_route_candidate,
    filter_route_candidates,
)


class PlausibleRouteCandidateTests(unittest.TestCase):
    # 実ルート/API は維持する（到達性を落とさないことが C1 の要件）。
    REAL_ROUTES = [
        "http://juice-shop.test/rest/products/search",
        "http://juice-shop.test/api/Users",
        "http://juice-shop.test/rest/user/whoami",
        "http://juice-shop.test/api/Feedbacks/",
        "http://juice-shop.test/assets/public/images/products/apple.jpg.route",
        "http://juice-shop.test/rest/products/3/reviews",
        "http://juice-shop.test/path/with-dash/and_underscore",
        "http://juice-shop.test/path/with.dot/segment",
        "http://juice-shop.test/rest/products/search?q=apple",  # クエリのメタ文字は許容
        "http://juice-shop.test/api/BasketItems;matrix=1",       # matrix param(;) は path で許容
        "http://juice-shop.test/%E3%83%86%E3%82%B9%E3%83%88/route",  # percent-encoded
        "http://odata.test/Products(1)",                         # OData: 括弧は実ルート（Codex #100）
        "http://odata.test/Users('alice')",                      # OData: 引用キー付き括弧
        "http://odata.test/Categories(1)/Products",              # OData: 括弧の後にセグメント継続
        "http://juice-shop.test/search?pattern=.*",              # クエリ値の regex 片は path 無関係で許容
        "http://juice-shop.test/rest/x?re=(?:a|b)",              # クエリの regex は path を汚さない
        "http://juice-shop.test/languages/C++",                  # + は path の正当な文字（Codex #100 R2）
        "http://juice-shop.test/rest/tags/a*b",                  # * も path で正当
        "http://odata.test/odata/GetDefault()/value",            # parameterless 関数ルート（識別子直後の()）
        "https://api.example.test/",                             # origin-root（別オリジンで実ルートになりうる）
    ]

    # minified JS の regex リテラル/式片の誤抽出（すべて除去されるべき）。
    GARBAGE = [
        "http://juice-shop.test/(?:",
        "http://juice-shop.test/16*(a.flipX",
        "http://juice-shop.test/()",
        "http://juice-shop.test/(?:foo|bar)",
        "http://juice-shop.test/[^a-z]+",
        "http://juice-shop.test/a.*b",
        "http://juice-shop.test/{n}",
        "http://juice-shop.test/foo|bar",
        "http://juice-shop.test/a^b",
        "http://juice-shop.test/(a|b)",       # 区切り直後の開き括弧＝regex リテラル片
    ]

    def test_real_routes_are_kept(self):
        for url in self.REAL_ROUTES:
            with self.subTest(url=url):
                self.assertTrue(
                    is_plausible_route_candidate(url),
                    f"実ルートを誤って除去した: {url}",
                )

    def test_garbage_is_rejected(self):
        for url in self.GARBAGE:
            with self.subTest(url=url):
                self.assertFalse(
                    is_plausible_route_candidate(url),
                    f"ゴミ URL を除去できなかった: {url}",
                )

    def test_non_http_scheme_rejected(self):
        self.assertFalse(is_plausible_route_candidate("javascript:void(0)"))
        self.assertFalse(is_plausible_route_candidate("data:text/html,x"))
        self.assertFalse(is_plausible_route_candidate(""))

    def test_filter_dedups_and_preserves_order(self):
        cands = [
            "http://h/rest/a",
            "http://h/(?:",        # ゴミ（regex 群）
            "http://h/rest/b",
            "http://h/rest/a",     # 重複
            "http://h/a|b",        # ゴミ（| は URL 不正）
        ]
        self.assertEqual(
            filter_route_candidates(cands),
            ["http://h/rest/a", "http://h/rest/b"],
        )

    def test_empty_input(self):
        self.assertEqual(filter_route_candidates([]), [])
        self.assertEqual(filter_route_candidates(None), [])


class CollectUrlsFromAssetsIntegrationTests(unittest.TestCase):
    """`_collect_urls_from_loaded_assets` がゴミを除去し実ルートを残すことを、
    ブラウザ非依存（network.pairs を差し替え）で検証する。"""

    class _Net:
        def __init__(self, pairs):
            self.pairs = pairs

    class _Harness:
        from wscan.browser import BrowserManager as _BM
        _collect_urls_from_loaded_assets = _BM._collect_urls_from_loaded_assets

        def __init__(self, pairs):
            self.network = CollectUrlsFromAssetsIntegrationTests._Net(pairs)

    def test_extracts_real_routes_and_drops_regex_garbage(self):
        # minified JS 風の本文：実ルート（fetch/href）と regex リテラル/式片を混在。
        js_body = (
            "fetch('/rest/products/search?q='+q);"
            "r.push('/api/Users');"
            "var re=/(?:foo|bar)/g; var x=/16*(a.flipX?-1:1/;"
            "if(s.match(/[^a-z]+/)){} var p='/rest/user/whoami';"
            "n.route('/()?;=');"
        )
        pairs = [{
            "request": {"url": "http://juice-shop.test/main.js"},
            "response": {
                "url": "http://juice-shop.test/main.js",
                "headers": {"content-type": "application/javascript"},
                "body": js_body,
            },
        }]
        harness = self._Harness(pairs)
        found = harness._collect_urls_from_loaded_assets("http://juice-shop.test/")

        # 実ルートは残る。
        for real in (
            "http://juice-shop.test/rest/products/search",
            "http://juice-shop.test/api/Users",
            "http://juice-shop.test/rest/user/whoami",
        ):
            self.assertTrue(
                any(u.startswith(real) for u in found),
                f"実ルートが抽出されなかった: {real} / got={found}",
            )
        # regex 由来のゴミ（メタ文字）は 1 件も残らない。
        for u in found:
            self.assertFalse(
                any(c in u for c in "[]{}|^`\\<>"),  # URL として不正な文字（*+() は正当なので除く）
                f"ゴミ URL が残った: {u}",
            )


if __name__ == "__main__":
    unittest.main()
