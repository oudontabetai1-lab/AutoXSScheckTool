"""0009 C1: JS 資産由来のゴミ URL 除去（純粋関数）の回帰テスト。

誤抽出0（regex/式片を弾く）と実ルート維持（到達性を落とさない）を同時に守る。
"""
import unittest

from wscan.url_extraction import (
    is_plausible_route_candidate,
    filter_route_candidates,
    truncated_regex_literal,
    regex_literal_end,
    is_regex_literal_extraction,
    preceding_nonspace,
    strip_trailing_noise,
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

    def test_strip_trailing_noise_keeps_balanced_parens(self):
        # OData/関数の均衡した末尾括弧は残す（Codex #100 R4）。
        self.assertEqual(strip_trailing_noise("/Products(1)"), "/Products(1)")
        self.assertEqual(strip_trailing_noise("/odata/GetDefault()"), "/odata/GetDefault()")
        # 余分な閉じ（外側の () を取り込んだ）だけ剥がす。
        self.assertEqual(strip_trailing_noise("/api/x)"), "/api/x")
        self.assertEqual(strip_trailing_noise("/api/x]"), "/api/x")
        # 空白・引用符・区切りは常に剥がす。
        self.assertEqual(strip_trailing_noise("/api/x'"), "/api/x")
        self.assertEqual(strip_trailing_noise("/api/x , "), "/api/x")

    def test_preceding_nonspace_skips_whitespace(self):
        self.assertEqual(preceding_nonspace("x =  /foo/", 5), "=")
        self.assertEqual(preceding_nonspace("'/foo'", 1), "'")
        self.assertEqual(preceding_nonspace("/foo", 0), "")

    def test_is_regex_literal_extraction_uses_context_and_shape(self):
        # regex を導く文脈 + 閉じた /…/flags 形 → regex リテラル。
        for prev in "=(,:[!&|?{;":
            with self.subTest(prev=prev):
                self.assertTrue(is_regex_literal_extraction(prev, "/foo.bar/"))
        self.assertTrue(is_regex_literal_extraction("=", "/foo$/"))
        self.assertTrue(is_regex_literal_extraction("(", "/foo+/g"))
        # 現行の全 JS フラグ（d/v を含む）を認識する（Codex #100 R5）。
        for flags in ("d", "v", "gd", "dgimsuvy"):
            with self.subTest(flags=flags):
                self.assertTrue(is_regex_literal_extraction("=", f"/foo/{flags}"))
        # 文字列リテラル由来（引用符/識別子が直前）→ 実ルートとして残す。
        self.assertFalse(is_regex_literal_extraction("'", "/foo.bar/"))
        self.assertFalse(is_regex_literal_extraction('"', "/api/v1/"))
        self.assertFalse(is_regex_literal_extraction("o", "/foo/"))  # 識別子直後
        # 形が /…/ でない（末尾が / でない実ルート）→ 文脈が regex でも対象外。
        self.assertFalse(is_regex_literal_extraction("=", "/rest/products/search"))
        # 式キーワード直後の regex（return/throw/yield 等）も文脈として認識（Codex #100 R6）。
        for kw in ("return", "throw ", "yield", "typeof", "x=case", "instanceof"):
            with self.subTest(kw=kw):
                self.assertTrue(is_regex_literal_extraction(kw, "/foo/"))
        # 通常の識別子直後（メソッド名等）は regex 文脈ではない → 実ルート扱い。
        self.assertFalse(is_regex_literal_extraction("myfunc", "/foo/"))
        # メンバ呼び出しで使う regex（/foo/.method(x)）も形として認識（Codex #100 R6）。
        self.assertTrue(is_regex_literal_extraction("=", "/foo/.test(value)"))
        self.assertTrue(is_regex_literal_extraction("return", "/foo/g.match(s)"))
        # 行頭（式先頭）も regex 文脈。
        self.assertTrue(is_regex_literal_extraction("", "/foo/"))
        # escaped slash 後に再抽出される regex 片（/foo\/bar/ → /bar/）も、直前 \ を文脈として弾く。
        self.assertTrue(is_regex_literal_extraction("\\", "/bar/"))
        # 制御ヘッダの `)` 直後の regex は文脈として認識（Codex #100 R8）。
        self.assertTrue(is_regex_literal_extraction("if (ready)", "/foo/.test(value)"))
        self.assertTrue(is_regex_literal_extraction("while (x > 0)", "/foo/"))
        # 関数呼び出しの `)` は除算文脈 → regex 扱いしない。
        self.assertFalse(is_regex_literal_extraction("compute(a, b)", "/foo/"))
        # 実パスの /.well-known 等（member-call 形だが文脈が regex でない）は残す。
        self.assertFalse(is_regex_literal_extraction("'", "/api/.well-known/x"))
        self.assertFalse(is_regex_literal_extraction("compute()", "/api/.well-known/x"))

    def test_regex_literal_end_skips_escaped_slash_and_class(self):
        # /escpat\/subpat/ : 切り詰めは escpat の後（\ の位置）。閉じ / まで読み飛ばす。
        body = "var e=/escpat\\/subpat/;fetch(x)"
        trunc_pos = body.index("\\")          # 切り詰め位置（\）
        end = regex_literal_end(body, trunc_pos)
        # 閉じ / の直後（; の位置）まで進む。
        self.assertEqual(body[end], ";")
        self.assertLess(body.index("subpat"), end)  # subpat は skip 範囲内
        # 文字クラス内の / は閉じでない。
        body2 = "=/a[/]b/g;"
        self.assertEqual(body2[regex_literal_end(body2, 2)], ";")
        # 閉じが無ければ pos を返す（安全側）。
        self.assertEqual(regex_literal_end("/nope", 1), 1)

    def test_truncated_regex_literal_detects_continuation_chars(self):
        # regex 継続文字（url_re が手前で切る）→ 切り詰めと判定。
        for ch in "|[]\\^{}":
            with self.subTest(ch=ch):
                self.assertTrue(truncated_regex_literal(ch))
        # 文字列/式の正常終端や空 → 切り詰めではない。
        for ch in ("'", '"', "`", ";", ")", " ", "", "/", "?"):
            with self.subTest(ch=ch):
                self.assertFalse(truncated_regex_literal(ch))


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
            # url_re が | や [ の手前で切り詰める regex リテラル。切り詰め後は /foo /abc に
            # 見えるが、直後の regex 継続文字で抽出時に弾く。
            "var a=/foo|bar/; var b=/abc[0-9]/;"
            # 切り詰められない完全な regex リテラル（url_re 文字のみ）。直前の文脈で弾く。
            "var c=/zab.qux/g; if(s.match(/quux$/)){}"
            # 式キーワード直後・メンバ呼び出しの regex も文脈で弾く。
            "function f(){return /retpat.x/;} var q=/membpat.x/.test(z);"
            # escaped slash を含む regex（/escpat\/subpat/）。/subpat/ が再抽出されるが \ 文脈で弾く。
            "var e=/escpat\\/subpat/;"
            # OData/関数の末尾括弧を持つ実ルート（文字列リテラル由来 → 残す）。
            "fetch('/Products(1)'); fetch('/odata/GetDefault()');"
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
        # 切り詰められた regex リテラル（/foo|bar/→/foo, /abc[0-9]/→/abc）は抽出されない。
        self.assertNotIn("http://juice-shop.test/foo", found)
        self.assertNotIn("http://juice-shop.test/abc", found)
        # 切り詰められない完全な regex リテラル（/zab.qux/・/quux$/）も文脈で弾く。
        self.assertFalse(any("zab.qux" in u for u in found), f"regex /zab.qux/ が残った: {found}")
        self.assertFalse(any("quux" in u for u in found), f"regex /quux$/ が残った: {found}")
        # 式キーワード直後・メンバ呼び出しの regex も弾く。
        self.assertFalse(any("retpat" in u for u in found), f"return /re/ が残った: {found}")
        self.assertFalse(any("membpat" in u for u in found), f"/re/.method() が残った: {found}")
        # escaped slash の後半片（/subpat/）も残らない。
        self.assertFalse(any("subpat" in u for u in found), f"escaped-slash 片が残った: {found}")
        # OData/関数の末尾括弧を持つ実ルートは残る（C1-g）。
        self.assertIn("http://juice-shop.test/Products(1)", found)
        self.assertIn("http://juice-shop.test/odata/GetDefault()", found)
        # regex 由来のゴミ（メタ文字）は 1 件も残らない。
        for u in found:
            self.assertFalse(
                any(c in u for c in "[]{}|^`\\<>"),  # URL として不正な文字（*+() は正当なので除く）
                f"ゴミ URL が残った: {u}",
            )


if __name__ == "__main__":
    unittest.main()
