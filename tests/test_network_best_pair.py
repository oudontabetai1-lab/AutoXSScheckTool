"""NetworkCapture.best_pair_for_page のユニットテスト。

フォーム送信 / URL パラメータ注入の後、アナリティクス等の別 URL ビーコンが
最後に飛ぶと、単純な latest() ではレポートの request/response が検査対象では
ない別 URL になってしまう。best_pair_for_page が対象ページ（同一オリジンの
文書本体）を正しく選ぶことを検証する。
"""
import unittest

from wscan.browser import NetworkCapture


def _pair(url: str, *, ctype: str = "text/html", status: int = 200, method: str = "GET") -> dict:
    return {
        "request": {"url": url, "method": method},
        "response": {"url": url, "status": status, "headers": {"content-type": ctype}},
    }


class BestPairForPageTests(unittest.TestCase):
    def test_exact_url_match_wins(self):
        cap = NetworkCapture()
        cap.pairs = [
            _pair("https://app.example.com/search?q=x"),
            _pair("https://www.google-analytics.com/collect", ctype="text/plain", method="POST"),
        ]
        pair = cap.best_pair_for_page("https://app.example.com/search?q=x")
        self.assertEqual(pair["response"]["url"], "https://app.example.com/search?q=x")

    def test_ignores_cross_origin_analytics_beacon(self):
        # 対象ページの後にサードパーティのアナリティクス POST が飛んだケース。
        # 完全一致が無くても同一オリジンの文書本体を選ぶ。
        cap = NetworkCapture()
        cap.pairs = [
            _pair("https://app.example.com/submit"),  # 文書本体（HTML）
            _pair("https://analytics.thirdparty.net/track", ctype="application/json", method="POST"),
        ]
        # わざと path 違いの URL で問い合わせ（redirect 等で完全一致しない状況）
        pair = cap.best_pair_for_page("https://app.example.com/result")
        self.assertEqual(pair["response"]["url"], "https://app.example.com/submit")

    def test_prefers_html_document_over_same_origin_asset(self):
        cap = NetworkCapture()
        cap.pairs = [
            _pair("https://app.example.com/page"),  # HTML 文書
            _pair("https://app.example.com/app.js", ctype="application/javascript"),
            _pair("https://app.example.com/style.css", ctype="text/css"),
        ]
        pair = cap.best_pair_for_page("https://app.example.com/other")
        self.assertEqual(pair["response"]["url"], "https://app.example.com/page")

    def test_falls_back_to_same_origin_when_no_html(self):
        # 対象が JSON API で HTML 文書が無い場合は同一オリジンの最新を返す。
        cap = NetworkCapture()
        cap.pairs = [
            _pair("https://app.example.com/api/a", ctype="application/json", method="POST"),
            _pair("https://app.example.com/api/b", ctype="application/json", method="POST"),
        ]
        pair = cap.best_pair_for_page("https://app.example.com/api/missing")
        # reversed 走査なので最新（/api/b）
        self.assertEqual(pair["response"]["url"], "https://app.example.com/api/b")

    def test_returns_none_when_only_cross_origin(self):
        cap = NetworkCapture()
        cap.pairs = [
            _pair("https://analytics.thirdparty.net/track", ctype="application/json", method="POST"),
        ]
        pair = cap.best_pair_for_page("https://app.example.com/page")
        self.assertIsNone(pair)


if __name__ == "__main__":
    unittest.main()
