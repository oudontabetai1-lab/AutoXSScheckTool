"""自動再ログイン後の Cookie 同期（ドメイン方向）のテスト。

ブラウザの送出規則に合わせ、対象ホスト宛に送られる Cookie（完全一致 or 親ドメイン
スコープ）だけを self.cookies へ写すこと。サブドメインスコープの Cookie を親へ
持ち込まない（セッション漏えい防止）。
"""
import asyncio
import types
import unittest

from wscan.engine import ScanEngine


class _Ctx:
    def __init__(self, cookies):
        self._cookies = cookies

    async def cookies(self):
        return self._cookies


def _run_sync(target_url, cookies, initial="", for_url=""):
    browser = types.SimpleNamespace(page=types.SimpleNamespace(context=_Ctx(cookies)))
    eng = types.SimpleNamespace(target_url=target_url, cookies=initial)
    asyncio.run(ScanEngine._sync_cookies_from_browser(eng, browser, for_url=for_url))
    return eng.cookies


class CookiePathMatchTests(unittest.TestCase):
    def test_path_match_pure(self):
        from wscan.engine import _cookie_path_matches
        self.assertTrue(_cookie_path_matches("/api/users", "/"))
        self.assertTrue(_cookie_path_matches("/admin/x", "/admin"))
        self.assertTrue(_cookie_path_matches("/admin", "/admin"))
        self.assertFalse(_cookie_path_matches("/api/users", "/admin"))
        # 境界チェック: /admin は /administrator にマッチしない
        self.assertFalse(_cookie_path_matches("/administrator", "/admin"))

    def test_path_scoped_cookie_not_sent_to_other_path(self):
        cookies = [{"name": "s", "value": "x", "domain": "example.com", "path": "/admin"}]
        result = _run_sync("https://example.com/", cookies,
                           for_url="https://example.com/api/users")
        self.assertEqual(result, "")

    def test_longer_path_cookie_sent_first(self):
        # RFC 6265 §5.4: 同名 Cookie が / と /admin にあるとき、より具体的な
        # /admin（長い path）を先頭に送る。最初の値を使うフレームワークが
        # root の Cookie で誤ったセッションを選ばないようにする。
        cookies = [
            {"name": "sid", "value": "root", "domain": "example.com", "path": "/"},
            {"name": "sid", "value": "admin", "domain": "example.com", "path": "/admin"},
        ]
        result = _run_sync("https://example.com/admin/panel", cookies,
                           for_url="https://example.com/admin/panel")
        # 両方 path 一致するが、/admin が先頭に来る
        self.assertEqual(result, "sid=admin; sid=root")


class CookieHeaderForUrlTests(unittest.TestCase):
    def _hdr(self, cookies, url):
        browser = types.SimpleNamespace(page=types.SimpleNamespace(context=_Ctx(cookies)))
        eng = types.SimpleNamespace(browser=browser)
        return asyncio.run(ScanEngine.cookie_header_for_url(eng, url))

    def test_origin_vs_page_path_scope(self):
        # cookie_header_for_url は URL 単位で path スコープする（#157）。
        cookies = [
            {"name": "root", "value": "r", "domain": "example.com", "path": "/"},
            {"name": "adm", "value": "a", "domain": "example.com", "path": "/admin"},
        ]
        # origin ルート(/): Path=/ の Cookie のみ（Path=/admin は送らない）。
        self.assertEqual(self._hdr(cookies, "https://example.com"), "root=r")
        # page(/admin): 両方送る（長い path が先）。
        self.assertEqual(self._hdr(cookies, "https://example.com/admin"), "adm=a; root=r")

    def test_no_browser_returns_empty(self):
        eng = types.SimpleNamespace(browser=types.SimpleNamespace(page=None))
        self.assertEqual(asyncio.run(ScanEngine.cookie_header_for_url(eng, "https://x.test")), "")

    def test_secure_cookie_excluded_over_http(self):
        # Secure Cookie は HTTP 宛には送らず、HTTPS 宛には送る（Codex #157）。
        from wscan.engine import _scoped_cookie_header
        cookies = [
            {"name": "sid", "value": "s", "domain": "example.com", "path": "/", "secure": True},
            {"name": "lang", "value": "ja", "domain": "example.com", "path": "/", "secure": False},
        ]
        self.assertEqual(_scoped_cookie_header(cookies, "http://example.com/"), "lang=ja")
        self.assertEqual(_scoped_cookie_header(cookies, "https://example.com/"), "sid=s; lang=ja")


class CookieDomainSyncTests(unittest.TestCase):
    def test_exact_and_parent_accepted_subdomain_rejected(self):
        cookies = [
            {"name": "a", "value": "1", "domain": "example.com"},        # exact
            {"name": "b", "value": "2", "domain": "admin.example.com"},  # subdomain → reject
            {"name": "c", "value": "3", "domain": ".example.com"},       # parent → accept
        ]
        result = _run_sync("https://example.com/app", cookies)
        self.assertIn("a=1", result)
        self.assertIn("c=3", result)
        self.assertNotIn("b=2", result)

    def test_domain_cookie_reaches_subdomain(self):
        # ドメイン Cookie（先頭ドット）は子サブドメインへ届く
        cookies = [{"name": "s", "value": "x", "domain": ".example.com"}]
        result = _run_sync("https://app.example.com/", cookies)
        self.assertIn("s=x", result)

    def test_host_only_cookie_not_sent_to_subdomain(self):
        # host-only Cookie（先頭ドット無し）は子サブドメインへ送らない
        cookies = [{"name": "s", "value": "x", "domain": "example.com"}]
        result = _run_sync("https://app.example.com/", cookies)
        self.assertEqual(result, "")

    def test_unrelated_domain_rejected(self):
        cookies = [{"name": "z", "value": "9", "domain": "evil.test"}]
        result = _run_sync("https://example.com/", cookies)
        self.assertEqual(result, "")

    def test_empty_jar_clears_cookies(self):
        # ブラウザの cookie jar が空ならクリアする（stale を送り続けない）
        result = _run_sync("https://example.com/", [], initial="old=stale")
        self.assertEqual(result, "")

    def test_stale_cookie_cleared_when_no_match(self):
        # 前 URL 用の cookie が残っていても、当該ホストに一致が無ければクリアする
        # （別ホストの Cookie を誤送信しない）。
        cookies = [{"name": "api", "value": "1", "domain": "api.example.com"}]
        result = _run_sync(
            "https://www.example.com/", cookies,
            initial="old=fromprevioushost", for_url="https://other.example.org/x",
        )
        self.assertEqual(result, "")


if __name__ == "__main__":
    unittest.main()
