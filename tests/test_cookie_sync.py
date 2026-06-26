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

    def test_subdomain_target_accepts_parent_cookie(self):
        # target が app.example.com なら親 example.com の Cookie は届く
        cookies = [{"name": "s", "value": "x", "domain": "example.com"}]
        result = _run_sync("https://app.example.com/", cookies)
        self.assertIn("s=x", result)

    def test_unrelated_domain_rejected(self):
        cookies = [{"name": "z", "value": "9", "domain": "evil.test"}]
        result = _run_sync("https://example.com/", cookies)
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
