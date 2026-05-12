import unittest
from pathlib import Path


class AuthCrawlSeedTests(unittest.TestCase):
    def test_engine_seeds_auto_login_landing_url(self):
        text = Path("wscan/engine.py").read_text(encoding="utf-8")
        expected = (
            "self.auth_landing_url",
            "last_login_url",
            "ログイン後ページをクロールキューに追加",
            "queue.append((self.auth_landing_url, 0, self.target_url))",
        )

        for marker in expected:
            with self.subTest(marker=marker):
                self.assertIn(marker, text)

    def test_browser_waits_for_login_navigation_before_polling(self):
        text = Path("wscan/browser.py").read_text(encoding="utf-8")
        expected = (
            "expect_navigation",
            "last_login_url",
            "success_indicator in post_url or success_indicator in post_body",
        )

        for marker in expected:
            with self.subTest(marker=marker):
                self.assertIn(marker, text)


if __name__ == "__main__":
    unittest.main()
