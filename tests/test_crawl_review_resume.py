"""検査前レビュー（巡回レビュー）の再開判定のテスト。

`_crawl_review_wants_recrawl` は「continue（検査開始）でレビューが再表示される」
不具合の核。continue では絶対に再巡回しない＝ループしないことを保証する。
"""
import unittest

from wscan.engine import _crawl_review_wants_recrawl


class TestCrawlReviewResume(unittest.TestCase):
    def test_recrawl_command_triggers_recrawl(self):
        self.assertTrue(_crawl_review_wants_recrawl("recrawl"))
        self.assertTrue(_crawl_review_wants_recrawl("  RECRAWL  "))

    def test_continue_never_recrawls(self):
        # 検査開始では再巡回しない（=レビュー再表示ループを防ぐ）。
        self.assertFalse(_crawl_review_wants_recrawl("continue"))
        self.assertFalse(_crawl_review_wants_recrawl("CONTINUE"))

    def test_cancel_and_unknown_do_not_recrawl(self):
        self.assertFalse(_crawl_review_wants_recrawl("cancel"))
        self.assertFalse(_crawl_review_wants_recrawl(""))
        self.assertFalse(_crawl_review_wants_recrawl(None))  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
