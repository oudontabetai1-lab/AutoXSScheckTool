"""`scan` の位置引数 URL 複数指定（1 スキャンで複数攻撃対象＝同一ログインセッション）。

`scan https://a https://b https://c` のように複数 URL を渡すと、先頭がクロール起点、
2 つ目以降が追加攻撃スコープ（--target-url と同義）になる。engine 側は
additional_target_urls を depth0 でクロールキューにシードするため、共有認証セッションで
全対象を巡回・攻撃できる。別ログインのサイトを個別並行するなら batch を使う。
"""
import sys
import unittest
from unittest import mock

import main


class CollapseMultiTargetTests(unittest.TestCase):
    def test_single_url_list_collapses_to_string(self):
        primary, extra = main._collapse_multi_target(["https://a"], [])
        self.assertEqual(primary, "https://a")
        self.assertEqual(extra, [])

    def test_multiple_urls_prepend_to_target_urls(self):
        primary, extra = main._collapse_multi_target(
            ["https://a", "https://b", "https://c"], []
        )
        self.assertEqual(primary, "https://a")
        self.assertEqual(extra, ["https://b", "https://c"])

    def test_existing_target_urls_are_preserved_after_extras(self):
        # 位置引数の 2 つ目以降が前、既存 --target-url 由来はその後ろ。
        primary, extra = main._collapse_multi_target(
            ["https://a", "https://b"], ["https://d"]
        )
        self.assertEqual(primary, "https://a")
        self.assertEqual(extra, ["https://b", "https://d"])

    def test_empty_strings_are_dropped(self):
        primary, extra = main._collapse_multi_target(["", "https://a", ""], [])
        self.assertEqual(primary, "https://a")
        self.assertEqual(extra, [])

    def test_plain_string_is_passthrough_backward_compat(self):
        primary, extra = main._collapse_multi_target("https://a", ["https://b"])
        self.assertEqual(primary, "https://a")
        self.assertEqual(extra, ["https://b"])


class ParseArgsMultiUrlTests(unittest.TestCase):
    def test_parse_multiple_positional_urls(self):
        argv = ["main.py", "scan", "https://a.example", "https://b.example",
                "--checks", "xss", "os", "--llm", "none"]
        with mock.patch.object(sys, "argv", argv):
            args = main.parse_args()
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.url, ["https://a.example", "https://b.example"])
        self.assertEqual(args.checks, ["xss", "os"])
        # collapse で先頭起点＋残りスコープに分かれる。
        primary, extra = main._collapse_multi_target(args.url, args.target_urls or [])
        self.assertEqual(primary, "https://a.example")
        self.assertEqual(extra, ["https://b.example"])

    def test_parse_single_positional_url_backward_compat(self):
        argv = ["main.py", "scan", "https://only.example", "--depth", "2"]
        with mock.patch.object(sys, "argv", argv):
            args = main.parse_args()
        self.assertEqual(args.url, ["https://only.example"])
        primary, _ = main._collapse_multi_target(args.url, args.target_urls or [])
        self.assertEqual(primary, "https://only.example")


if __name__ == "__main__":
    unittest.main()
