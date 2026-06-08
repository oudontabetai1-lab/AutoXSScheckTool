"""SQLi 時間ベース判定 `_is_time_based_sql` の回帰テスト。

進化wave・community 由来の任意クォート方言の遅延ペイロードでも時間判定が
走る（=固定リスト依存をやめた）ことを保証する。
"""
import unittest

from wscan.scanners.sqli import _is_time_based_sql


class IsTimeBasedSqlTests(unittest.TestCase):
    def test_detects_sleep_and_waitfor_dialects(self):
        for p in (
            "' OR SLEEP(3)-- -",
            '" OR SLEEP(3)-- -',
            "'; WAITFOR DELAY '0:0:3'--",
            "1) AND SLEEP(3)--",
            "1' AND pg_sleep(3)--",
            "1' AND BENCHMARK(3000000,MD5('a'))--",
            "1' AND DBMS_PIPE.RECEIVE_MESSAGE('a',3)--",
        ):
            self.assertTrue(_is_time_based_sql(p), f"missed time-based payload: {p!r}")

    def test_non_time_based_payloads_are_ignored(self):
        for p in (
            "' OR '1'='1",
            "1 UNION SELECT NULL--",
            "admin'--",
            "",
            "no sleep here just text",  # 'sleep' 単語があっても関数呼び出しでなければ無視
        ):
            self.assertFalse(_is_time_based_sql(p), f"false time-based: {p!r}")


if __name__ == "__main__":
    unittest.main()
