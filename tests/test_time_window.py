"""検査時間帯ゲート（純粋関数）のテスト。"""
import unittest
from datetime import datetime

from wscan.time_window import (
    WindowRule,
    parse_window,
    parse_windows,
    is_allowed,
    seconds_until_allowed,
)


class ParseTests(unittest.TestCase):
    def test_simple_daily(self):
        r = parse_window("09:00-18:00")
        self.assertEqual(r.start, 540)
        self.assertEqual(r.end, 1080)
        self.assertEqual(r.days, frozenset(range(7)))

    def test_weekday_range(self):
        r = parse_window("Mon-Fri 22:00-06:00")
        self.assertEqual(r.days, frozenset({0, 1, 2, 3, 4}))
        self.assertEqual(r.start, 1320)
        self.assertEqual(r.end, 360)

    def test_day_list(self):
        r = parse_window("Sat,Sun 00:00-24:00")
        self.assertEqual(r.days, frozenset({5, 6}))
        self.assertEqual(r.end, 1440)

    def test_invalid_returns_none(self):
        self.assertIsNone(parse_window("not a window"))
        self.assertIsNone(parse_window("25:00-26:00"))
        self.assertIsNone(parse_window(""))
        self.assertIsNone(parse_window("10:00-10:00"))  # ゼロ幅

    def test_parse_windows_csv(self):
        # 複数ウィンドウはセミコロン区切り（カンマは曜日リスト専用）
        rules = parse_windows("09:00-12:00; 13:00-18:00")
        self.assertEqual(len(rules), 2)

    def test_parse_windows_weekday_list_not_split(self):
        # "Sat,Sun 00:00-24:00" を 1 本のルールとして扱う（カンマで割らない）
        rules = parse_windows("Sat,Sun 00:00-24:00")
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].days, frozenset({5, 6}))

    def test_parse_windows_list_skips_bad(self):
        rules = parse_windows(["09:00-18:00", "garbage"])
        self.assertEqual(len(rules), 1)


class ContainsTests(unittest.TestCase):
    # 2024-01-01 is a Monday.
    def test_same_day_window(self):
        r = parse_window("09:00-18:00")
        self.assertTrue(r.contains(datetime(2024, 1, 1, 10, 0)))
        self.assertFalse(r.contains(datetime(2024, 1, 1, 18, 0)))  # end is exclusive
        self.assertFalse(r.contains(datetime(2024, 1, 1, 8, 59)))

    def test_overnight_window(self):
        r = parse_window("22:00-06:00")
        self.assertTrue(r.contains(datetime(2024, 1, 1, 23, 0)))   # late evening
        self.assertTrue(r.contains(datetime(2024, 1, 1, 2, 0)))    # early morning
        self.assertFalse(r.contains(datetime(2024, 1, 1, 12, 0)))  # midday

    def test_weekday_restriction(self):
        r = parse_window("Mon-Fri 09:00-18:00")
        self.assertTrue(r.contains(datetime(2024, 1, 1, 10, 0)))   # Monday
        self.assertFalse(r.contains(datetime(2024, 1, 6, 10, 0)))  # Saturday


class IsAllowedTests(unittest.TestCase):
    def test_no_rules_always_allowed(self):
        self.assertTrue(is_allowed(datetime(2024, 1, 1, 3, 0), [], []))

    def test_allowed_only(self):
        allowed = parse_windows(["22:00-06:00"])
        self.assertTrue(is_allowed(datetime(2024, 1, 1, 23, 0), allowed, []))
        self.assertFalse(is_allowed(datetime(2024, 1, 1, 12, 0), allowed, []))

    def test_forbidden_takes_precedence(self):
        allowed = parse_windows(["00:00-24:00"])
        forbidden = parse_windows(["12:00-13:00"])
        self.assertFalse(is_allowed(datetime(2024, 1, 1, 12, 30), allowed, forbidden))
        self.assertTrue(is_allowed(datetime(2024, 1, 1, 14, 0), allowed, forbidden))

    def test_forbidden_only(self):
        forbidden = parse_windows(["09:00-18:00"])
        self.assertFalse(is_allowed(datetime(2024, 1, 1, 10, 0), [], forbidden))
        self.assertTrue(is_allowed(datetime(2024, 1, 1, 20, 0), [], forbidden))


class SecondsUntilAllowedTests(unittest.TestCase):
    def test_zero_when_allowed(self):
        self.assertEqual(
            seconds_until_allowed(datetime(2024, 1, 1, 10, 0),
                                  parse_windows(["09:00-18:00"]), []),
            0.0,
        )

    def test_waits_for_next_window(self):
        allowed = parse_windows(["22:00-23:00"])
        now = datetime(2024, 1, 1, 21, 30)
        self.assertEqual(seconds_until_allowed(now, allowed, []), 30 * 60)

    def test_waits_out_forbidden(self):
        forbidden = parse_windows(["12:00-13:00"])
        now = datetime(2024, 1, 1, 12, 0)
        self.assertEqual(seconds_until_allowed(now, [], forbidden), 60 * 60)

    def test_unreachable_returns_inf(self):
        # allowed window exists but on a day that never matches forbidden-everything
        allowed = parse_windows(["Mon 09:00-10:00"])
        forbidden = parse_windows(["00:00-24:00"])  # forbid all the time
        now = datetime(2024, 1, 1, 0, 0)
        self.assertEqual(seconds_until_allowed(now, allowed, forbidden), float("inf"))


class TimeGateActiveDecouplingTests(unittest.TestCase):
    """時間帯ゲートが controller._active に依存しないこと（非TTY/--no-monitor 回帰）。"""

    def test_gate_runs_when_inactive(self):
        import asyncio
        from wscan.intervention import ScanController, AbortScan

        c = ScanController()
        # 終日禁止 → 常に窓の外。_active=False（非TTYでキーリーダーが落ちた状態）でも
        # ゲートはループに入り、abort で抜ける（= 黙って素通りしない）。
        c.set_time_windows(forbidden=["00:00-24:00"])
        c._active = False
        c._abort = True
        with self.assertRaises(AbortScan):
            asyncio.run(c._time_gate())


if __name__ == "__main__":
    unittest.main()
