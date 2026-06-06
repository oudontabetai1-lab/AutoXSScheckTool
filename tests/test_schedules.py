"""定期スキャンの期限判定ロジック（純粋関数）のテスト。"""
import unittest

from wscan.monitor import due_schedule_ids


class DueScheduleTests(unittest.TestCase):
    NOW = 1_000_000_000

    def test_due_when_next_run_past_and_enabled(self):
        schedules = [
            {"id": "a", "enabled": True, "next_run": self.NOW - 10},
            {"id": "b", "enabled": True, "next_run": self.NOW + 10},  # 未来 → 対象外
        ]
        self.assertEqual(due_schedule_ids(schedules, self.NOW), ["a"])

    def test_disabled_never_due(self):
        schedules = [{"id": "a", "enabled": False, "next_run": self.NOW - 100}]
        self.assertEqual(due_schedule_ids(schedules, self.NOW), [])

    def test_exactly_now_is_due(self):
        schedules = [{"id": "a", "enabled": True, "next_run": self.NOW}]
        self.assertEqual(due_schedule_ids(schedules, self.NOW), ["a"])

    def test_missing_next_run_treated_as_due(self):
        schedules = [{"id": "a", "enabled": True}]
        self.assertEqual(due_schedule_ids(schedules, self.NOW), ["a"])

    def test_invalid_next_run_does_not_crash(self):
        schedules = [{"id": "a", "enabled": True, "next_run": "oops"}]
        self.assertEqual(due_schedule_ids(schedules, self.NOW), ["a"])

    def test_empty(self):
        self.assertEqual(due_schedule_ids([], self.NOW), [])


if __name__ == "__main__":
    unittest.main()
