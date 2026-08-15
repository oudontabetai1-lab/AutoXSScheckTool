"""_effective_open_report（CLI/config のレポート自動表示解決）のテスト。"""
import types
import unittest

import main


class EffectiveOpenReportTests(unittest.TestCase):
    @staticmethod
    def _args(no_monitor=False, no_open_report=False, open_report=False):
        return types.SimpleNamespace(
            no_monitor=no_monitor,
            no_open_report=no_open_report,
            open_report=open_report,
        )

    def test_default_opens_report(self):
        self.assertTrue(main._effective_open_report(self._args()))

    def test_no_monitor_suppresses_report(self):
        self.assertFalse(main._effective_open_report(self._args(no_monitor=True)))

    def test_no_open_report_suppresses_report(self):
        self.assertFalse(main._effective_open_report(self._args(no_open_report=True)))

    def test_open_report_overrides_no_monitor(self):
        self.assertTrue(
            main._effective_open_report(
                self._args(no_monitor=True, open_report=True)
            )
        )

    def test_no_monitor_and_no_open_report_suppress_report(self):
        self.assertFalse(
            main._effective_open_report(
                self._args(no_monitor=True, no_open_report=True)
            )
        )

    def test_open_report_overrides_no_open_report(self):
        self.assertTrue(
            main._effective_open_report(
                self._args(no_open_report=True, open_report=True)
            )
        )

    def test_missing_attributes_use_defaults(self):
        self.assertTrue(main._effective_open_report(types.SimpleNamespace()))


if __name__ == "__main__":
    unittest.main()
