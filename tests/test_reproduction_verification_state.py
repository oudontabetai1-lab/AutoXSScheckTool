"""reproduction package が verification_state/note を保持することのテスト。"""
import unittest

from wscan.reproduction import _finding_to_repro_item
from wscan.scanners.base import Finding


def _finding(state, note=""):
    return Finding(
        check_type="sqli", severity="high", url="http://h/a", field_name="q",
        payload="'", evidence="SQL error", evidence_type="sqli_error",
        verification_state=state, verification_note=note,
    )


class ReproductionVerificationStateTests(unittest.TestCase):
    def test_repro_item_includes_state_and_note(self):
        item = _finding_to_repro_item(_finding("skipped", note="要手動確認"), 1)
        self.assertEqual(item["verification_state"], "skipped")
        self.assertEqual(item["verification_note"], "要手動確認")

    def test_assumed_and_reproduced_distinguishable(self):
        # reproduced のみ verified=True、assumed は verified=False。state も保持する。
        a = _finding_to_repro_item(_finding("assumed"), 1)
        r = _finding_to_repro_item(_finding("reproduced"), 2)
        self.assertFalse(a["verified"])
        self.assertTrue(r["verified"])
        self.assertNotEqual(a["verification_state"], r["verification_state"])

    def test_skipped_and_unreproduced_distinguishable(self):
        # verified が同値(False)でも state で skipped/unreproduced を区別できる。
        s = _finding_to_repro_item(_finding("skipped"), 1)
        u = _finding_to_repro_item(_finding("unreproduced"), 2)
        self.assertEqual(s["verified"], u["verified"])
        self.assertNotEqual(s["verification_state"], u["verification_state"])


if __name__ == "__main__":
    unittest.main()
