"""remediation の action plan が verification_state を出力し assumed を明示することのテスト。"""
import unittest

from wscan.action_plan import build_action_plan
from wscan.scanners.base import Finding


def _finding(state, confidence="confirmed", verified=True, field_name="q"):
    f = Finding(
        check_type="sqli", severity="high", url="http://h/a", field_name=field_name,
        payload="'", evidence="SQL error", evidence_type="sqli_error",
        confidence=confidence, verified=verified,
    )
    f.verification_state = state
    return f


class ActionPlanVerificationStateTests(unittest.TestCase):
    def test_task_exports_state_and_flags_assumed(self):
        plan = build_action_plan([_finding("assumed")])
        self.assertEqual(len(plan["tasks"]), 1)
        task = plan["tasks"][0]
        self.assertEqual(task["verification_state"], "assumed")
        # assumed は「消さない（タスクとして残す）が要手動確認」を明示。
        self.assertTrue(task["needs_confirmation"])

    def test_reproduced_not_flagged(self):
        task = build_action_plan([_finding("reproduced")])["tasks"][0]
        self.assertEqual(task["verification_state"], "reproduced")
        self.assertFalse(task["needs_confirmation"])

    def test_assumed_and_reproduced_distinguishable_in_task_data(self):
        # 同じ severity/confidence/verified でも state で区別できる（"indistinguishable" 解消）。
        # 別フィールドにして別タスクへ（同一 group にまとめられないように）。
        tasks = build_action_plan([
            _finding("assumed", field_name="a"),
            _finding("reproduced", confidence="likely", field_name="b"),
        ])["tasks"]
        states = {t["verification_state"] for t in tasks}
        self.assertIn("assumed", states)
        self.assertIn("reproduced", states)

    def test_review_item_exports_state(self):
        # verified=False は review-only。そこにも state を出す。
        plan = build_action_plan([_finding("unreproduced", verified=False)])
        self.assertEqual(len(plan["review_items"]), 1)
        self.assertEqual(plan["review_items"][0]["verification_state"], "unreproduced")


if __name__ == "__main__":
    unittest.main()
