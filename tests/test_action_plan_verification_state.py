"""remediation の action plan が verification_state を出力し assumed を明示することのテスト。"""
import unittest

from wscan.action_plan import build_action_plan
from wscan.scanners.base import Finding


def _finding(state, confidence="confirmed", field_name="q"):
    return Finding(
        check_type="sqli", severity="high", url="http://h/a", field_name=field_name,
        payload="'", evidence="SQL error", evidence_type="sqli_error",
        confidence=confidence, verification_state=state,
    )


class ActionPlanVerificationStateTests(unittest.TestCase):
    def test_assumed_is_retained_as_review_item(self):
        plan = build_action_plan([_finding("assumed")])
        self.assertEqual(len(plan["tasks"]), 0)
        self.assertEqual(len(plan["review_items"]), 1)
        self.assertEqual(plan["review_items"][0]["verification_state"], "assumed")
        self.assertFalse(plan["review_items"][0]["verified"])

    def test_reproduced_and_assumed_split_without_dropping_either(self):
        plan = build_action_plan([_finding("reproduced"), _finding("assumed")])
        self.assertEqual(len(plan["tasks"]), 1)
        self.assertEqual(len(plan["review_items"]), 1)
        self.assertEqual(plan["tasks"][0]["verification_state"], "reproduced")
        self.assertEqual(plan["review_items"][0]["verification_state"], "assumed")

    def test_reproduced_not_flagged(self):
        task = build_action_plan([_finding("reproduced")])["tasks"][0]
        self.assertEqual(task["verification_state"], "reproduced")
        self.assertFalse(task["needs_confirmation"])

    def test_assumed_and_reproduced_distinguishable_in_plan_data(self):
        plan = build_action_plan([
            _finding("assumed", field_name="a"),
            _finding("reproduced", confidence="likely", field_name="b"),
        ])
        self.assertEqual(plan["tasks"][0]["verification_state"], "reproduced")
        self.assertEqual(plan["review_items"][0]["verification_state"], "assumed")

    def test_review_item_exports_state(self):
        # verified=False は review-only。そこにも state を出す。
        plan = build_action_plan([_finding("unreproduced")])
        self.assertEqual(len(plan["review_items"]), 1)
        self.assertEqual(plan["review_items"][0]["verification_state"], "unreproduced")

    def test_markdown_review_section_renders_state(self):
        # remediation_plan.md の Review-only Signals で unreproduced/skipped を区別できる
        # （verified=False で潰さない）。
        from wscan.action_plan import _build_markdown
        plan = build_action_plan([
            _finding("unreproduced", field_name="a"),
            _finding("skipped", field_name="b"),
        ])
        md = _build_markdown(plan["tasks"], plan["review_items"])
        self.assertIn("- Verification: unreproduced", md)
        self.assertIn("- Verification: skipped", md)

    def test_grouped_review_aggregates_states(self):
        # 同一 group（同 field/evidence）で unreproduced と skipped がまとまると、
        # 代表 1 つでなく group 内の全 state を出す（片方の経路を見落とさない）。
        from wscan.action_plan import _build_markdown
        plan = build_action_plan([
            _finding("unreproduced", field_name="q"),
            _finding("skipped", field_name="q"),
        ])
        self.assertEqual(len(plan["review_items"]), 1)  # 同 group=1 item
        self.assertEqual(
            plan["review_items"][0]["verification_states"], ["skipped", "unreproduced"]
        )
        md = _build_markdown(plan["tasks"], plan["review_items"])
        self.assertIn("- Verification: skipped, unreproduced", md)


if __name__ == "__main__":
    unittest.main()
