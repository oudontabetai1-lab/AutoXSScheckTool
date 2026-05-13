import json
import tempfile
import unittest
from pathlib import Path

from wscan.action_plan import write_action_plan
from wscan.scanners.base import Finding


class ActionPlanTests(unittest.TestCase):
    def test_write_action_plan_exports_ticket_ready_tasks(self):
        finding = Finding(
            check_type="xss",
            severity="critical",
            url="http://fixture.test/search",
            field_name="q",
            payload="<script>alert(1)</script>",
            evidence="JavaScript dialog fired",
            confidence="confirmed",
            evidence_type="xss_dialog",
            reproduction_steps=["Open search", "Submit payload"],
        )

        with tempfile.TemporaryDirectory() as tmp:
            result = write_action_plan([finding], Path(tmp))
            plan = json.loads(Path(result["json"]).read_text(encoding="utf-8"))
            tasks = plan["tasks"]
            markdown = Path(result["markdown"]).read_text(encoding="utf-8")

        self.assertEqual(result["count"], 1)
        self.assertEqual(plan["review_items"], [])
        self.assertEqual(tasks[0]["priority"], "P0")
        self.assertIn("contextually encoded", " ".join(tasks[0]["acceptance_criteria"]))
        self.assertIn("WS-001", markdown)
        self.assertIn("Acceptance criteria", markdown)

    def test_write_action_plan_keeps_unverified_tentative_signals_out_of_tasks(self):
        finding = Finding(
            check_type="xss",
            severity="medium",
            url="http://fixture.test/dom",
            field_name="next",
            payload="<script>alert(1)</script>",
            evidence="Reflected in HTML text but execution was not reproduced",
            confidence="tentative",
            verified=False,
            evidence_type="xss_reflection",
            reproduction_steps=["Open page", "Submit payload"],
        )

        with tempfile.TemporaryDirectory() as tmp:
            result = write_action_plan([finding], Path(tmp))
            plan = json.loads(Path(result["json"]).read_text(encoding="utf-8"))
            markdown = Path(result["markdown"]).read_text(encoding="utf-8")

        self.assertEqual(result["count"], 0)
        self.assertEqual(result["review_count"], 1)
        self.assertEqual(plan["tasks"], [])
        self.assertEqual(plan["review_items"][0]["id"], "WR-001")
        self.assertIn("Review-only Signals", markdown)

    def test_write_action_plan_groups_related_review_only_signals(self):
        findings = [
            Finding(
                check_type="xss",
                severity="medium",
                url="http://fixture.test/dom?next=hello",
                field_name="next",
                payload="<script>alert(1)</script>",
                evidence="Reflected but not reproduced",
                confidence="tentative",
                verified=False,
                evidence_type="xss_reflection",
                evidence_details={"context": "html_text"},
            ),
            Finding(
                check_type="xss",
                severity="medium",
                url="http://fixture.test/dom",
                field_name="next",
                payload="<script>alert(1)</script>",
                evidence="Reflected again but not reproduced",
                confidence="tentative",
                verified=False,
                evidence_type="xss_reflection",
                evidence_details={"context": "html_text"},
            ),
        ]

        with tempfile.TemporaryDirectory() as tmp:
            result = write_action_plan(findings, Path(tmp))
            plan = json.loads(Path(result["json"]).read_text(encoding="utf-8"))
            markdown = Path(result["markdown"]).read_text(encoding="utf-8")

        self.assertEqual(result["count"], 0)
        self.assertEqual(result["review_count"], 1)
        self.assertEqual(len(plan["review_items"][0]["related_signals"]), 1)
        self.assertIn("Related signals: 1", markdown)

    def test_write_action_plan_groups_related_actionable_findings(self):
        findings = [
            Finding(
                check_type="xss",
                severity="critical",
                url="http://fixture.test/",
                field_name="q",
                payload="<script>alert(1)</script>",
                evidence="Dialog from search form",
                confidence="confirmed",
                verified=True,
                evidence_type="xss_dialog",
                reproduction_steps=["Open /", "Submit q"],
            ),
            Finding(
                check_type="xss",
                severity="critical",
                url="http://fixture.test/search?q=hello",
                field_name="q",
                payload="<script>alert(1)</script>",
                evidence="Dialog from query parameter",
                confidence="confirmed",
                verified=True,
                evidence_type="xss_dialog",
                reproduction_steps=["Open /search", "Submit q"],
            ),
        ]

        with tempfile.TemporaryDirectory() as tmp:
            result = write_action_plan(findings, Path(tmp))
            plan = json.loads(Path(result["json"]).read_text(encoding="utf-8"))
            markdown = Path(result["markdown"]).read_text(encoding="utf-8")

        self.assertEqual(result["count"], 1)
        self.assertEqual(len(plan["tasks"]), 1)
        self.assertEqual(len(plan["tasks"][0]["related_findings"]), 1)
        self.assertIn("Related findings: 1", markdown)

    def test_write_action_plan_groups_auth_bypass_fields_by_login_endpoint(self):
        findings = [
            Finding(
                check_type="sqli",
                severity="critical",
                url="http://fixture.test/login",
                field_name="username",
                payload="' OR '1'='1",
                evidence="Auth bypass via username",
                confidence="confirmed",
                verified=True,
                evidence_type="sqli_auth_bypass",
                evidence_details={
                    "original_url": "http://fixture.test/login",
                    "post_login_url": "http://fixture.test/admin",
                },
            ),
            Finding(
                check_type="sqli",
                severity="critical",
                url="http://fixture.test/login",
                field_name="password",
                payload="' OR '1'='1",
                evidence="Auth bypass via password",
                confidence="confirmed",
                verified=True,
                evidence_type="sqli_auth_bypass",
                evidence_details={
                    "original_url": "http://fixture.test/login",
                    "post_login_url": "http://fixture.test/admin",
                },
            ),
        ]

        with tempfile.TemporaryDirectory() as tmp:
            result = write_action_plan(findings, Path(tmp))
            plan = json.loads(Path(result["json"]).read_text(encoding="utf-8"))

        self.assertEqual(result["count"], 1)
        self.assertEqual(len(plan["tasks"][0]["related_findings"]), 1)
        self.assertEqual(
            plan["tasks"][0]["title"],
            "[CRITICAL] Fix SQLi authentication bypass on login form",
        )
        self.assertEqual(plan["tasks"][0]["field_name"], "password, username")
        self.assertEqual(plan["tasks"][0]["url"], "http://fixture.test/login")

    def test_write_action_plan_adds_authorization_criteria_for_state_changing_actions(self):
        finding = Finding(
            check_type="privesc_action",
            severity="high",
            url="http://fixture.test/admin/users",
            field_name="(state-changing action: POST /admin/users/role)",
            payload="low-privilege session submitted form",
            evidence="Low-privilege user could submit role change form",
            confidence="confirmed",
            verified=True,
        )

        with tempfile.TemporaryDirectory() as tmp:
            result = write_action_plan([finding], Path(tmp))
            plan = json.loads(Path(result["json"]).read_text(encoding="utf-8"))

        self.assertEqual(result["count"], 1)
        self.assertIn(
            "Authorization checks are enforced server-side",
            " ".join(plan["tasks"][0]["acceptance_criteria"]),
        )


if __name__ == "__main__":
    unittest.main()
