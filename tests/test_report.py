import tempfile
import unittest
from pathlib import Path

from wscan.report import ReportGenerator
from wscan.scanners.base import Finding


class ReportGeneratorTests(unittest.TestCase):
    def test_audit_report_includes_remediation_summary_and_review_signals(self):
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
                reproduction_steps=["Open /dom", "Submit next"],
            ),
        ]

        with tempfile.TemporaryDirectory() as tmp:
            report_path = ReportGenerator(Path(tmp)).generate(
                target="http://fixture.test",
                findings=findings,
                visited_urls=["http://fixture.test/"],
                checks=["xss"],
                scan_matrix=[],
                llm_summary={
                    "provider": "ollama",
                    "model": "qwen2.5-coder:latest",
                    "role_models": {
                        "planner": "qwen2.5-coder:latest",
                        "report": "qwen3:8b",
                    },
                    "total_plans": 1,
                    "llm_plans": 1,
                    "heuristic_plans": 0,
                },
            )
            html = report_path.read_text(encoding="utf-8")

        self.assertIn("Remediation Summary (1 tasks)", html)
        self.assertIn("Related findings: 1", html)
        self.assertIn("Review-only Signals (1)", html)
        self.assertIn("WR-001", html)
        self.assertIn('rel="icon"', html)
        self.assertIn("table-scroll", html)
        self.assertIn("LLM Runtime Summary", html)
        self.assertIn("Role Models", html)
        self.assertIn("qwen3:8b", html)
        self.assertIn("qwen2.5-coder:latest", html)
        forbidden = tuple(
            "".join(chr(c) for c in codes)
            for codes in (
                (65, 101, 121, 101, 83, 99, 97, 110),
                (86, 69, 88),
                (86, 101, 120),
                (97, 101, 121, 101, 115, 99, 97, 110),
                (118, 101, 120),
            )
        )
        for name in forbidden:
            self.assertNotIn(name, html)


if __name__ == "__main__":
    unittest.main()
