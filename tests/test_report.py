import tempfile
import unittest
from pathlib import Path

from wscan.report import ReportGenerator
from wscan.scanners.base import Finding


class ReportGeneratorTests(unittest.TestCase):
    def test_verification_states_have_distinct_labels_and_badges(self):
        def finding(field_name, state, verified=True, note=""):
            return Finding(
                check_type="xss",
                severity="high",
                url=f"http://fixture.test/{field_name}",
                field_name=field_name,
                payload="<svg/onload=alert(1)>",
                evidence=f"{state or 'legacy'} evidence",
                verified=verified,
                verification_state=state,
                verification_note=note,
                evidence_type="xss_reflection",
            )

        findings = [
            finding("reproduced", "reproduced"),
            finding("assumed", "assumed"),
            finding("unreproduced", "unreproduced", verified=False),
            finding("skipped", "skipped", verified=False, note="要手動確認"),
            finding("legacy", ""),
        ]

        with tempfile.TemporaryDirectory() as tmp:
            report_path = ReportGenerator(Path(tmp)).generate(
                target="http://fixture.test",
                findings=findings,
                visited_urls=["http://fixture.test/"],
                checks=["xss"],
            )
            html = report_path.read_text(encoding="utf-8")

        self.assertIn(">reproduced</div>", html)
        self.assertIn(">assumed (not re-verified)</div>", html)
        self.assertIn(">not reproduced</div>", html)
        self.assertIn(">skipped (needs review)</div>", html)
        self.assertIn(">reproduced/assumed</div>", html)
        self.assertIn("〜 推定（再検証未実行）", html)
        self.assertEqual(html.count('class="badge-assumed"'), 1)
        self.assertEqual(html.count("⚠ 要確認"), 2)

    def test_assumed_with_verified_false_labeled_assumed_not_unreproduced(self):
        # Agent 仮説等は verified=False かつ state="assumed"（一度も retry していない）。
        # legacy boolean を優先すると "not reproduced"＝失敗した再現試行、と偽る。state 優先で
        # "assumed (not re-verified)" を出す。
        finding = Finding(
            check_type="xss", severity="high",
            url="http://fixture.test/agent", field_name="q",
            payload="<svg/onload=alert(1)>", evidence="agent hypothesis",
            verified=False, verification_state="assumed",
            evidence_type="xss_reflection",
        )
        with tempfile.TemporaryDirectory() as tmp:
            html = ReportGenerator(Path(tmp)).generate(
                target="http://fixture.test", findings=[finding],
                visited_urls=["http://fixture.test/"], checks=["xss"],
            ).read_text(encoding="utf-8")
        self.assertIn(">assumed (not re-verified)</div>", html)
        # この finding を "not reproduced" とは表示しない。
        self.assertNotIn(">not reproduced</div>", html)
        # バッジも state 優先: verified=False+assumed は 推定バッジで、⚠要確認（検証失敗/未実行の
        # 警告）は付けない（一度も retry していない Agent 仮説等）。
        self.assertIn('class="badge-assumed"', html)
        self.assertNotIn("⚠ 要確認", html)

    def test_remediation_summary_html_renders_verification_state(self):
        # HTML レポートの remediation summary が task/review 行に verify state を出す
        # （JSON/MD だけでなく主レポートでも assumed/reproduced・unreproduced/skipped を保つ）。
        findings = [
            Finding(check_type="sqli", severity="high", url="http://h/a",
                    field_name="q", payload="'", evidence="err",
                    evidence_type="sqli_error", confidence="confirmed",
                    verification_state="assumed"),
            Finding(check_type="xss", severity="high", url="http://h/b",
                    field_name="r", payload="<x>", evidence="reflected",
                    evidence_type="xss_reflection", verified=False,
                    verification_state="skipped"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            html = ReportGenerator(Path(tmp)).generate(
                target="http://h", findings=findings,
                visited_urls=["http://h/"], checks=["sqli", "xss"],
            ).read_text(encoding="utf-8")
        # actionable task（assumed）に verify state と要手動確認バッジ。
        self.assertIn("verify: assumed", html)
        self.assertIn("⚠ 要手動確認", html)
        # review-only（skipped）行に verify state。
        self.assertIn("verify=skipped", html)

    def test_agent_findings_have_origin_and_verification_badges(self):
        findings = [
            Finding(
                check_type="xss",
                severity="high",
                url="http://fixture.test/unverified",
                field_name="q",
                payload="<svg/onload=alert(1)>",
                evidence="Agent observed a script execution signal",
                source="agent",
            ),
            Finding(
                check_type="sqli",
                severity="critical",
                url="http://fixture.test/verified",
                field_name="id",
                payload="' OR 1=1--",
                evidence="Agent observed an authentication bypass",
                source="agent",
                agent_verified=True,
            ),
            Finding(
                check_type="csrf",
                severity="medium",
                url="http://fixture.test/scanner",
                field_name="form",
                payload="",
                evidence="Scanner finding",
            ),
        ]

        with tempfile.TemporaryDirectory() as tmp:
            report_path = ReportGenerator(Path(tmp)).generate(
                target="http://fixture.test",
                findings=findings,
                visited_urls=["http://fixture.test/"],
                checks=["xss", "sqli", "csrf"],
            )
            html = report_path.read_text(encoding="utf-8")

        self.assertIn("🤖 Agent発見（LLM独自解釈・未確証）", html)
        self.assertIn("🤖 Agent発見（LLM独自解釈）", html)
        self.assertIn("✅ 決定論的にも再現確認済み", html)
        self.assertEqual(html.count('class="finding-card finding-card-agent"'), 2)
        self.assertIn('data-source="scanner"', html)

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
