import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from wscan.agent_engine import AgentEngine, AgentHandoffData
from wscan.engine import ScanEngine
from wscan.llm_agent_browser import (
    AgentBrowserScanner,
    AgentFinding,
    AgentMemory,
    _parse_findings_from_text,
)
from wscan.sarif import SarifExporter
from wscan.scanners.base import Finding


class AgentFindingSourceTests(unittest.TestCase):
    def test_handoff_findings_default_is_empty_and_independent(self):
        first = AgentHandoffData()
        second = AgentHandoffData()
        positional = AgentHandoffData(
            ["http://fixture.test"], "user", "pass", "/login", "summary"
        )

        self.assertEqual(first.findings, [])
        first.findings.append("finding")
        self.assertEqual(second.findings, [])
        self.assertEqual(positional.auth_user, "user")
        self.assertEqual(positional.findings, [])

    def test_parser_marks_finding_as_agent_origin(self):
        nonce = "test-session"
        text = f"""WSCAN-NONCE:{nonce}
VULNERABILITY FOUND:
Type: xss
Severity: high
URL: http://fixture.test/search
Field: q
Payload: <svg/onload=alert(1)>
Evidence: alert dialog was observed
"""

        findings = _parse_findings_from_text(text, nonce=nonce)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].source, "agent")
        self.assertFalse(findings[0].agent_verified)
        self.assertEqual(findings[0].to_dict()["source"], "agent")

    def test_sarif_preserves_agent_origin_properties(self):
        sarif = SarifExporter().export([
            {
                "check_type": "xss",
                "severity": "high",
                "url": "http://fixture.test/search",
                "field_name": "q",
                "payload": "<svg/onload=alert(1)>",
                "evidence": "alert dialog was observed",
                "source": "agent",
                "agent_verified": True,
            }
        ])

        properties = sarif["runs"][0]["results"][0]["properties"]
        self.assertEqual(properties["source"], "agent")
        self.assertTrue(properties["agent_verified"])

    def test_sarif_fingerprint_separates_agent_and_scanner_findings(self):
        common = {
            "check_type": "xss",
            "severity": "high",
            "url": "http://fixture.test/search",
            "field_name": "q",
            "payload": "<svg/onload=alert(1)>",
            "evidence": "alert dialog was observed",
        }

        results = SarifExporter().export([
            {**common, "source": "scanner"},
            {**common, "source": "agent"},
        ])["runs"][0]["results"]

        fingerprints = [
            result["partialFingerprints"]["primaryLocationLineHash"]
            for result in results
        ]
        self.assertNotEqual(fingerprints[0], fingerprints[1])

    def test_recon_task_keeps_url_discovery_primary_and_surfaces_findings(self):
        scanner = AgentBrowserScanner(
            target_url="http://fixture.test",
            checks=["xss"],
            recon_mode=True,
        )

        task = scanner._build_recon_task()

        self.assertIn("URL discovery is the primary objective", task)
        self.assertIn("Cross-Site Scripting", task)
        self.assertIn("VULNERABILITY FOUND", task)


class AgentReconHandoffTests(unittest.IsolatedAsyncioTestCase):
    async def test_run_recon_returns_agent_finding_in_standard_format(self):
        agent_finding = AgentFinding(
            check_type="xss",
            severity="high",
            url="http://fixture.test/search",
            field_name="q",
            payload="<svg/onload=alert(1)>",
            evidence="alert dialog was observed",
        )
        result = SimpleNamespace(
            findings=[agent_finding],
            memory=AgentMemory(visited_urls=["http://fixture.test/search"]),
            final_summary="site mapped",
        )

        with patch("wscan.llm_agent_browser.AgentBrowserScanner") as scanner_cls:
            scanner_cls.return_value.run = AsyncMock(return_value=result)
            with tempfile.TemporaryDirectory() as output_dir:
                engine = AgentEngine(
                    url="http://fixture.test",
                    checks=["xss"],
                    output_dir=output_dir,
                    open_report=False,
                )

                handoff = await engine.run_recon()

        scanner_kwargs = scanner_cls.call_args.kwargs
        self.assertEqual(scanner_kwargs["checks"], ["xss"])
        self.assertTrue(scanner_kwargs["recon_mode"])
        self.assertEqual(
            handoff.discovered_urls,
            ["http://fixture.test", "http://fixture.test/search"],
        )
        self.assertEqual(len(handoff.findings), 1)
        self.assertIsInstance(handoff.findings[0], Finding)
        self.assertEqual(handoff.findings[0].source, "agent")
        self.assertFalse(handoff.findings[0].verified)
        self.assertFalse(handoff.findings[0].agent_verified)

    async def test_run_writes_agent_finding_as_unverified_evidence(self):
        agent_finding = AgentFinding(
            check_type="xss",
            severity="high",
            url="http://fixture.test/search",
            field_name="q",
            payload="<svg/onload=alert(1)>",
            evidence="alert dialog was observed",
        )
        result = SimpleNamespace(
            findings=[agent_finding],
            steps_taken=3,
            success=True,
            error="",
            final_summary="",
        )

        with patch("wscan.llm_agent_browser.AgentBrowserScanner") as scanner_cls:
            scanner_cls.return_value.run = AsyncMock(return_value=result)
            with tempfile.TemporaryDirectory() as output_dir, patch(
                "wscan.report.ReportGenerator.generate",
                return_value=Path(output_dir) / "report.html",
            ):
                engine = AgentEngine(
                    url="http://fixture.test",
                    checks=["xss"],
                    output_dir=output_dir,
                    open_report=False,
                )
                await engine.run()
                evidence = json.loads(
                    (Path(output_dir) / "evidence.json").read_text(encoding="utf-8")
                )

        finding = evidence["findings"][0]
        self.assertEqual(finding["source"], "agent")
        self.assertFalse(finding["verified"])
        self.assertFalse(finding["agent_verified"])


class HybridFindingMergeTests(unittest.TestCase):
    def test_agent_and_scanner_duplicates_are_both_kept_in_final_collection(self):
        scanner_finding = Finding(
            check_type="xss",
            severity="high",
            url="http://fixture.test/search",
            field_name="q",
            payload="scanner-payload",
            evidence="scanner evidence",
            source="scanner",
        )
        agent_finding = Finding(
            check_type="xss",
            severity="high",
            url="http://fixture.test/search",
            field_name="q",
            payload="agent-payload",
            evidence="agent evidence",
            source="agent",
        )
        engine = object.__new__(ScanEngine)
        engine.all_findings = [scanner_finding]
        engine.additional_report_findings = [agent_finding]
        engine._save_evidence = Mock()
        engine._generate_report = Mock()
        engine._print_summary = Mock()
        engine.enable_payload_learning = False

        engine._merge_additional_report_findings()
        engine._merge_additional_report_findings()
        engine._phase_report()

        self.assertEqual(len(engine.all_findings), 2)
        self.assertEqual(
            [finding.source for finding in engine.all_findings],
            ["scanner", "agent"],
        )
        self.assertEqual(engine.additional_report_findings, [])
        engine._generate_report.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
