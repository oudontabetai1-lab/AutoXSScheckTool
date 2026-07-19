import unittest

from wscan.llm_agent_browser import _parse_findings_from_text
from wscan.sarif import SarifExporter


class AgentFindingSourceTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
