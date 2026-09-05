"""SARIF run properties へ検査カバレッジ補助情報を出すことのテスト（0016）。

SARIF 消費側（CI/セキュリティダッシュボード）が「0 findings＝安全ではない・未実行や
前提不足の検査がある」を判別できるよう、run.properties.coverage を検証する。
"""
import unittest

from wscan.sarif import SarifExporter


_FINDING = {
    "check_type": "sqli", "url": "http://h/a", "field_name": "q",
    "payload": "'", "severity": "high", "verified": True,
    "verification_state": "reproduced",
}


class SarifCoverageTests(unittest.TestCase):
    def test_coverage_omitted_when_not_provided(self):
        run = SarifExporter().export([_FINDING])["runs"][0]
        self.assertNotIn("coverage", run["properties"])  # 後方互換

    def test_check_coverage_surfaced_in_run_properties(self):
        coverage = {
            "check_coverage": {
                "registry_total": 36, "selected": ["sqli", "xss"], "selected_count": 2,
                "not_selected": ["cms", "cors"], "coverage_status": "PARTIAL",
                "unknown_selected": ["xs"],
            },
        }
        run = SarifExporter().export([_FINDING], coverage=coverage)["runs"][0]
        cov = run["properties"]["coverage"]["check_coverage"]
        self.assertEqual(cov["registry_total"], 36)
        self.assertEqual(cov["coverage_status"], "PARTIAL")
        self.assertIn("cms", cov["not_selected"])
        self.assertIn("xs", cov["unknown_selected"])

    def test_prerequisite_and_state_profile_skips_flattened(self):
        coverage = {
            "check_coverage": {"registry_total": 36, "coverage_status": "COMPLETE"},
            "prerequisite_coverage": {
                "prerequisite_missing": [{"check": "mass_assignment", "reasons": ["x"]}],
                "state_profile_skipped": [{"check": "graphql", "reason": "y"}],
            },
        }
        props = SarifExporter().export([_FINDING], coverage=coverage)["runs"][0]["properties"]
        self.assertEqual(props["coverage"]["prerequisite_missing"], ["mass_assignment"])
        self.assertEqual(props["coverage"]["state_profile_skipped"], ["graphql"])

    def test_empty_coverage_dict_adds_no_coverage_block(self):
        run = SarifExporter().export([_FINDING], coverage={})["runs"][0]
        self.assertNotIn("coverage", run["properties"])


if __name__ == "__main__":
    unittest.main()
