"""SARIF が verification_note を出力し、skip と genuine 非再現を区別できることのテスト。"""
import unittest

from wscan.sarif import SarifExporter


class SarifVerificationNoteTests(unittest.TestCase):
    def test_result_properties_include_verification_note(self):
        # verified=False でも「例外で検証未実行(要手動確認)」の理由が SARIF 消費側へ届く。
        skip = {
            "check_type": "sqli", "url": "http://h/api", "field_name": "body",
            "payload": "'", "severity": "high", "verified": False,
            "verification_note": "検証が例外で実行できず未再現（要手動確認）",
        }
        props = SarifExporter._finding_to_result(skip)["properties"]
        self.assertFalse(props["verified"])
        self.assertIn("要手動確認", props["verification_note"])

    def test_note_distinguishes_skip_from_genuine_nonreproduction(self):
        skip = {
            "check_type": "sqli", "url": "http://h/a", "field_name": "b",
            "payload": "'", "severity": "high", "verified": False,
            "verification_note": "検証が例外で実行できず未再現（要手動確認）",
        }
        genuine = {
            "check_type": "sqli", "url": "http://h/a", "field_name": "b",
            "payload": "'", "severity": "high", "verified": False,
            "verification_note": "2回目の試行で再現できませんでした (possible false positive)",
        }
        skip_props = SarifExporter._finding_to_result(skip)["properties"]
        genuine_props = SarifExporter._finding_to_result(genuine)["properties"]
        # verified は同値でも note で区別できる。
        self.assertEqual(skip_props["verified"], genuine_props["verified"])
        self.assertNotEqual(
            skip_props["verification_note"], genuine_props["verification_note"]
        )

    def test_absent_note_defaults_empty(self):
        f = {
            "check_type": "xss", "url": "http://h/x", "field_name": "q",
            "payload": "<script>", "severity": "high", "verified": True,
        }
        props = SarifExporter._finding_to_result(f)["properties"]
        self.assertEqual(props["verification_note"], "")


if __name__ == "__main__":
    unittest.main()
