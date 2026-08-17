import unittest

from wscan.engine import ScanEngine
from wscan.scanners.base import Finding


def _finding(field_name="q"):
    return Finding(
        check_type="sqli",
        severity="critical",
        url="http://fixture.test/search?q=value",
        field_name=field_name,
        payload="'",
        evidence="SQL error",
    )


class _ResultScanner:
    def __init__(self, result):
        self.result = result

    async def verify_finding(self, finding):
        return self.result


class _VerifyOneEngine:
    _verify_one = ScanEngine._verify_one

    def __init__(self, scanner=None):
        self.scanners = {} if scanner is None else {"sqli": scanner}


class _PhaseVerifyEngine:
    _phase_verify = ScanEngine._phase_verify
    _VERIFIABLE_CHECKS = {"sqli"}

    def __init__(self, findings, states):
        self.all_findings = findings
        self.states = states
        self.monitor = None
        self.wave_errors = []

    async def _verify_one(self, finding):
        state = self.states[finding.field_name]
        if isinstance(state, Exception):
            raise state
        return state


class VerificationStateTests(unittest.IsolatedAsyncioTestCase):
    async def test_verify_one_returns_assumed_without_scanner(self):
        engine = _VerifyOneEngine()

        self.assertEqual(await engine._verify_one(_finding()), "assumed")

    async def test_verify_one_returns_reproduced_for_scanner_true(self):
        engine = _VerifyOneEngine(_ResultScanner(True))

        self.assertEqual(await engine._verify_one(_finding()), "reproduced")

    async def test_verify_one_returns_unreproduced_for_scanner_false(self):
        engine = _VerifyOneEngine(_ResultScanner(False))

        self.assertEqual(await engine._verify_one(_finding()), "unreproduced")

    async def test_phase_verify_applies_all_states_without_dropping_findings(self):
        findings = [
            _finding("reproduced"),
            _finding("assumed"),
            _finding("unreproduced"),
            _finding("skipped"),
        ]
        engine = _PhaseVerifyEngine(
            findings,
            {
                "reproduced": "reproduced",
                "assumed": "assumed",
                "unreproduced": "unreproduced",
                "skipped": RuntimeError("simulated verify crash"),
            },
        )

        await engine._phase_verify()

        reproduced, assumed, unreproduced, skipped = findings
        self.assertTrue(reproduced.verified)
        self.assertEqual(reproduced.verification_state, "reproduced")
        self.assertEqual(reproduced.verification_note, "")

        self.assertTrue(assumed.verified)
        self.assertEqual(assumed.verification_state, "assumed")
        self.assertEqual(assumed.verification_note, "")

        self.assertFalse(unreproduced.verified)
        self.assertEqual(unreproduced.verification_state, "unreproduced")
        self.assertIn("再現できませんでした", unreproduced.verification_note)

        self.assertFalse(skipped.verified)
        self.assertEqual(skipped.verification_state, "skipped")
        self.assertIn("要手動確認", skipped.verification_note)
        self.assertEqual(len(engine.all_findings), 4)


if __name__ == "__main__":
    unittest.main()
