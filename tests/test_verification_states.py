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

    async def _run_fallback_engine(self, mode):
        # scanner verify が失効/transport 失敗で None を返しても、_verify_one は既定で
        # フォールバック再送し 401/空応答を評価して "unreproduced" にしてしまう。json の
        # 失効/transport 失敗時は terminal な "assumed"（penalize しない）にする（Codex #99 R6）。
        # ハーネスは**フォールバックが実際に走る**よう browser 等を備え、fix 無しなら
        # unreproduced を返す（＝有効な回帰テスト）。
        import re as _re

        class _FbBrowser:
            async def navigate(self, url, retries=0):
                return None

            def reset_dialog(self):
                pass

        class _FbScanner:
            CHECK_TYPE = "sqli"

            def __init__(self, engine, mode):
                self.engine = engine
                self.mode = mode

            def _fail(self):
                if self.mode == "auth":
                    self.engine._api_auth_failed = True
                    return "login required", {"response": {"status": 401, "body": "login required"}}
                self.engine._json_probe_failed = True
                return "", {}

            async def verify_finding(self, finding):
                self._fail()
                return None

            async def _apply_ip(self, ip, payload):
                return self._fail()

            def check_response_for_patterns(self, body, patterns):
                return any(_re.search(p, body or "", _re.IGNORECASE) for p in patterns)

        class _FbEngine:
            _verify_one = ScanEngine._verify_one

            def __init__(self, mode):
                self.scanners = {"sqli": _FbScanner(self, mode)}
                self.browser = _FbBrowser()
                self._effective_delay = 0
                self.navigation_retries = 0
                self._api_auth_failed = False
                self._json_probe_failed = False

        finding = Finding(
            check_type="sqli", severity="critical", url="http://h/api/login",
            field_name="email", payload="'", evidence="e",
            injection_location="json_body", injection_pointer="/email",
            injection_method="POST", injection_template_id="t",
        )
        return await _FbEngine(mode)._verify_one(finding)

    async def test_verify_one_json_auth_failure_is_assumed_not_unreproduced(self):
        self.assertEqual(await self._run_fallback_engine("auth"), "assumed")

    async def test_verify_one_json_transport_failure_is_assumed(self):
        self.assertEqual(await self._run_fallback_engine("transport"), "assumed")

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
