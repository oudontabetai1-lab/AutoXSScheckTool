"""0018: TLS 設定不備検査（sslyze 活用）の単体テスト。

judgment（結果→issue）は sslyze 非依存の純粋関数 extract_tls_issues を fake 結果で検証。
scanner は tls_scan をモックして実 TLS ハンドシェイクなしで分岐を確認する。
"""
import types
import unittest
from unittest import mock

from wscan import tls_scan
from wscan.scanners import SCANNERS


def _status(name):
    return types.SimpleNamespace(name=name)


def _cipher_attempt(accepted, status="COMPLETED"):
    res = types.SimpleNamespace(accepted_cipher_suites=(["x"] if accepted else []))
    return types.SimpleNamespace(status=_status(status), result=res)


def _bool_attempt(attr, value, status="COMPLETED"):
    return types.SimpleNamespace(status=_status(status), result=types.SimpleNamespace(**{attr: value}))


def _robot_attempt(vulnerable, status="COMPLETED"):
    rr = _status("VULNERABLE_WEAK_ORACLE") if vulnerable else _status("NOT_VULNERABLE_NO_ORACLE")
    return types.SimpleNamespace(status=_status(status), result=types.SimpleNamespace(robot_result=rr))


class ExtractIssuesTests(unittest.TestCase):
    def _scan_result(self, **fields):
        base = {
            "ssl_2_0_cipher_suites": _cipher_attempt(False),
            "ssl_3_0_cipher_suites": _cipher_attempt(False),
            "tls_1_0_cipher_suites": _cipher_attempt(False),
            "tls_1_1_cipher_suites": _cipher_attempt(False),
            "heartbleed": _bool_attempt("is_vulnerable_to_heartbleed", False),
            "openssl_ccs_injection": _bool_attempt("is_vulnerable_to_ccs_injection", False),
            "robot": _robot_attempt(False),
        }
        base.update(fields)
        return types.SimpleNamespace(scan_result=types.SimpleNamespace(**base))

    def test_no_issues(self):
        self.assertEqual(tls_scan.extract_tls_issues(self._scan_result()), [])

    def test_weak_protocols(self):
        r = self._scan_result(
            tls_1_0_cipher_suites=_cipher_attempt(True),
            ssl_3_0_cipher_suites=_cipher_attempt(True),
        )
        issues = tls_scan.extract_tls_issues(r)
        labels = {i["label"]: i["severity"] for i in issues}
        self.assertEqual(labels.get("TLS 1.0"), "medium")
        self.assertEqual(labels.get("SSLv3"), "high")

    def test_heartbleed_ccs_robot(self):
        r = self._scan_result(
            heartbleed=_bool_attempt("is_vulnerable_to_heartbleed", True),
            openssl_ccs_injection=_bool_attempt("is_vulnerable_to_ccs_injection", True),
            robot=_robot_attempt(True),
        )
        kinds = {i["kind"] for i in tls_scan.extract_tls_issues(r)}
        self.assertEqual(kinds, {"heartbleed", "ccs_injection", "robot"})

    def test_incomplete_attempts_are_skipped(self):
        # ERROR/NOT_SCHEDULED の attempt は判定しない（部分失敗でクラッシュしない）。
        r = self._scan_result(tls_1_0_cipher_suites=_cipher_attempt(True, status="ERROR"))
        self.assertEqual(tls_scan.extract_tls_issues(r), [])

    def test_defensive_on_garbage(self):
        # 想定外の形でも例外を投げない。
        self.assertEqual(tls_scan.extract_tls_issues(object()), [])


class _FakeEngine:
    def __init__(self, enabled=True):
        self.browser = None
        self.monitor = None
        self.payload_gen = None
        self.wave_errors = []
        self.timeout = 20
        self.tls_scan_enabled = enabled


class ScannerTests(unittest.IsolatedAsyncioTestCase):
    async def test_http_origin_skipped(self):
        scanner = SCANNERS["tls_scan"](_FakeEngine(enabled=True))
        self.assertEqual(await scanner.scan_page("http://plain.test/"), [])

    async def test_disabled_is_inert(self):
        scanner = SCANNERS["tls_scan"](_FakeEngine(enabled=False))
        self.assertEqual(await scanner.scan_page("https://x.test/"), [])

    async def test_reports_issues_on_https(self):
        engine = _FakeEngine(enabled=True)
        scanner = SCANNERS["tls_scan"](engine)
        recorded = []

        async def _rec(**kw):
            recorded.append(kw)
            return object()

        scanner.record_finding = _rec
        with mock.patch.object(tls_scan, "sslyze_available", return_value=True), \
             mock.patch.object(tls_scan, "run_sslyze_scan", return_value=object()), \
             mock.patch.object(tls_scan, "extract_tls_issues", return_value=[
                 {"kind": "weak_protocol", "label": "TLS 1.0", "severity": "medium", "detail": "d"},
                 {"kind": "heartbleed", "label": "Heartbleed", "severity": "critical", "detail": "d"},
             ]):
            out = await scanner.scan_page("https://x.test/")
        self.assertEqual(len(out), 2)
        self.assertEqual({r["evidence_type"] for r in recorded},
                         {"tls_weak_protocol", "tls_heartbleed"})

    async def test_sslyze_unavailable_is_graceful(self):
        scanner = SCANNERS["tls_scan"](_FakeEngine(enabled=True))
        with mock.patch.object(tls_scan, "sslyze_available", return_value=False):
            out = await scanner.scan_page("https://x.test/")
        self.assertEqual(out, [])


if __name__ == "__main__":
    unittest.main()
