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


class ReachabilityTests(unittest.TestCase):
    def _result(self, conn="COMPLETED", scan="COMPLETED", scan_result=None):
        ns = types.SimpleNamespace(scan_result=scan_result)
        if conn is not None:
            ns.connectivity_status = _status(conn)
        if scan is not None:
            ns.scan_status = _status(scan)
        return ns

    def test_reachable_when_completed(self):
        self.assertTrue(tls_scan.server_scan_reachable(self._result()))

    def test_unreachable_on_connectivity_error(self):
        self.assertFalse(tls_scan.server_scan_reachable(self._result(conn="ERROR")))

    def test_unreachable_on_scan_error(self):
        self.assertFalse(tls_scan.server_scan_reachable(
            self._result(scan="ERROR_NO_CONNECTIVITY")))

    def test_missing_attrs_default_reachable(self):
        # 版差で属性が無くても過剰抑制しない（従来どおり到達扱い）。
        self.assertTrue(tls_scan.server_scan_reachable(object()))

    def test_completed_attempts_detection(self):
        sr = types.SimpleNamespace(scan_result=types.SimpleNamespace(
            ssl_2_0_cipher_suites=_cipher_attempt(False, status="ERROR"),
            heartbleed=_bool_attempt("is_vulnerable_to_heartbleed", False, status="COMPLETED"),
        ))
        self.assertTrue(tls_scan.scan_has_completed_attempts(sr))

    def test_no_completed_attempts(self):
        sr = types.SimpleNamespace(scan_result=types.SimpleNamespace(
            ssl_2_0_cipher_suites=_cipher_attempt(False, status="ERROR"),
            robot=_robot_attempt(False, status="ERROR"),
        ))
        self.assertFalse(tls_scan.scan_has_completed_attempts(sr))

    def test_incomplete_commands_lists_failed(self):
        # TLS1.0 は成功だが Heartbleed/ROBOT が ERROR → 失敗コマンドを列挙する（黙って捨てない）。
        sr = types.SimpleNamespace(scan_result=types.SimpleNamespace(
            tls_1_0_cipher_suites=_cipher_attempt(True, status="COMPLETED"),
            heartbleed=_bool_attempt("is_vulnerable_to_heartbleed", False, status="ERROR"),
            robot=_robot_attempt(False, status="ERROR"),
        ))
        inc = tls_scan.incomplete_commands(sr)
        self.assertIn("heartbleed", inc)
        self.assertIn("robot", inc)
        self.assertNotIn("tls_1_0_cipher_suites", inc)

    def test_incomplete_commands_none_when_all_completed(self):
        sr = types.SimpleNamespace(scan_result=types.SimpleNamespace(
            heartbleed=_bool_attempt("is_vulnerable_to_heartbleed", False, status="COMPLETED"),
        ))
        self.assertEqual(tls_scan.incomplete_commands(sr), [])


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

    async def test_unreachable_records_note_not_silent(self):
        engine = _FakeEngine(enabled=True)
        scanner = SCANNERS["tls_scan"](engine)
        with mock.patch.object(tls_scan, "sslyze_available", return_value=True), \
             mock.patch.object(tls_scan, "run_sslyze_scan", return_value=object()), \
             mock.patch.object(tls_scan, "server_scan_reachable", return_value=False):
            out = await scanner.scan_page("https://x.test/")
        self.assertEqual(out, [])
        self.assertTrue(any("unreachable" in n for n in engine.wave_errors))

    async def test_reachable_but_no_completed_attempts_records_incomplete(self):
        engine = _FakeEngine(enabled=True)
        scanner = SCANNERS["tls_scan"](engine)
        with mock.patch.object(tls_scan, "sslyze_available", return_value=True), \
             mock.patch.object(tls_scan, "run_sslyze_scan", return_value=object()), \
             mock.patch.object(tls_scan, "server_scan_reachable", return_value=True), \
             mock.patch.object(tls_scan, "extract_tls_issues", return_value=[]), \
             mock.patch.object(tls_scan, "scan_has_completed_attempts", return_value=False):
            out = await scanner.scan_page("https://x.test/")
        self.assertEqual(out, [])
        self.assertTrue(any("scan_incomplete" in n for n in engine.wave_errors))


    async def test_cvss_mapped_by_kind_not_severity(self):
        # Heartbleed は OOB read＝機密性のみ。severity バケツの critical(9.1, I:H) ではなく
        # kind 整合の 7.5 / I:N を publish する（Codex #158）。
        engine = _FakeEngine(enabled=True)
        scanner = SCANNERS["tls_scan"](engine)
        recorded = []

        async def _rec(**kw):
            recorded.append(kw)
            return object()

        scanner.record_finding = _rec
        with mock.patch.object(tls_scan, "sslyze_available", return_value=True), \
             mock.patch.object(tls_scan, "run_sslyze_scan", return_value=object()), \
             mock.patch.object(tls_scan, "server_scan_reachable", return_value=True), \
             mock.patch.object(tls_scan, "extract_tls_issues", return_value=[
                 {"kind": "heartbleed", "label": "Heartbleed", "severity": "critical", "detail": "d"},
             ]):
            await scanner.scan_page("https://x.test/")
        self.assertEqual(recorded[0]["severity"], "critical")  # 表示 severity は維持
        self.assertEqual(recorded[0]["cvss_score"], 7.5)
        self.assertIn("C:H/I:N/A:N", recorded[0]["cvss_vector"])  # 完全性影響なし

    async def test_proxy_configured_skips_with_note(self):
        # proxy 設定時は別経路の直接接続を避け、明示的に skip を記録する（#158）。
        engine = _FakeEngine(enabled=True)
        engine.proxy = "http://127.0.0.1:8080"
        scanner = SCANNERS["tls_scan"](engine)
        with mock.patch.object(tls_scan, "sslyze_available", return_value=True), \
             mock.patch.object(tls_scan, "run_sslyze_scan") as run:
            out = await scanner.scan_page("https://x.test/")
        self.assertEqual(out, [])
        run.assert_not_called()
        self.assertTrue(any("proxy_unsupported" in n for n in engine.wave_errors))

    async def test_client_cert_configured_skips_with_note(self):
        engine = _FakeEngine(enabled=True)
        engine.tls_config = type("C", (), {"has_client_certificate": lambda self: True})()
        scanner = SCANNERS["tls_scan"](engine)
        with mock.patch.object(tls_scan, "sslyze_available", return_value=True), \
             mock.patch.object(tls_scan, "run_sslyze_scan") as run:
            out = await scanner.scan_page("https://x.test/")
        self.assertEqual(out, [])
        run.assert_not_called()
        self.assertTrue(any("client_cert_unsupported" in n for n in engine.wave_errors))

    def test_cvss_for_issue_per_kind(self):
        # 各 kind が自己整合する (score, vector) を返す。
        self.assertEqual(tls_scan.cvss_for_issue("heartbleed")[0], 7.5)
        self.assertIn("I:N", tls_scan.cvss_for_issue("heartbleed")[1])
        self.assertIn("I:H", tls_scan.cvss_for_issue("ccs_injection")[1])  # MITM 改ざん
        self.assertEqual(tls_scan.cvss_for_issue("robot")[0], 5.9)
        # 未知 kind は機密性のみの保守値（根拠無い I:H を出さない）。
        self.assertIn("I:N", tls_scan.cvss_for_issue("unknown")[1])

    async def test_ipv6_origin_is_bracketed(self):
        # IPv6 host は URL 上ブラケットが要る（https://::1:443 は不正）。
        engine = _FakeEngine(enabled=True)
        scanner = SCANNERS["tls_scan"](engine)
        recorded = []

        async def _rec(**kw):
            recorded.append(kw)
            return object()

        scanner.record_finding = _rec
        with mock.patch.object(tls_scan, "sslyze_available", return_value=True), \
             mock.patch.object(tls_scan, "run_sslyze_scan", return_value=object()), \
             mock.patch.object(tls_scan, "server_scan_reachable", return_value=True), \
             mock.patch.object(tls_scan, "incomplete_commands", return_value=[]), \
             mock.patch.object(tls_scan, "extract_tls_issues", return_value=[
                 {"kind": "weak_protocol", "label": "TLS 1.0", "severity": "medium", "detail": "d"},
             ]):
            await scanner.scan_page("https://[::1]/")
        self.assertEqual(recorded[0]["url"], "https://[::1]:443")

    async def test_partial_failure_recorded(self):
        # issue が見つかっても、失敗コマンドがあれば記録する。
        engine = _FakeEngine(enabled=True)
        scanner = SCANNERS["tls_scan"](engine)
        scanner.record_finding = lambda **kw: None
        with mock.patch.object(tls_scan, "sslyze_available", return_value=True), \
             mock.patch.object(tls_scan, "run_sslyze_scan", return_value=object()), \
             mock.patch.object(tls_scan, "server_scan_reachable", return_value=True), \
             mock.patch.object(tls_scan, "extract_tls_issues", return_value=[]), \
             mock.patch.object(tls_scan, "scan_has_completed_attempts", return_value=True), \
             mock.patch.object(tls_scan, "incomplete_commands", return_value=["robot", "heartbleed"]):
            await scanner.scan_page("https://x.test/")
        self.assertTrue(any("scan_incomplete" in n and "robot" in n for n in engine.wave_errors))


class CvssOverrideTests(unittest.TestCase):
    def test_finding_cvss_override(self):
        from wscan.scanners.base import Finding
        f = Finding(check_type="tls_scan", severity="critical", url="u", field_name="x",
                    payload="p", evidence="e",
                    cvss_score_override=9.1, cvss_vector_override="CVSS:3.1/AV:N/...")
        self.assertEqual(f.cvss_score, 9.1)
        self.assertEqual(f.cvss_vector, "CVSS:3.1/AV:N/...")

    def test_finding_cvss_default_without_override(self):
        from wscan.scanners.base import Finding
        f = Finding(check_type="tls_scan", severity="medium", url="u", field_name="x",
                    payload="p", evidence="e")
        # override 無しなら check_type 既定（_CVSS_TABLE）。
        self.assertGreater(f.cvss_score, 0)


class EngineEnableTests(unittest.TestCase):
    def test_explicit_tls_scan_check_enables_feature(self):
        # checks に tls_scan を直接渡す呼び出し（batch_runner 等）でも有効化される。
        from wscan.engine import ScanEngine
        e = ScanEngine("https://x.test", checks=["tls_scan"], llm_provider="none", monitor=None)
        self.assertTrue(e.tls_scan_enabled)
        self.assertIn("tls_scan", e.checks)

    def test_not_requested_stays_off(self):
        from wscan.engine import ScanEngine
        e = ScanEngine("https://x.test", checks=["xss"], llm_provider="none", monitor=None)
        self.assertFalse(e.tls_scan_enabled)

    def test_explicit_false_disables_even_with_check(self):
        # serve が None を渡せば checks 推論が効く（明示 False 上書きで no-op にしない・Codex #158）。
        from wscan.engine import ScanEngine
        e = ScanEngine("https://x.test", checks=["tls_scan"], enable_tls_scan=None,
                       llm_provider="none", monitor=None)
        self.assertTrue(e.tls_scan_enabled)
        # 明示 False は尊重（無効）。
        e2 = ScanEngine("https://x.test", checks=["tls_scan"], enable_tls_scan=False,
                        llm_provider="none", monitor=None)
        self.assertFalse(e2.tls_scan_enabled)


class SeedScanTests(unittest.IsolatedAsyncioTestCase):
    async def test_tls_seed_scan_probes_only_attack_scope_origins(self):
        # crawl 非依存で seed origin を検査するが、能動 TLS プローブは攻撃スコープ内に限定する。
        # http/重複は除く。out-of-scope の偵察 seed（別ホスト）へは SSLyze を送らない（Codex #158 P1）。
        from wscan.engine import ScanEngine
        # origin レベルの攻撃スコープ（/ 終端）。weak.test 配下は全 path が in-scope。
        engine = ScanEngine("https://weak.test/", checks=["tls_scan"],
                            enable_tls_scan=True, llm_provider="none", monitor=None)
        engine.seed_urls = [
            "https://weak.test/other",   # in-scope（同一ホスト）
            "http://plain.test/",        # http → 除外
            "https://evil.test/cb",      # out-of-scope（偵察で発見した別ホスト）→ 送らない
        ]
        probed = []

        async def _rec_scan_page(url):
            probed.append(url)
            return []

        engine.scanners["tls_scan"].scan_page = _rec_scan_page
        await engine._run_tls_seed_scans()
        self.assertIn("https://weak.test", probed)          # 攻撃スコープ内
        self.assertNotIn("https://evil.test", probed)        # スコープ外は能動プローブしない
        self.assertNotIn("http://plain.test", probed)        # http は対象外
        self.assertEqual(len(probed), len(set(probed)))      # origin dedup


class CliChecksTests(unittest.TestCase):
    def test_checks_tls_scan_is_accepted(self):
        import sys
        import main as m
        argv = ["prog", "scan", "https://x.test", "--checks", "tls_scan", "--no-monitor"]
        with mock.patch.object(sys, "argv", argv):
            args = m.parse_args()
        self.assertIn("tls_scan", args.checks)


if __name__ == "__main__":
    unittest.main()
