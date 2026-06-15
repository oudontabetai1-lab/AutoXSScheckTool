"""ADR-0002 で保留していた検出ロジック強化の回帰テスト。

- #2: baseline 取得不能（空ボディ）時は finding を出さず、scan note に記録する
      （誤検知ゼロ優先。黙って見逃さないよう観測可能にする）。
- #1: os の time-based(blind) verify は no-sleep 対照と比較し、閾値超え かつ
      対照より十分遅いときだけ True（恒常的に遅いだけの endpoint を誤検知しない）。
"""
import unittest
from unittest.mock import AsyncMock

from wscan.scanners.base import Finding
from wscan.scanners.os_injection import OSInjectionScanner
from wscan.scanners.path_traversal import PathTraversalScanner


class _DummyBrowser:
    async def screenshot_b64(self, label=""):
        return ""


class _DummyEngine:
    def __init__(self):
        self.browser = _DummyBrowser()
        self.monitor = None
        self.payload_gen = None
        self._finding_dedup = set()
        self.all_findings = []
        self.checks = []
        # この回帰テストは「標準掃射」だけに集中させる（追加 wave を無効化）。
        self.enable_payload_evolution = False
        self.enable_payload_mutation = False


def _pair(elapsed: float, body: str = "") -> dict:
    return {
        "request": {"timestamp": 1000.0},
        "response": {"timestamp": 1000.0 + elapsed, "body": body},
    }


class BaselineUnavailableSuppressionTests(unittest.IsolatedAsyncioTestCase):
    async def test_os_suppresses_match_when_baseline_request_failed(self):
        # baseline *リクエスト失敗*（pair が空 {}）→ 既存/新規を判別できず抑止。
        engine = _DummyEngine()
        scanner = OSInjectionScanner(engine)
        scanner.get_payloads = AsyncMock(return_value=["; id"])
        scanner._apply_payload = AsyncMock(side_effect=[
            ("", {}),  # baseline リクエスト失敗（pair が空）
            ("uid=1000(wscan) gid=1000(wscan)", {"response": {"body": "uid=1000(wscan)"}}),
        ])
        findings = await scanner.scan_field(
            "http://fixture.test/ping?host=x", 0, {"name": "host"}, is_url_param=True
        )
        self.assertEqual(findings, [])  # 誤検知ゼロ優先で報告しない
        self.assertTrue(
            any("baseline_unavailable:os" in e for e in getattr(engine, "wave_errors", []))
        )

    async def test_path_suppresses_match_when_baseline_request_failed(self):
        engine = _DummyEngine()
        scanner = PathTraversalScanner(engine)
        scanner.get_payloads = AsyncMock(return_value=["../../etc/passwd"])
        scanner._apply_payload = AsyncMock(side_effect=[
            ("", {}),  # baseline リクエスト失敗（pair が空）
            ("root:x:0:0:root:/root:/bin/bash", {"response": {"body": "root:x:0:0"}}),
        ])
        findings = await scanner.scan_field(
            "http://fixture.test/page?file=a", 0, {"name": "file"}, is_url_param=True
        )
        self.assertEqual(findings, [])
        self.assertTrue(
            any("baseline_unavailable:path_traversal" in e
                for e in getattr(engine, "wave_errors", []))
        )

    async def test_os_reports_on_empty_body_success_baseline(self):
        # baseline が *成功* して空ボディ（空 200/204）の場合は有効な対照として扱い、
        # 注入時のみ出力する API を見逃さない（Codex 指摘の偽陰性を防ぐ）。
        engine = _DummyEngine()
        scanner = OSInjectionScanner(engine)
        scanner.get_payloads = AsyncMock(return_value=["; id"])
        scanner._apply_payload = AsyncMock(side_effect=[
            ("", {"request": {}, "response": {"body": ""}}),  # 成功・空ボディ
            ("uid=1000(wscan) gid=1000(wscan)", {"response": {"body": "uid=1000(wscan)"}}),
        ])
        findings = await scanner.scan_field(
            "http://fixture.test/ping?host=x", 0, {"name": "host"}, is_url_param=True
        )
        self.assertEqual(len(findings), 1)

    async def test_path_reports_on_empty_body_success_baseline(self):
        engine = _DummyEngine()
        scanner = PathTraversalScanner(engine)
        scanner.get_payloads = AsyncMock(return_value=["../../etc/passwd"])
        scanner._apply_payload = AsyncMock(side_effect=[
            ("", {"request": {}, "response": {"body": ""}}),  # 成功・空ボディ
            ("root:x:0:0:root:/root:/bin/bash", {"response": {"body": "root:x:0:0"}}),
        ])
        findings = await scanner.scan_field(
            "http://fixture.test/page?file=a", 0, {"name": "file"}, is_url_param=True
        )
        self.assertEqual(len(findings), 1)

    async def test_os_reports_when_body_present_but_no_pair(self):
        # フォーム送信で network pair が捕捉できず本文だけ得られた場合（本文あり・
        # pair 空）は、本文を対照に既存/新規を判別できるので抑止しない。
        engine = _DummyEngine()
        scanner = OSInjectionScanner(engine)
        scanner.get_payloads = AsyncMock(return_value=["; id"])
        scanner._apply_payload = AsyncMock(side_effect=[
            ("welcome to the host pinger", {}),  # 本文あり・pair 空（pair 未捕捉）
            ("uid=1000(wscan) gid=1000(wscan)", {"response": {"body": "uid=1000(wscan)"}}),
        ])
        findings = await scanner.scan_field(
            "http://fixture.test/ping?host=x", 0, {"name": "host"}, is_url_param=True
        )
        self.assertEqual(len(findings), 1)
        self.assertFalse(getattr(engine, "wave_errors", []))  # 抑止していない

    async def test_path_reports_when_body_present_but_no_pair(self):
        engine = _DummyEngine()
        scanner = PathTraversalScanner(engine)
        scanner.get_payloads = AsyncMock(return_value=["../../etc/passwd"])
        scanner._apply_payload = AsyncMock(side_effect=[
            ("Documentation for baseline_test_value", {}),  # 本文あり・pair 空
            ("root:x:0:0:root:/root:/bin/bash", {"response": {"body": "root:x:0:0"}}),
        ])
        findings = await scanner.scan_field(
            "http://fixture.test/page?file=a", 0, {"name": "file"}, is_url_param=True
        )
        self.assertEqual(len(findings), 1)

    async def test_os_still_reports_when_baseline_available(self):
        # baseline が取れていれば従来どおり検知する（抑止の副作用で見逃さない）。
        engine = _DummyEngine()
        scanner = OSInjectionScanner(engine)
        scanner.get_payloads = AsyncMock(return_value=["; id"])
        scanner._apply_payload = AsyncMock(side_effect=[
            ("welcome to the host pinger",
             {"response": {"body": "welcome to the host pinger"}}),  # 成功・パターン非該当
            ("uid=1000(wscan) gid=1000(wscan)", {"response": {"body": "uid=1000(wscan)"}}),
        ])
        findings = await scanner.scan_field(
            "http://fixture.test/ping?host=x", 0, {"name": "host"}, is_url_param=True
        )
        self.assertEqual(len(findings), 1)


class OsTimeBasedControlTests(unittest.IsolatedAsyncioTestCase):
    def _scanner(self, baseline_elapsed: float, sleep_elapsed: float) -> OSInjectionScanner:
        scanner = OSInjectionScanner(_DummyEngine())
        scanner._apply_payload = AsyncMock(side_effect=[
            ("", _pair(baseline_elapsed)),   # verify 内 baseline（no-sleep 対照）
            ("", _pair(sleep_elapsed)),      # payload（sleep）応答
        ])
        return scanner

    def _finding(self) -> Finding:
        return Finding(
            check_type="os",
            severity="high",
            url="http://victim.test/ping",
            field_name="host",
            payload="; sleep 3",
            evidence="time-based",
        )

    async def test_accept_when_control_fast(self):
        sc = self._scanner(baseline_elapsed=0.2, sleep_elapsed=3.2)
        self.assertTrue(await sc.verify_finding(self._finding()))

    async def test_reject_when_endpoint_always_slow(self):
        # 対照も遅い（4.5s）→ 閾値 7.3s を payload 5.0s が超えない → 棄却。
        sc = self._scanner(baseline_elapsed=4.5, sleep_elapsed=5.0)
        self.assertFalse(await sc.verify_finding(self._finding()))

    async def test_reject_when_below_threshold(self):
        sc = self._scanner(baseline_elapsed=0.1, sleep_elapsed=1.0)
        self.assertFalse(await sc.verify_finding(self._finding()))


if __name__ == "__main__":
    unittest.main()
