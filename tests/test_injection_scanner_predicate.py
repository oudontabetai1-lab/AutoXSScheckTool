"""_is_injection_scanner: 受動スキャナ（js_static/security_headers 等）を
注入系と誤認しないことの回帰テスト（G7/P1）。

G7 の反射観測 probe は注入系 check があるときだけ動く。受動スキャナを選ぶと
base evolution probe が marker を注入し、`--checks js_static` のような受動監査を
能動的な状態変更攻撃に変えてしまうため。
"""
import unittest

from wscan.engine import _is_injection_scanner
from wscan.scanners.js_static import JsStaticScanner
from wscan.scanners.security_headers import SecurityHeadersScanner
from wscan.scanners.sqli import SQLiScanner
from wscan.scanners.xss import XSSScanner


class InjectionScannerPredicateTests(unittest.TestCase):
    def _inst(self, cls):
        # 述語は type のみ見るため __init__ を通さず生成する（engine 不要）。
        return object.__new__(cls)

    def test_injection_scanners_are_detected(self):
        self.assertTrue(_is_injection_scanner(self._inst(XSSScanner)))
        self.assertTrue(_is_injection_scanner(self._inst(SQLiScanner)))

    def test_passive_scanners_are_not_injection(self):
        self.assertFalse(_is_injection_scanner(self._inst(JsStaticScanner)))
        self.assertFalse(_is_injection_scanner(self._inst(SecurityHeadersScanner)))


if __name__ == "__main__":
    unittest.main()
