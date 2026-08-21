"""G7 の反射 probe を動かす check 集合 _EVOLUTION_PROBE_CHECKS の回帰テスト。

probe は marker を field へ注入するため、動かしてよいのは evolution wave 配線かつ
任意テキスト field を一律に攻撃する generic 注入系のみ。次を含めない:
- 受動スキャナ（js_static/security_headers）… 受動監査を能動攻撃化しない。
- field-selective な注入系（ssrf/open_redirect）… 無関係 field へ marker を入れない。
"""
import unittest

from wscan.engine import _EVOLUTION_PROBE_CHECKS, _PROBE_ALLOWED_INPUT_TYPES


class EvolutionProbeChecksTests(unittest.TestCase):
    def test_generic_injection_checks_are_included(self):
        for c in ("xss", "dom_xss", "sqli", "ssti", "os", "nosql", "ldap", "path_traversal"):
            self.assertIn(c, _EVOLUTION_PROBE_CHECKS)

    def test_passive_and_field_selective_checks_are_excluded(self):
        for c in ("js_static", "security_headers", "csrf", "session", "clickjacking",
                  "ssrf", "open_redirect"):
            self.assertNotIn(c, _EVOLUTION_PROBE_CHECKS)


class ProbeAllowedInputTypesTests(unittest.TestCase):
    def test_text_like_types_can_hold_marker_and_are_allowed(self):
        # marker(特殊文字列)を typed value に保持できる text 系のみ許可。
        for t in ("", "text", "textarea", "search", "tel", "password"):
            self.assertIn(t, _PROBE_ALLOWED_INPUT_TYPES)

    def test_constrained_and_noninjectable_types_are_excluded(self):
        # 制約付き型（ブラウザ正規化で marker が消える）と非注入コントロールは除外。
        # url/email は値は保持するが native constraint validation で送信がブロックされる。
        for t in ("url", "email", "number", "range", "date", "datetime-local", "time",
                  "month", "week", "color", "file", "checkbox", "radio", "submit",
                  "button", "image", "reset", "hidden"):
            self.assertNotIn(t, _PROBE_ALLOWED_INPUT_TYPES)


if __name__ == "__main__":
    unittest.main()
