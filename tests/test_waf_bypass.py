"""WAF/フィルタ・バイパス用の決定論的ペイロード生成（純粋関数）のテスト。

ネットワーク/ブラウザ非依存。``wscan.waf_bypass`` の生成器が
  - 期待する種類のバイパス変種を含むか（検出力 / false negative ガード）
  - 余計な空入力や重複を出さないか（投入の無駄/誤検知の温床を避ける）
を検証する。
"""
import unittest

from wscan import waf_bypass


class CrlfBypassVariantTests(unittest.TestCase):
    def test_includes_raw_and_encoded_newlines(self):
        variants = waf_bypass.crlf_bypass_variants(
            "test@example.com", "Bcc: attacker@evil.example.com"
        )
        payloads = [p for p, _desc in variants]
        # 生 CRLF / LF のみ / パーセントエンコード / 二重エンコードを必ず含む。
        self.assertIn(
            "test@example.com\r\nBcc: attacker@evil.example.com", payloads
        )
        self.assertIn(
            "test@example.com\nBcc: attacker@evil.example.com", payloads
        )
        self.assertIn(
            "test@example.com%0d%0aBcc: attacker@evil.example.com", payloads
        )
        self.assertTrue(
            any("%250d%250a" in p for p in payloads),
            "二重エンコード CRLF 変種が無い",
        )

    def test_every_payload_carries_injected_header(self):
        variants = waf_bypass.crlf_bypass_variants(
            "user@x.test", "Cc: attacker@evil.example.com"
        )
        self.assertTrue(variants)
        for payload, desc in variants:
            self.assertIn("Cc: attacker@evil.example.com", payload)
            self.assertTrue(desc)

    def test_no_duplicates(self):
        variants = waf_bypass.crlf_bypass_variants("a@b.test", "Bcc: c@d.test")
        payloads = [p for p, _ in variants]
        self.assertEqual(len(payloads), len(set(payloads)))

    def test_empty_header_yields_nothing(self):
        self.assertEqual(waf_bypass.crlf_bypass_variants("a@b.test", ""), [])


class UploadBypassProbeTests(unittest.TestCase):
    def setUp(self):
        self.probes = waf_bypass.upload_bypass_probes()

    def test_unique_filenames(self):
        names = [p.filename for p in self.probes]
        self.assertEqual(len(names), len(set(names)))

    def test_contains_alt_extension_and_case_bypasses(self):
        names = {p.filename for p in self.probes}
        # 代替実行拡張子・大文字小文字・末尾ドット/空白のバイパス変種を含む。
        self.assertIn("wscan_probe.php5", names)
        self.assertIn("wscan_probe.phar", names)
        self.assertIn("wscan_probe.PHP", names)
        self.assertIn("wscan_probe.php.", names)
        self.assertTrue(any(n.endswith(" ") for n in names), "末尾空白変種が無い")

    def test_magic_byte_polyglot_present(self):
        polyglots = [p for p in self.probes if p.content.startswith(b"GIF89a")]
        self.assertTrue(polyglots, "GIF89a polyglot が無い")
        # polyglot でも実行されれば応答に現れる probe マーカーを含む本体であること。
        self.assertIn(b"wscan-probe-", polyglots[0].content)

    def test_each_probe_has_content_type(self):
        for p in self.probes:
            self.assertTrue(p.content_type)
            self.assertTrue(p.content)
            self.assertTrue(p.description)

    def test_backward_compatible_basic_probes_first(self):
        # 互換: 従来の基本プローブ（PHP）が先頭に残っていること。
        self.assertEqual(self.probes[0].filename, "wscan_probe.php")


if __name__ == "__main__":
    unittest.main()
