"""payload_encoder の符号化が JS/SSRF で正しく往復することの回帰テスト。

- ASCII は従来どおり \\xNN / \\uXXXX。
- 非 ASCII / BMP 外（絵文字）は JS が解釈できる UTF-16 表現にする
  （\\x3042 や \\u1f600 のような不正出力を出さない）。
- SSRF の 10 進 IP 変換は妥当な IPv4 のときだけ行う。
"""
import json
import re
import unittest

from wscan import payload_encoder as pe


def _js_decode(literal_body: str) -> str:
    """JS 文字列リテラル本体を解釈した結果を JSON 経由で再現する。

    JS の ``\\xNN`` は JSON に無いので ``\\u00NN`` へ正規化してから
    ``json.loads`` でデコードする（eval は使わない）。
    """
    norm = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: "\\u00" + m.group(1), literal_body)
    return json.loads(f'"{norm}"')


class JsEscapeTests(unittest.TestCase):
    def test_ascii_roundtrip(self):
        self.assertEqual(pe.js_hex("a"), "\\x61")
        self.assertEqual(pe.js_unicode("a"), "\\u0061")
        self.assertEqual(_js_decode(pe.js_hex("abc")), "abc")
        self.assertEqual(_js_decode(pe.js_unicode("abc")), "abc")

    def test_bmp_non_ascii_roundtrip(self):
        # あ (U+3042): js_hex は \xNN で表現できないので \uXXXX にフォールバック。
        self.assertEqual(_js_decode(pe.js_hex("あ")), "あ")
        self.assertEqual(_js_decode(pe.js_unicode("あ")), "あ")
        # 不正な 5 桁 \x3042 を出していないこと。
        self.assertNotIn("\\x3042", pe.js_hex("あ"))

    def test_astral_surrogate_pair(self):
        # 😀 (U+1F600) はサロゲートペアで表現され JS で正しく復元できる。
        out = pe.js_unicode("😀")
        self.assertEqual(out, "\\ud83d\\ude00")
        self.assertEqual(_js_decode(out), "😀")


class SsrfDecimalIpTests(unittest.TestCase):
    @staticmethod
    def _host(variant: str) -> str:
        return variant.split("//", 1)[-1].split("/", 1)[0]

    def test_valid_ip_converted(self):
        variants = pe._ssrf_variants("http://127.0.0.1/")
        self.assertTrue(any("2130706433" in v for v in variants))

    def test_invalid_octets_not_converted(self):
        # 999.999.999.999 は妥当な IPv4 でないので 10 進変換版が現れない。
        variants = pe._ssrf_variants("http://999.999.999.999/")
        self.assertFalse(any(self._host(v).isdigit() for v in variants))


if __name__ == "__main__":
    unittest.main()
