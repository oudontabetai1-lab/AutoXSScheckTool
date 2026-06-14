"""LLM 非依存ペイロード変異 :mod:`wscan.payload_mutator` の回帰テスト（純粋関数）。

二重エンコード/NULL バイト/バックスラッシュ等のバイパス変種が正しく生成され、
high/ultra 級の素朴な防御（``..`` ブラックリスト＋拡張子チェック＋二重デコード等）を
突破できる形になっていることを固定する。
"""
import unittest
from urllib.parse import unquote

from wscan import payload_mutator as pm


class MutatePayloadTests(unittest.TestCase):
    def test_generic_encodings_present(self):
        out = pm.mutate("a b'", "sqli")
        self.assertIn(pm._url_encode("a b'"), out)
        self.assertIn(pm._double_url_encode("a b'"), out)
        self.assertNotIn("a b'", out)  # 元 payload 自身は含めない

    def test_sqli_case_and_comment(self):
        out = pm.mutate("UNION SELECT", "sqli")
        self.assertIn("UNION/**/SELECT", out)
        self.assertTrue(any(v.lower() == "union select" or v != "UNION SELECT" for v in out))

    def test_path_traversal_double_encode_null_extension(self):
        # 二重/単一エンコード + NULL + 拡張子で `..` ブラックリストと拡張子チェックを回避。
        out = pm.mutate("../../../../etc/passwd", "path_traversal")
        # 「`..` リテラルを含まず」「`.pdf` で終わり」「二重デコードで etc/passwd へ到達」する
        # 真のバイパス変種が少なくとも1つ存在する（素朴な `..`+拡張子ゲートを突破）。
        true_bypass = [
            p for p in out
            if ".." not in p
            and p.endswith(".pdf")
            and "etc/passwd" in unquote(unquote(p))
        ]
        self.assertTrue(true_bypass, f"no double-encode+null bypass variant; got {out!r}")

    def test_open_redirect_backslash_variants(self):
        out = pm.mutate("https://evil.example.com", "open_redirect")
        self.assertIn("/\\evil.example.com", out)
        self.assertIn("//evil.example.com", out)


class MutationPayloadsTests(unittest.TestCase):
    def test_sqli_includes_blind_seeds(self):
        # キャップ順で漏れがちな blind(boolean/time) を確実に投入する。
        out = pm.mutation_payloads("sqli")
        self.assertIn("1 AND 1=1", out)                       # boolean-based blind
        self.assertTrue(any("SLEEP" in p.upper() for p in out))  # time-based blind

    def test_os_includes_sleep_seed(self):
        out = pm.mutation_payloads("os")
        self.assertIn("; sleep 3", out)

    def test_path_traversal_includes_decodable_bypass(self):
        out = pm.mutation_payloads("path_traversal")
        self.assertTrue(any("etc/passwd" in unquote(unquote(p)) and ".." not in p for p in out))

    def test_seeds_are_merged_and_deduped(self):
        # BYPASS_SEEDS を持たない check_type ではシードが基点になる（キャップに埋もれない）。
        out = pm.mutation_payloads("ldap", seeds=["custom_seed", "custom_seed"])
        self.assertEqual(len(out), len(set(out)))           # 重複なし
        self.assertIn("custom_seed", out)                    # シードも基点に含む

    def test_bypass_seeds_take_priority_over_caller_seeds(self):
        # blind 系の取りこぼし防止のため、BYPASS_SEEDS をシードより優先して前置する。
        out = pm.mutation_payloads("sqli", seeds=["zzz_low_priority_seed"])
        self.assertIn("1 AND 1=1", out)                      # blind は必ず含む
        self.assertTrue(any("SLEEP" in p.upper() for p in out))

    def test_later_bypass_seed_survives_cap(self):
        # ラウンドロビン配分で 2 つ目以降の BYPASS_SEEDS（Windows win.ini）が
        # 先頭シードの変種に食い潰されず残る。
        out = pm.mutation_payloads("path_traversal")
        self.assertTrue(any("win.ini" in p for p in out), f"win.ini seed dropped: {out!r}")

    def test_caller_seeds_survive_cap_with_many(self):
        seeds = ["s1", "s2", "s3", "s4", "s5", "s6"]
        out = pm.mutation_payloads("path_traversal", seeds=seeds)
        for s in seeds:
            self.assertIn(s, out)  # 全シードがキャップ後も残る

    def test_double_encode_dots_is_truly_double(self):
        # `_double_encode_dots_slashes` は %2e ではなく %252e を生成する（真の二重）。
        self.assertIn("%252e", pm._double_encode_dots_slashes("../"))

    def test_unknown_check_type_is_safe(self):
        self.assertEqual(pm.mutation_payloads("nonexistent"), [])
        self.assertEqual(pm.mutate("", "sqli"), [])


if __name__ == "__main__":
    unittest.main()
