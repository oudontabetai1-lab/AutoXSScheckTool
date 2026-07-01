import gzip
import tempfile
import unittest
from pathlib import Path

from wscan.textio import read_text_resilient, safe_decode


class ReadTextResilientTests(unittest.TestCase):
    def _write(self, data: bytes) -> str:
        p = Path(tempfile.mkdtemp()) / "f.txt"
        p.write_bytes(data)
        return str(p)

    def test_reads_plain_utf8(self):
        path = self._write("テスト ascii".encode("utf-8"))
        self.assertEqual(read_text_resilient(path), "テスト ascii")

    def test_reads_utf8_with_bom(self):
        path = self._write("hello 日本語".encode("utf-8-sig"))
        # BOM should be stripped by utf-8-sig
        self.assertEqual(read_text_resilient(path), "hello 日本語")

    def test_reads_shift_jis_without_crashing(self):
        # A Shift-JIS / cp932 file would raise UnicodeDecodeError under utf-8.
        path = self._write("日本語のコメント".encode("cp932"))
        self.assertEqual(read_text_resilient(path), "日本語のコメント")

    def test_reads_gzipped_file_transparently(self):
        # gzip 圧縮ファイル（マジック 0x1f 0x8b）を UTF-8 で読むと
        # "can't decode byte 0x8b in position 1" で落ちる。透過的に解凍する。
        path = self._write(gzip.compress('{"hello": "日本語"}'.encode("utf-8")))
        self.assertEqual(read_text_resilient(path), '{"hello": "日本語"}')


class SafeDecodeTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(safe_decode(b""), "")

    def test_plain_utf8(self):
        self.assertEqual(safe_decode("テスト".encode("utf-8")), "テスト")

    def test_invalid_bytes_do_not_raise(self):
        # Mixed valid text + invalid UTF-8 continuation bytes.
        out = safe_decode(b"valid \xff\xfe end")
        self.assertIsInstance(out, str)
        self.assertIn("valid", out)
        self.assertIn("end", out)

    def test_limit_truncates_before_decode(self):
        out = safe_decode(b"abcdefg", limit=3)
        self.assertEqual(out, "abc")

    def test_gzip_bytes_are_decompressed(self):
        # 0x1f 0x8b で始まる gzip バイト列を透過的に解凍してからデコードする。
        out = safe_decode(gzip.compress("テスト body".encode("utf-8")))
        self.assertEqual(out, "テスト body")


if __name__ == "__main__":
    unittest.main()
