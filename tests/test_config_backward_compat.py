"""検査コンフィグの後方互換性テスト。

新しい設定キー/ブロックを追加しても、それらを持たない **古い/最小の config** が
そのまま読み込めて既定値で動くことを固定する（過去の全バージョン対応は不要だが、
未知キーの無視・欠落キーの既定化・空ファイル・パース不能を安全に扱う）。
"""
import tempfile
import unittest
from pathlib import Path

import main
from wscan.engine import _tls_scan_enabled_by_config


def _write(text: str) -> Path:
    d = tempfile.mkdtemp()
    p = Path(d) / "wscan.yaml"
    p.write_text(text, encoding="utf-8")
    return p


class LoadConfigBackwardCompatTests(unittest.TestCase):
    def test_minimal_old_config_defaults(self):
        # features ブロックも新ブロックも無い最小 config（＝古い版の config を模す）。
        cfg = main._load_config(_write("scan:\n  checks:\n    - xss\n  depth: 2\n"))
        # 明示指定した値は反映。
        self.assertEqual(cfg.get("checks"), ["xss"])
        # 新しい機能フラグは既定値（欠落しても KeyError にならない）。
        self.assertFalse(cfg.get("tls_scan"))          # 新規・既定 off
        self.assertTrue(cfg.get("waf_detection"))       # 既存・既定 on
        self.assertTrue(cfg.get("community_payloads"))  # 既定 on
        self.assertTrue(cfg.get("sitemap_crawl"))

    def test_empty_config_is_safe(self):
        self.assertIsInstance(main._load_config(_write("")), dict)
        self.assertIsInstance(main._load_config(_write("{}")), dict)

    def test_unknown_and_obsolete_keys_ignored(self):
        # 廃止/未知のキーがあっても落ちない（前方互換的に無視）。
        cfg = main._load_config(_write(
            "scan:\n  checks: [xss]\n"
            "features:\n  some_removed_flag: true\n  another_obsolete: 123\n"
            "obsolete_section:\n  foo: bar\n"
        ))
        self.assertEqual(cfg.get("checks"), ["xss"])
        self.assertFalse(cfg.get("tls_scan"))

    def test_missing_file_returns_defaults(self):
        self.assertEqual(main._load_config(Path("/nonexistent/wscan.yaml")), {})

    def test_feature_helper_defaults_off_when_missing(self):
        # features.tls_scan が無い config でも False（例外にしない）。
        self.assertFalse(_tls_scan_enabled_by_config(_write("scan:\n  checks: [xss]\n")))
        self.assertFalse(_tls_scan_enabled_by_config(_write("")))
        self.assertFalse(_tls_scan_enabled_by_config(Path("/nonexistent.yaml")))


if __name__ == "__main__":
    unittest.main()
