"""JSON harvest のスコープ判定が query を無視して path-scoped target と照合できることのテスト。"""
import unittest
from urllib.parse import urlparse

from wscan.engine import ScanEngine


class _ScopeStub:
    # _url_matches_scope は self.target_urls だけを参照する純粋な照合。
    _url_matches_scope = ScanEngine._url_matches_scope

    def __init__(self, targets):
        self.target_urls = targets


class JsonHarvestScopeTests(unittest.TestCase):
    def test_path_scoped_target_needs_query_stripped_for_json(self):
        s = _ScopeStub(["https://api.example/v1/users"])
        observed = "https://api.example/v1/users?dry_run=1"
        # full 文字列照合は query 付き observed を弾く（これが Codex #90 R4 のバグ）。
        self.assertFalse(s._url_matches_scope(observed, s.target_urls))
        # query/fragment を落とせば path-scoped target と一致する（_json_in_scope の対処）。
        clean = urlparse(observed)._replace(query="", fragment="").geturl()
        self.assertTrue(s._url_matches_scope(clean, s.target_urls))

    def test_origin_scoped_target_unaffected(self):
        # origin だけの scope は従来通り query 付きでも一致（回帰なし）。
        s = _ScopeStub(["https://api.example"])
        self.assertTrue(
            s._url_matches_scope("https://api.example/v1/users?dry_run=1", s.target_urls)
        )


if __name__ == "__main__":
    unittest.main()
