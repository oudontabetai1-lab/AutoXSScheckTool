"""JSON harvest のスコープ判定が query を無視して path-scoped target と照合できることのテスト。"""
import unittest
from urllib.parse import urlparse

from wscan.engine import ScanEngine


class _ScopeStub:
    # _url_matches_scope は self.target_urls だけを参照する純粋な照合。
    _url_matches_scope = ScanEngine._url_matches_scope

    def __init__(self, targets):
        self.target_urls = targets


class _PredicateStub:
    # _json_target_in_scope（scope=query除去 / exclusion=原文）を実コードのまま検証する。
    _url_matches_scope = ScanEngine._url_matches_scope
    _is_attack_target_url = ScanEngine._is_attack_target_url
    _is_url_excluded = ScanEngine._is_url_excluded
    _json_target_in_scope = ScanEngine._json_target_in_scope

    def __init__(self, targets, excludes):
        self.target_urls = targets
        self.exclude_urls = excludes


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

    def test_json_predicate_scope_stripped_exclusion_original(self):
        # scope は query 除去で path-scoped target と一致。
        p = _PredicateStub(["https://api.example/v1/users"], [])
        self.assertTrue(p._json_target_in_scope("https://api.example/v1/users?dry_run=1"))

    def test_json_predicate_honors_query_specific_exclusion(self):
        # exclusion は observed 原文（query 込み）で判定＝query 固有の除外が効く。
        p = _PredicateStub(
            ["https://api.example/v1/users"],
            ["https://api.example/v1/users?dry_run=1"],
        )
        # query 固有の除外に一致する observed は弾く（scope 通過でも exclusion 優先）。
        self.assertFalse(p._json_target_in_scope("https://api.example/v1/users?dry_run=1"))
        # 除外に一致しない別 query は通す。
        self.assertTrue(p._json_target_in_scope("https://api.example/v1/users?page=2"))

    def test_json_predicate_honors_full_url_wildcard_exclusion_with_query(self):
        # full-URL ワイルドカード（url 全体を照合＝query 込み）。query を落とすと一致しなくなる。
        p = _PredicateStub(
            ["https://api.example/v1/users"],
            ["https://api.example/v1/users?dry_run=*"],
        )
        self.assertFalse(p._json_target_in_scope("https://api.example/v1/users?dry_run=1"))


if __name__ == "__main__":
    unittest.main()
