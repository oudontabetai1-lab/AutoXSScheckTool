"""再開可能スキャン（チェックポイント）の純粋ロジックのテスト。"""
import unittest
import tempfile
from pathlib import Path

from wscan.checkpoint import (
    CheckpointState,
    unit_key,
    save_checkpoint,
    load_checkpoint,
    checkpoint_path,
)


class UnitKeyTests(unittest.TestCase):
    def test_trailing_slash_normalised(self):
        self.assertEqual(
            unit_key("http://h/a/", "q", 0, "xss"),
            unit_key("http://h/a", "q", 0, "xss"),
        )

    def test_distinct_checks_distinct_keys(self):
        self.assertNotEqual(
            unit_key("http://h/a", "q", 0, "xss"),
            unit_key("http://h/a", "q", 0, "sqli"),
        )

    def test_url_param_vs_form_distinct_keys(self):
        # 同名・同 form_index でも URL param と form field は別単位
        self.assertNotEqual(
            unit_key("http://h/a", "id", 0, "sqli", is_url_param=True),
            unit_key("http://h/a", "id", 0, "sqli", is_url_param=False),
        )


class StateTests(unittest.TestCase):
    def test_mark_and_is_done(self):
        s = CheckpointState(target_url="http://h", checks=["xss"])
        self.assertFalse(s.is_done("http://h/a", "q", 0, "xss"))
        s.mark_done("http://h/a", "q", 0, "xss")
        self.assertTrue(s.is_done("http://h/a", "q", 0, "xss"))
        # slash-insensitive
        self.assertTrue(s.is_done("http://h/a/", "q", 0, "xss"))
        # 同名の URL param 単位はまだ未完了（位置がキーに含まれる）
        self.assertFalse(s.is_done("http://h/a", "q", 0, "xss", is_url_param=True))

    def test_roundtrip(self):
        s = CheckpointState(target_url="http://h", checks=["xss", "sqli"])
        s.mark_done("http://h/a", "q", 0, "xss")
        s.add_finding({"check_type": "xss", "url": "http://h/a"})
        restored = CheckpointState.from_dict(s.to_dict())
        self.assertEqual(restored.target_url, "http://h")
        self.assertTrue(restored.is_done("http://h/a", "q", 0, "xss"))
        self.assertEqual(len(restored.findings), 1)

    def test_compatibility(self):
        s = CheckpointState(target_url="http://h/", checks=["xss", "sqli"])
        self.assertTrue(s.is_compatible_with("http://h", ["xss"]))
        self.assertTrue(s.is_compatible_with("http://h", ["xss", "sqli"]))
        # superset of saved checks → not compatible
        self.assertFalse(s.is_compatible_with("http://h", ["xss", "os"]))
        # different target → not compatible
        self.assertFalse(s.is_compatible_with("http://other", ["xss"]))


class CheckTypeScopeTests(unittest.TestCase):
    """エンジンの _check_type_in_scope（復元 Finding のチェック絞り込み）。"""

    def _engine(self, checks):
        import types
        from wscan.engine import ScanEngine
        e = types.SimpleNamespace(checks=checks)
        # bound method を借用
        return lambda ct: ScanEngine._check_type_in_scope(e, ct)

    def test_exact_and_prefix_match(self):
        in_scope = self._engine(["xss", "graphql", "jwt"])
        self.assertTrue(in_scope("xss"))
        self.assertTrue(in_scope("graphql_introspection"))
        self.assertTrue(in_scope("jwt_alg_none"))

    def test_out_of_scope_excluded(self):
        in_scope = self._engine(["xss"])
        self.assertFalse(in_scope("sqli"))
        self.assertFalse(in_scope("sqli_error"))
        # "xss" は "dom_xss" にマッチしない
        self.assertFalse(in_scope("dom_xss"))


class IoTests(unittest.TestCase):
    def test_save_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            s = CheckpointState(target_url="http://h", checks=["xss"])
            s.mark_done("http://h/a", "q", 0, "xss")
            save_checkpoint(d, s)
            self.assertTrue(checkpoint_path(d).exists())
            # load by directory
            loaded = load_checkpoint(d)
            self.assertIsNotNone(loaded)
            self.assertTrue(loaded.is_done("http://h/a", "q", 0, "xss"))
            # load by file path
            loaded2 = load_checkpoint(checkpoint_path(d))
            self.assertIsNotNone(loaded2)

    def test_load_missing_returns_none(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(load_checkpoint(d))

    def test_load_corrupt_returns_none(self):
        with tempfile.TemporaryDirectory() as d:
            p = checkpoint_path(d)
            p.write_text("{ not json", encoding="utf-8")
            self.assertIsNone(load_checkpoint(d))


if __name__ == "__main__":
    unittest.main()
