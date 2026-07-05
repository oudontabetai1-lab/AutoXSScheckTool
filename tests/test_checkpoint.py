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


class PageCheckCpUrlTests(unittest.TestCase):
    def test_graphql_uses_exact_url(self):
        from wscan.engine import _page_check_cp_url
        # graphql も exact URL で刻む。origin で刻むと、先行 URL（/users 等）で
        # origin を「済み」にした後、非標準 GraphQL エンドポイント（/gql）が
        # 丸ごと飛ばされてしまうため（exact-URL プローブが走らない）。
        self.assertNotEqual(
            _page_check_cp_url("graphql", "http://h/users"),
            _page_check_cp_url("graphql", "http://h/gql"),
        )
        self.assertEqual(_page_check_cp_url("graphql", "http://h/gql"), "http://h/gql")

    def test_non_origin_scoped_uses_url(self):
        from wscan.engine import _page_check_cp_url
        self.assertEqual(_page_check_cp_url("cache_poisoning", "http://h/a"), "http://h/a")
        self.assertNotEqual(
            _page_check_cp_url("cache_poisoning", "http://h/a"),
            _page_check_cp_url("cache_poisoning", "http://h/b"),
        )


class CheckTypeScopeTests(unittest.TestCase):
    """エンジンの _check_type_in_scope（復元 Finding のチェック絞り込み）。"""

    def _engine(self, checks, scanners=None):
        import types
        from wscan.engine import ScanEngine
        e = types.SimpleNamespace(checks=checks, scanners=dict.fromkeys(scanners or []))
        # bound method を借用
        return lambda ct: ScanEngine._check_type_in_scope(e, ct)

    def test_auto_enabled_scanner_findings_in_scope(self):
        # privesc は checks に無くても scanners にあれば復元対象（Cookie 認証時の自動追加）
        in_scope = self._engine(["xss"], scanners=["xss", "privesc"])
        self.assertTrue(in_scope("privesc_vertical"))
        self.assertTrue(in_scope("xss"))
        self.assertFalse(in_scope("sqli"))

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

    def test_auto_enabled_cms_in_scope_before_crawl(self):
        # cms は crawl 中に自動有効化されるため、復元時点（scanners 未追加）でも
        # in-scope 扱いにして既出 cms Finding を取りこぼさない。
        in_scope = self._engine(["xss"], scanners=["xss"])
        self.assertTrue(in_scope("cms"))
        self.assertTrue(in_scope("cms_version_disclosure"))
        # privesc も同様（Cookie 認証時に自動有効化）
        self.assertTrue(in_scope("privesc_vertical"))
        # 無関係チェックは依然 out-of-scope
        self.assertFalse(in_scope("sqli"))

    def test_cache_deception_alias_in_scope(self):
        # cache_poisoning スキャナは cache_deception も出すので復元対象に含める
        in_scope = self._engine(["cache_poisoning"])
        self.assertTrue(in_scope("cache_poisoning"))
        self.assertTrue(in_scope("cache_deception"))
        # 無関係チェックでは含めない
        self.assertFalse(self._engine(["xss"])("cache_deception"))


class AdaptiveUnitTests(unittest.TestCase):
    """adaptive パスを first-pass チェックと独立した checkpoint 単位で管理することを守る。

    first-pass の各チェックが done でも "(adaptive)" 単位は未完で残せる。これにより
    「first-pass 完了後・adaptive 実行中に abort→resume」で adaptive を再試行できる
    （`_scan_field` の adaptive ゲートがこの区別に依存する）。
    """

    def test_adaptive_unit_independent_of_first_pass_checks(self):
        s = CheckpointState(target_url="http://h", checks=["xss", "sqli"])
        # first-pass の全チェックを done 化（adaptive はまだ）。
        s.mark_done("http://h/a", "q", 0, "xss")
        s.mark_done("http://h/a", "q", 0, "sqli")
        self.assertTrue(s.is_done("http://h/a", "q", 0, "xss"))
        self.assertTrue(s.is_done("http://h/a", "q", 0, "sqli"))
        # adaptive 単位は未完 → resume で adaptive を再試行すべき状態。
        self.assertFalse(s.is_done("http://h/a", "q", 0, "(adaptive)"))
        # adaptive 完了を記録すると、以降は skip 判定になる。
        s.mark_done("http://h/a", "q", 0, "(adaptive)")
        self.assertTrue(s.is_done("http://h/a", "q", 0, "(adaptive)"))

    def test_adaptive_unit_survives_roundtrip(self):
        s = CheckpointState(target_url="http://h", checks=["xss"])
        s.mark_done("http://h/a", "q", 0, "(adaptive)")
        restored = CheckpointState.from_dict(s.to_dict())
        self.assertTrue(restored.is_done("http://h/a", "q", 0, "(adaptive)"))

    def test_fresh_state_is_current_version(self):
        from wscan.checkpoint import CHECKPOINT_VERSION
        s = CheckpointState(target_url="http://h", checks=["xss"])
        self.assertEqual(s.source_version, CHECKPOINT_VERSION)
        self.assertGreaterEqual(s.source_version, 2)

    def test_legacy_fully_done_field_backfills_adaptive(self):
        # v1 で全 configured check が done のフィールドは adaptive 実行済みなので、
        # load 時に "(adaptive)" を補完し、resume で再攻撃しない。
        legacy = CheckpointState.from_dict({
            "version": 1,
            "target_url": "http://h",
            "checks": ["xss", "sqli"],
            "completed_units": [
                unit_key("http://h/a", "q", 0, "xss"),
                unit_key("http://h/a", "q", 0, "sqli"),
            ],
            "findings": [],
        })
        self.assertTrue(legacy.is_done("http://h/a", "q", 0, "(adaptive)"))

    def test_legacy_partial_field_not_backfilled(self):
        # 一部の check だけ done の部分完了フィールドは補完しない
        # （resume で残り check とともに adaptive が走る = v1 挙動）。
        legacy = CheckpointState.from_dict({
            "version": 1,
            "target_url": "http://h",
            "checks": ["xss", "sqli"],
            "completed_units": [
                unit_key("http://h/a", "q", 0, "xss"),  # sqli 未完
            ],
            "findings": [],
        })
        self.assertFalse(legacy.is_done("http://h/a", "q", 0, "(adaptive)"))

    def test_legacy_migrated_saved_as_v2(self):
        # マイグレーション済み（marker 補完済み）は v2 として保存してよい。
        legacy = CheckpointState.from_dict({
            "version": 1,
            "target_url": "http://h",
            "checks": ["xss"],
            "completed_units": [unit_key("http://h/a", "q", 0, "xss")],
            "findings": [],
        })
        from wscan.checkpoint import CHECKPOINT_VERSION
        self.assertEqual(legacy.to_dict()["version"], CHECKPOINT_VERSION)
        # 再読込でも adaptive marker は保持され、二重マイグレーションでも無害。
        reloaded = CheckpointState.from_dict(legacy.to_dict())
        self.assertTrue(reloaded.is_done("http://h/a", "q", 0, "(adaptive)"))

    def test_v2_checkpoint_no_spurious_adaptive_backfill(self):
        # v2 は marker をそのまま尊重し、マイグレーションで勝手に補完しない。
        s = CheckpointState(target_url="http://h", checks=["xss"])
        s.mark_done("http://h/a", "q", 0, "xss")  # adaptive 未完のまま
        restored = CheckpointState.from_dict(s.to_dict())
        self.assertFalse(restored.is_done("http://h/a", "q", 0, "(adaptive)"))


class SaveCheckpointFindingsTests(unittest.TestCase):
    """abort 時に `_save_checkpoint` が in-memory Finding を永続化することを守る。

    payload 単位の即時停止は `_scan_field` 末尾の保存より前に抜けるため、run() の
    abort ハンドラが `_save_checkpoint()` を呼んで中断時点の Finding を snapshot に
    載せる。ここでは persistence 機構そのもの（all_findings → checkpoint.findings →
    ディスク）が働くことを検証する。
    """

    def test_in_memory_findings_persisted_on_save(self):
        import types
        from wscan.engine import ScanEngine
        from wscan.scanners.base import Finding

        with tempfile.TemporaryDirectory() as d:
            state = CheckpointState(target_url="http://h", checks=["xss"])
            f = Finding(
                check_type="xss",
                severity="high",
                url="http://h/a",
                field_name="q",
                payload="<script>",
                evidence="reflected",
            )
            e = types.SimpleNamespace(
                enable_checkpoint=True,
                checkpoint=state,
                all_findings=[f],
                output_dir=Path(d),
                wave_errors=[],
            )
            # 実メソッドを借用して保存（abort ハンドラが呼ぶのと同じ経路）。
            ScanEngine._save_checkpoint(e)

            loaded = load_checkpoint(d)
            self.assertIsNotNone(loaded)
            self.assertEqual(len(loaded.findings), 1)
            self.assertEqual(loaded.findings[0]["check_type"], "xss")
            self.assertEqual(loaded.findings[0]["field_name"], "q")

    def test_save_noop_when_checkpoint_disabled(self):
        import types
        from wscan.engine import ScanEngine

        with tempfile.TemporaryDirectory() as d:
            e = types.SimpleNamespace(
                enable_checkpoint=False,
                checkpoint=None,
                all_findings=[],
                output_dir=Path(d),
                wave_errors=[],
            )
            ScanEngine._save_checkpoint(e)  # 例外を出さず no-op
            self.assertIsNone(load_checkpoint(d))


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
