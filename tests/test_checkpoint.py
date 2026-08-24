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
from wscan.injection_point import InjectionPoint


class UnitKeyTests(unittest.TestCase):
    def test_legacy_form_key_is_byte_identical(self):
        self.assertEqual(
            unit_key("http://h/a/", "id", 0, "sqli", is_url_param=False),
            "http://h/a\x1fid\x1f0\x1ff\x1fsqli",
        )

    def test_legacy_url_param_key_is_byte_identical(self):
        self.assertEqual(
            unit_key("http://h/a/", "id", 0, "sqli", is_url_param=True),
            "http://h/a\x1fid\x1f0\x1fu\x1fsqli",
        )

    def test_trailing_slash_normalised(self):
        self.assertEqual(
            unit_key("http://h/a/", "q", 0, "xss"),
            unit_key("http://h/a", "q", 0, "xss"),
        )

    def test_query_value_trailing_slash_remains_distinct(self):
        self.assertNotEqual(
            unit_key("http://h/p?z=/admin/&a=1", "q", 0, "xss"),
            unit_key("http://h/p?a=1&z=/admin", "q", 0, "xss"),
        )

    def test_legacy_whole_rstrip_matches_v5_query_value_key(self):
        url = "https://h/p?z=/admin/"
        self.assertEqual(
            unit_key(
                url,
                "q",
                0,
                "xss",
                legacy_whole_rstrip=True,
            ),
            "https://h/p?z=/admin\x1fq\x1f0\x1ff\x1fxss",
        )
        self.assertTrue(unit_key(url, "q", 0, "xss").startswith(f"{url}\x1f"))

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

    def test_rotating_nonce_values_share_one_unit_key(self):
        self.assertEqual(
            unit_key("https://h/a?op=create&nonce=1699999999", "id", 0, "sqli"),
            unit_key("https://h/a?nonce=1699999999000&op=create", "id", 0, "sqli"),
        )

    def test_meaningful_timestamp_values_have_distinct_unit_keys(self):
        self.assertNotEqual(
            unit_key("https://h/a?timestamp=1699999999", "id", 0, "sqli"),
            unit_key("https://h/a?timestamp=1700000000", "id", 0, "sqli"),
        )

    def test_meaningful_operation_values_remain_distinct(self):
        self.assertNotEqual(
            unit_key("https://h/a?op=create", "id", 0, "sqli"),
            unit_key("https://h/a?op=delete", "id", 0, "sqli"),
        )


class StateTests(unittest.TestCase):
    def test_form_injection_point_matches_legacy_unit(self):
        state = CheckpointState()
        ip = InjectionPoint.for_form("http://h/a/", "id", 2)
        state.mark_done_ip(ip, "sqli")
        self.assertTrue(state.is_done("http://h/a", "id", 2, "sqli"))
        self.assertTrue(state.is_done_ip(ip, "sqli"))

    def test_url_param_injection_point_matches_legacy_unit(self):
        state = CheckpointState()
        ip = InjectionPoint.for_url_param("http://h/a/", "id")
        state.mark_done("http://h/a", "id", 0, "sqli", is_url_param=True)
        self.assertTrue(state.is_done_ip(ip, "sqli"))

    def test_non_ip_path_normalizes_rotating_nonce(self):
        state = CheckpointState()
        state.mark_done(
            "https://h/action?op=create&nonce=1699999999", "name", 0, "sqli"
        )
        self.assertTrue(state.is_done(
            "https://h/action?nonce=1699999999000&op=create", "name", 0, "sqli"
        ))

    def test_ip_path_normalizes_rotating_nonce(self):
        state = CheckpointState()
        first = InjectionPoint.for_url_param(
            "https://h/action?op=create&nonce=1699999999", "name"
        )
        second = InjectionPoint.for_url_param(
            "https://h/action?nonce=1699999999000&op=create", "name"
        )
        state.mark_done_ip(first, "sqli")
        self.assertTrue(state.is_done_ip(second, "sqli"))

    def test_json_body_pointer_and_method_do_not_collide(self):
        state = CheckpointState()
        profile = InjectionPoint.for_json_body(
            "POST", "http://h/users", "/profile/email"
        )
        billing = InjectionPoint.for_json_body(
            "POST", "http://h/users", "/billing/email"
        )
        get_profile = InjectionPoint.for_json_body(
            "GET", "http://h/users", "/profile/email"
        )
        state.mark_done_ip(profile, "sqli")
        self.assertTrue(state.is_done_ip(profile, "sqli"))
        self.assertFalse(state.is_done_ip(billing, "sqli"))
        self.assertFalse(state.is_done_ip(get_profile, "sqli"))

    def test_v3_checkpoint_resumes_without_key_migration(self):
        legacy_key = "http://h/a\x1fid\x1f0\x1ff\x1fsqli"
        state = CheckpointState.from_dict({
            "version": 3,
            "target_url": "http://h",
            "checks": ["sqli"],
            "completed_units": [legacy_key],
            "findings": [],
        })
        self.assertEqual(state.source_version, 3)
        self.assertTrue(state.is_done("http://h/a", "id", 0, "sqli"))
        self.assertIn(legacy_key, state.completed_units)

    def test_v5_checkpoint_urls_migrate_for_non_ip_and_ip_lookups(self):
        old_url = "https://h/action?nonce=1699999999&op=create"
        legacy_form_key = "\x1f".join([old_url, "name", "0", "f", "sqli"])
        legacy_json_key = "\x1f".join(
            [old_url, "name", "0", "j:POST", "sqli", "/name"]
        )
        state = CheckpointState.from_dict({
            "version": 5,
            "target_url": "https://h",
            "checks": ["sqli"],
            "completed_units": [legacy_form_key, legacy_json_key],
            "findings": [],
        })

        self.assertTrue(state.is_done(
            "https://h/action?op=create&nonce=1699999999000", "name", 0, "sqli"
        ))
        resumed_ip = InjectionPoint.for_json_body(
            "POST",
            "https://h/action?op=create&nonce=1700000000",
            "/name",
        )
        self.assertTrue(state.is_done_ip(resumed_ip, "sqli"))
        self.assertTrue(all(
            key.split("\x1f")[0] == "https://h/action?op=create"
            for key in state.completed_units
        ))

    def test_v5_checkpoint_target_url_is_normalized_during_migration(self):
        state = CheckpointState.from_dict({
            "version": 5,
            "target_url": "https://h/start?nonce=1699999999",
            "checks": ["sqli"],
            "completed_units": [],
            "findings": [],
        })

        self.assertEqual(state.target_url, "https://h/start")

    def test_v5_migration_trims_path_but_keeps_query_value_slash(self):
        old_url = "https://h/action/?z=/admin/&a=1"
        legacy_key = "\x1f".join([old_url, "name", "0", "f", "sqli"])
        state = CheckpointState.from_dict({
            "version": 5,
            "target_url": old_url,
            "checks": ["sqli"],
            "completed_units": [legacy_key],
            "findings": [],
        })

        expected_url = "https://h/action/?a=1&z=/admin/"
        self.assertEqual(state.target_url, expected_url)
        self.assertEqual(next(iter(state.completed_units)).split("\x1f")[0], expected_url)
        self.assertTrue(state.is_done(expected_url, "name", 0, "sqli"))

    def test_v5_whole_url_rstrip_key_has_read_only_lookup_fallback(self):
        url = "https://h/p?z=/admin/"
        legacy_key = unit_key(
            url,
            "name",
            0,
            "sqli",
            legacy_whole_rstrip=True,
        )
        state = CheckpointState.from_dict({
            "version": 5,
            "target_url": "https://h",
            "checks": ["sqli"],
            "completed_units": [legacy_key],
            "findings": [],
        })

        self.assertTrue(state.is_done(url, "name", 0, "sqli"))
        self.assertTrue(state.is_done_ip(InjectionPoint.for_form(url, "name"), "sqli"))

        current = CheckpointState()
        current.mark_done(url, "name", 0, "sqli")
        normal_key = unit_key(url, "name", 0, "sqli")
        self.assertEqual(current.completed_units, {normal_key})
        self.assertNotIn(legacy_key, current.completed_units)

        current_ip = CheckpointState()
        current_ip.mark_done_ip(InjectionPoint.for_form(url, "name"), "sqli")
        self.assertEqual(current_ip.completed_units, {normal_key})
        self.assertNotIn(legacy_key, current_ip.completed_units)

    def test_v5_legacy_fallback_is_noop_for_url_without_query_value_slash(self):
        url = "https://h/p?op=create"
        normal_key = unit_key(url, "name", 0, "sqli")
        legacy_key = unit_key(
            url,
            "name",
            0,
            "sqli",
            legacy_whole_rstrip=True,
        )
        self.assertEqual(normal_key, legacy_key)
        state = CheckpointState(completed_units={normal_key})
        self.assertTrue(state.is_done(url, "name", 0, "sqli"))

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

    def test_compatibility_normalizes_rotating_target_nonce(self):
        s = CheckpointState(
            target_url="https://h/start?nonce=1699999999",
            checks=["sqli"],
        )

        self.assertTrue(s.is_compatible_with(
            "https://h/start?nonce=1699999999000", ["sqli"]
        ))

    def test_compatibility_keeps_meaningful_target_operations_distinct(self):
        s = CheckpointState(
            target_url="https://h/start?op=create",
            checks=["sqli"],
        )

        self.assertFalse(s.is_compatible_with(
            "https://h/start?op=delete", ["sqli"]
        ))

    def test_compatibility_trims_path_but_keeps_query_value_slash(self):
        s = CheckpointState(
            target_url="https://h/start/?z=/admin/&a=1",
            checks=["sqli"],
        )

        # path 末尾スラッシュはクエリが続くと保持される（/start/ と /start は別）。
        self.assertTrue(s.is_compatible_with(
            "https://h/start/?a=1&z=/admin/", ["sqli"]
        ))
        # query 値の末尾スラッシュ違いは別 operation。
        self.assertFalse(s.is_compatible_with(
            "https://h/start/?a=1&z=/admin", ["sqli"]
        ))
        # path 末尾スラッシュ違いも別（クエリが続くため保持）。
        self.assertFalse(s.is_compatible_with(
            "https://h/start?a=1&z=/admin/", ["sqli"]
        ))


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

    def test_adaptive_check_units_are_independent_and_survive_roundtrip(self):
        s = CheckpointState(target_url="http://h", checks=["xss"])
        s.mark_done("http://h/a", "q", 0, "(adaptive:xss)")
        restored = CheckpointState.from_dict(s.to_dict())
        self.assertTrue(restored.is_done("http://h/a", "q", 0, "(adaptive:xss)"))
        self.assertFalse(restored.is_done("http://h/a", "q", 0, "(adaptive:sqli)"))

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

    def test_legacy_migrated_saved_as_current_version(self):
        # マイグレーション済み（marker 補完済み）は現行版として保存してよい。
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

    def test_v2_field_level_adaptive_marker_remains_readable(self):
        restored = CheckpointState.from_dict({
            "version": 2,
            "target_url": "http://h",
            "checks": ["xss", "sqli"],
            "completed_units": [unit_key("http://h/a", "q", 0, "(adaptive)")],
            "findings": [],
        })

        self.assertEqual(restored.source_version, 2)
        self.assertTrue(restored.is_done("http://h/a", "q", 0, "(adaptive)"))


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

    def test_malformed_version_does_not_crash(self):
        # 非数値 version でも from_dict は落ちず legacy(v1) 扱いにフォールバック。
        s = CheckpointState.from_dict({
            "version": "not-a-number",
            "target_url": "http://h",
            "checks": ["xss"],
            "completed_units": [],
            "findings": [],
        })
        self.assertEqual(s.source_version, 1)

    def test_load_malformed_version_file_returns_state(self):
        # ファイル経由でも resume がクラッシュせず、使える state を返す。
        import json as _json
        with tempfile.TemporaryDirectory() as d:
            checkpoint_path(d).write_text(
                _json.dumps({"version": None, "target_url": "http://h", "checks": []}),
                encoding="utf-8",
            )
            loaded = load_checkpoint(d)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.source_version, 1)

    def test_load_corrupt_metadata_returns_none(self):
        # from_dict が想定外の型で落ちる場合も None（クラッシュしない）。
        import json as _json
        with tempfile.TemporaryDirectory() as d:
            checkpoint_path(d).write_text(
                _json.dumps({"version": 2, "checks": "not-a-list"}),
                encoding="utf-8",
            )
            # list("not-a-list") は落ちないが、completed_units 等が壊れても None 安全網。
            # ここでは少なくともクラッシュしないことを保証する。
            result = load_checkpoint(d)
            self.assertTrue(result is None or isinstance(result, CheckpointState))

    def test_load_corrupt_returns_none(self):
        with tempfile.TemporaryDirectory() as d:
            p = checkpoint_path(d)
            p.write_text("{ not json", encoding="utf-8")
            self.assertIsNone(load_checkpoint(d))


if __name__ == "__main__":
    unittest.main()


class AttemptLedgerPersistenceTests(unittest.TestCase):
    def test_ledger_survives_save_load(self):
        from wscan.attempt_ledger import AttemptLedger, Attempt
        led = AttemptLedger()
        key = ("http://t/p", "q", "0", "u", "")
        led.record(key, "xss", Attempt("<svg/onload=1>", status=200, reflected=True))
        state = CheckpointState(target_url="http://t/p", checks=["xss"])
        state.attempt_ledger = led.to_dict()
        with tempfile.TemporaryDirectory() as d:
            save_checkpoint(d, state)
            loaded = load_checkpoint(checkpoint_path(d))
        back = AttemptLedger.from_dict(loaded.attempt_ledger)
        h = back.history(key, "xss")
        self.assertEqual(len(h), 1)
        self.assertEqual(h[0].payload, "<svg/onload=1>")
        self.assertTrue(h[0].reflected)

    def test_missing_ledger_key_defaults_empty(self):
        # 旧 checkpoint（attempt_ledger キー無し）でも壊れない。
        state = CheckpointState.from_dict({"version": 4, "target_url": "http://t",
                                           "checks": ["xss"], "completed_units": []})
        self.assertEqual(state.attempt_ledger, {})

    def test_v5_ledger_record_urls_migrate_to_stable_key_parts(self):
        from wscan.attempt_ledger import AttemptLedger

        raw_url = (
            "https://h/action/?z=/admin/&nonce=1699999999"
            "&csrf=old&op=create"
        )
        serialized = {
            "max_per_key": 40,
            "records": [
                {
                    "key": [raw_url, "name", "0", "u", ""],
                    "check": "sqli",
                    "attempts": [{"payload": "'", "status": 500}],
                },
                {"key": []},
                {"key": (raw_url, "name", "0", "u", "")},
                "broken-record",
            ],
        }
        state = CheckpointState.from_dict({
            "version": 5,
            "target_url": "https://h",
            "checks": ["sqli"],
            "completed_units": [],
            "attempt_ledger": serialized,
        })
        resumed = InjectionPoint.for_url_param(
            "https://h/action/?op=create&csrf=new&nonce=1700000000&z=/admin/",
            "name",
        )

        migrated_key = state.attempt_ledger["records"][0]["key"]
        self.assertEqual(tuple(migrated_key), resumed.stable_key_parts())
        ledger = AttemptLedger.from_dict(state.attempt_ledger)
        history = ledger.history(resumed.stable_key_parts(), "sqli")
        self.assertEqual([attempt.payload for attempt in history], ["'"])


def test_legacy_fallback_only_applies_to_loaded_v5_checkpoints():
    """v5 legacy fallback は fresh v6 state では無効（初回スキャンで別 operation を潰さない）。

    fresh v6: `?z=/admin` 完了後に `?z=/admin/` は未完了扱い（fallback 無効）。
    v5 load: whole-url rstrip で保存された `?z=/admin` を `?z=/admin/` の照合で拾う（互換）。
    """
    from wscan.checkpoint import CheckpointState, unit_key, CHECKPOINT_VERSION

    admin = "https://h/p?z=/admin"
    admin_slash = "https://h/p?z=/admin/"

    # fresh v6 state
    fresh = CheckpointState(target_url="https://h/", checks=["xss"])
    assert fresh.source_version >= 6
    fresh.mark_done(admin, "q", 0, "xss", is_url_param=True)
    assert fresh.is_done(admin, "q", 0, "xss", is_url_param=True) is True
    # 別 operation（末尾スラッシュ有り）は未完了のまま（fallback を適用しない）
    assert fresh.is_done(admin_slash, "q", 0, "xss", is_url_param=True) is False

    # v5 loaded state: 旧 whole-url rstrip 形のキーを completed_units に持つ
    legacy_key = unit_key(
        admin_slash, "q", 0, "xss", True, legacy_whole_rstrip=True
    )
    v5 = CheckpointState.from_dict({
        "version": 5,
        "target_url": "https://h/",
        "checks": ["xss"],
        "completed_units": [legacy_key],
    })
    assert v5.source_version == 5
    # 新 URL（スラッシュ保持）で照合しても legacy fallback でヒットする
    assert v5.is_done(admin_slash, "q", 0, "xss", is_url_param=True) is True


def test_legacy_fallback_excludes_units_marked_during_v5_resume():
    """v5 resume 中に新規 mark した単位は legacy fallback の対象外（Codex #103 P1）。

    v5 state をロード後、`?z=/admin` を新規に mark_done しても、distinct な
    `?z=/admin/` は完了扱いにならない（新規 mark は _legacy_units に含めない）。
    """
    from wscan.checkpoint import CheckpointState

    state = CheckpointState.from_dict({
        "version": 5,
        "target_url": "https://h/",
        "checks": ["sqli"],
        "completed_units": [],  # legacy には何も無い
    })
    assert state.source_version == 5
    # resume 中に新規 mark
    state.mark_done("https://h/p?z=/admin", "q", 0, "sqli", is_url_param=True)
    assert state.is_done("https://h/p?z=/admin", "q", 0, "sqli", is_url_param=True) is True
    # distinct な末尾スラッシュ版は完了にならない（新規 mark は legacy 照合対象外）
    assert state.is_done("https://h/p?z=/admin/", "q", 0, "sqli", is_url_param=True) is False
