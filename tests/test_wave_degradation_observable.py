"""payload 強化 wave（evolution/mutation）の失敗が *観測可能* であることの回帰テスト。

これらの wave は「加算的・例外保護で失敗時は従来挙動（空 list）」が設計上の不変条件。
ただし以前は ``except: return []`` で完全に握りつぶしており、検出力の低下
（blind/time 系の喪失など）に気づけなかった。修正後は失敗を ``engine.wave_errors``
へ記録しつつ、従来どおり空 list を返す（ループ挙動は不変）ことを保証する。
"""
import unittest

from wscan.scanners.base import BaseScanner


class _Scanner(BaseScanner):
    """scan_field だけ実装した最小の具象スキャナ。"""
    CHECK_TYPE = "sqli"

    async def scan_field(self, url, form_index, field, is_url_param=False):  # pragma: no cover
        return []


class _FakeEngine:
    """BaseScanner が参照する属性だけを持つ最小エンジン。"""
    def __init__(self):
        self.browser = None          # _evolution_probe を確実に失敗させる
        self.monitor = None
        self.payload_gen = None
        self.enable_payload_mutation = True
        self.enable_payload_evolution = True
        self.adaptive_enabled = False
        self.adaptive_engine = None
        self.max_payloads = 8


class WaveDegradationObservableTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.engine = _FakeEngine()
        self.scanner = _Scanner(self.engine)

    async def test_evolution_probe_failure_is_recorded(self):
        # browser=None なので _evolution_probe が失敗する。文脈適応は失われるが
        # 既定 payload へはフォールバックしうる（out は空とは限らない）。重要なのは
        # probe 失敗が wave_errors に観測可能な形で残ること。
        out = await self.scanner.evolved_payloads(
            "http://x/", 0, "rx", is_url_param=True
        )
        self.assertIsInstance(out, list)
        self.assertTrue(
            any("evolution_probe:sqli" in e for e in getattr(self.engine, "wave_errors", []))
        )

    async def test_evolution_mutate_failure_returns_empty_and_is_recorded(self):
        # context_mutator.mutate を失敗させて evolution wave 本体の例外経路を踏む。
        import wscan.context_mutator as cm

        original = cm.mutate

        def _boom(*a, **kw):
            raise RuntimeError("mutate broke")

        cm.mutate = _boom
        try:
            out = await self.scanner.evolved_payloads(
                "http://x/", 0, "rx", is_url_param=True
            )
        finally:
            cm.mutate = original
        self.assertEqual(out, [])  # 従来挙動（ループは壊さない）
        self.assertTrue(
            any("evolution:sqli" in e for e in getattr(self.engine, "wave_errors", []))
        )

    async def test_mutation_failure_returns_empty_and_is_recorded(self):
        import wscan.payload_mutator as pm

        original = pm.mutation_payloads

        def _boom(check_type, seeds):
            raise RuntimeError("mutator broke")

        pm.mutation_payloads = _boom
        try:
            out = await self.scanner.mutated_payloads("rx", "http://x/", ["1 AND 1=1"])
        finally:
            pm.mutation_payloads = original
        self.assertEqual(out, [])  # 従来挙動
        self.assertTrue(
            any("mutation:sqli" in e for e in getattr(self.engine, "wave_errors", []))
        )

    async def test_no_error_recorded_on_success(self):
        # mutation wave が正常なら wave_errors は作られない/空のまま。
        out = await self.scanner.mutated_payloads("rx", "http://x/", ["1 AND 1=1"])
        self.assertIsInstance(out, list)
        self.assertFalse(getattr(self.engine, "wave_errors", []))


if __name__ == "__main__":
    unittest.main()
