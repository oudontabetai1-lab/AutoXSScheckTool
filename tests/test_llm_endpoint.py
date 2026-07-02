"""OpenAI 互換エンドポイント設定（tsuzumi2 等）のユニットテスト。"""
import os
import unittest

from wscan import llm_endpoint as e


class LlmEndpointTests(unittest.TestCase):
    def setUp(self):
        # 各テストは env をクリーンな状態から始める。
        for k in ("WSCAN_LLM_BASE_URL", "OPENAI_BASE_URL", "WSCAN_LLM_API_KEY",
                  "OPENAI_API_KEY", "WSCAN_LLM_MODEL"):
            os.environ.pop(k, None)

    tearDown = setUp

    def test_default_base_url_is_official(self):
        self.assertEqual(e.resolve_base_url(), "https://api.openai.com/v1")
        self.assertEqual(
            e.chat_completions_url(), "https://api.openai.com/v1/chat/completions"
        )
        self.assertFalse(e.is_custom_endpoint())

    def test_canonical_provider(self):
        self.assertEqual(e.canonical_provider("openai_compatible"), "openai")
        self.assertEqual(e.canonical_provider("openai"), "openai")
        self.assertEqual(e.canonical_provider("claude"), "claude")
        self.assertEqual(e.canonical_provider(None), "")

    def test_env_base_url_overrides_and_strips_slash(self):
        os.environ["WSCAN_LLM_BASE_URL"] = "https://tsuzumi.example/v1/"
        self.assertEqual(e.resolve_base_url(), "https://tsuzumi.example/v1")
        self.assertEqual(
            e.chat_completions_url(), "https://tsuzumi.example/v1/chat/completions"
        )
        self.assertTrue(e.is_custom_endpoint())

    def test_openai_base_url_env_fallback(self):
        # ecosystem 標準の OPENAI_BASE_URL もフォールバックとして尊重する。
        os.environ["OPENAI_BASE_URL"] = "https://compat.example/v1"
        self.assertEqual(e.resolve_base_url(), "https://compat.example/v1")

    def test_wscan_env_wins_over_openai_env(self):
        os.environ["OPENAI_BASE_URL"] = "https://a/v1"
        os.environ["WSCAN_LLM_BASE_URL"] = "https://b/v1"
        self.assertEqual(e.resolve_base_url(), "https://b/v1")

    def test_base_already_full_endpoint_is_respected(self):
        os.environ["WSCAN_LLM_BASE_URL"] = "https://host/v2/chat/completions"
        self.assertEqual(
            e.chat_completions_url(), "https://host/v2/chat/completions"
        )

    def test_api_key_resolution_prefers_wscan(self):
        os.environ["OPENAI_API_KEY"] = "openai-key"
        self.assertEqual(e.resolve_api_key(), "openai-key")
        self.assertTrue(e.api_key_present())
        os.environ["WSCAN_LLM_API_KEY"] = "wscan-key"
        self.assertEqual(e.resolve_api_key(), "wscan-key")

    def test_api_key_absent(self):
        self.assertIsNone(e.resolve_api_key())
        self.assertFalse(e.api_key_present())

    def test_official_openai_uses_only_openai_api_key(self):
        # 公式 openai は OPENAI_API_KEY のみ。互換用 WSCAN_LLM_API_KEY を流用しない。
        os.environ["WSCAN_LLM_API_KEY"] = "wscan-key"
        os.environ["OPENAI_API_KEY"] = "official-key"
        self.assertEqual(e.resolve_api_key("openai"), "official-key")
        # WSCAN だけがある状態で公式を選ぶと、公式キー無しとして扱う（流用しない）。
        del os.environ["OPENAI_API_KEY"]
        self.assertIsNone(e.resolve_api_key("openai"))
        self.assertFalse(e.api_key_present("openai"))

    def test_compatible_prefers_wscan_then_openai(self):
        os.environ["OPENAI_API_KEY"] = "official-key"
        self.assertEqual(e.resolve_api_key("openai_compatible"), "official-key")
        os.environ["WSCAN_LLM_API_KEY"] = "wscan-key"
        self.assertEqual(e.resolve_api_key("openai_compatible"), "wscan-key")

    def test_no_env_mutators_exposed(self):
        # env を書き換えるヘルパーは廃止済み（operator の env を壊さないため）。
        for name in ("apply_env", "set_base_url", "configure_endpoint"):
            self.assertFalse(hasattr(e, name), f"{name} should have been removed")

    def test_resolving_does_not_mutate_env(self):
        # 解決系は純粋（env を読むだけで書き換えない）。
        os.environ["WSCAN_LLM_BASE_URL"] = "https://tsuzumi.env/v1"
        e.resolve_instance_base("openai", "")       # 公式（env無視）
        e.resolve_base_url("https://x/v1")
        e.chat_completions_url("https://y/v1")
        # env は解決系呼び出し後も変わらない。
        self.assertEqual(os.environ["WSCAN_LLM_BASE_URL"], "https://tsuzumi.env/v1")

    def test_compatible_env_only_resolution(self):
        # openai_compatible で明示 base URL なし → WSCAN_LLM_BASE_URL を解決して使う。
        os.environ["WSCAN_LLM_BASE_URL"] = "https://tsuzumi.env/v1"
        self.assertEqual(e.resolve_instance_base("openai_compatible", ""), "https://tsuzumi.env/v1")
        # OPENAI_BASE_URL だけで運用するケースも解決される。
        del os.environ["WSCAN_LLM_BASE_URL"]
        os.environ["OPENAI_BASE_URL"] = "https://compat.env/v1"
        self.assertEqual(e.resolve_instance_base("openai_compatible", ""), "https://compat.env/v1")

    def test_resolve_instance_base_official_ignores_env(self):
        # 公式 openai は明示 base が無ければ env が設定済みでも公式既定を使う
        # （env 値を「明示指定」として公式リクエストに流用しない）。
        os.environ["WSCAN_LLM_BASE_URL"] = "https://compat/v1"
        self.assertEqual(e.resolve_instance_base("openai", ""), e.DEFAULT_OPENAI_BASE)
        # 一方 openai_compatible は env を解決して使う。
        self.assertEqual(e.resolve_instance_base("openai_compatible", ""), "https://compat/v1")
        # 明示 base はどのプロバイダでも優先。
        self.assertEqual(e.resolve_instance_base("openai", "https://x/v1"), "https://x/v1")


class PayloadGeneratorCanonicalizeTests(unittest.TestCase):
    def setUp(self):
        for k in ("WSCAN_LLM_BASE_URL", "OPENAI_BASE_URL"):
            os.environ.pop(k, None)

    tearDown = setUp

    def test_openai_compatible_canonicalized_and_base_url_snapshotted(self):
        from wscan.payload_gen import PayloadGenerator
        pg = PayloadGenerator(
            provider="openai_compatible",
            openai_model="tsuzumi-2",
            openai_base_url="https://tsuzumi.example/v1",
        )
        # 内部プロバイダは openai に正規化される。
        self.assertEqual(pg.provider, "openai")
        # ベース URL はインスタンスにスナップショットされ、呼び出しはこれを使う。
        self.assertEqual(pg.openai_base_url, "https://tsuzumi.example/v1")
        self.assertEqual(
            e.chat_completions_url(pg.openai_base_url),
            "https://tsuzumi.example/v1/chat/completions",
        )
        # openai_compatible のモデルは openai_model 経由で使われる。
        self.assertEqual(pg.get_model("payload"), "tsuzumi-2")

    def test_instances_are_isolated_from_env_mutation(self):
        # 長時間プロセスを模擬: scan A(互換, カスタム endpoint) の後に、別リクエストが
        # env を書き換えても、A のインスタンスの endpoint は変わらない。
        from wscan.payload_gen import PayloadGenerator
        pg_a = PayloadGenerator(provider="openai_compatible", openai_model="tsuzumi-2",
                                openai_base_url="https://tsuzumi.example/v1")
        # 別スキャン/リクエストが env を書き換え、公式 OpenAI を選ぶ
        pg_b = PayloadGenerator(provider="openai", openai_model="gpt-4o-mini",
                                openai_base_url="")
        os.environ["WSCAN_LLM_BASE_URL"] = "https://someone-else/v1"
        # A は自分の endpoint を保持（env 変更の影響を受けない）
        self.assertEqual(
            e.chat_completions_url(pg_a.openai_base_url),
            "https://tsuzumi.example/v1/chat/completions",
        )
        # B は公式 OpenAI（互換の持ち越しなし）
        self.assertEqual(pg_b.openai_base_url, e.DEFAULT_OPENAI_BASE)
        self.assertEqual(
            e.chat_completions_url(pg_b.openai_base_url),
            "https://api.openai.com/v1/chat/completions",
        )

    def test_openai_compatible_env_only_is_snapshotted(self):
        # openai_compatible を選び、明示 base URL は渡さず WSCAN_LLM_BASE_URL だけに
        # 頼るケース（/api/v1/scan や新フィールド未対応の旧 config 等）でも、
        # 構築時に env を解決してインスタンスに保持する。
        from wscan.payload_gen import PayloadGenerator
        os.environ["WSCAN_LLM_BASE_URL"] = "https://tsuzumi.env/v1"
        pg = PayloadGenerator(provider="openai_compatible", openai_model="tsuzumi-2",
                              openai_base_url="")
        self.assertEqual(pg.provider, "openai")
        self.assertEqual(pg.openai_base_url, "https://tsuzumi.env/v1")
        # 構築後に env が変わってもインスタンスは影響を受けない。
        os.environ["WSCAN_LLM_BASE_URL"] = "https://changed/v1"
        self.assertEqual(
            e.chat_completions_url(pg.openai_base_url),
            "https://tsuzumi.env/v1/chat/completions",
        )


if __name__ == "__main__":
    unittest.main()
