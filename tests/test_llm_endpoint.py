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

    def test_apply_env_sets_values(self):
        e.apply_env(base_url="https://x/v1", api_key="k", model="tsuzumi-2")
        self.assertEqual(os.environ["WSCAN_LLM_BASE_URL"], "https://x/v1")
        self.assertEqual(os.environ["WSCAN_LLM_API_KEY"], "k")
        self.assertEqual(os.environ["WSCAN_LLM_MODEL"], "tsuzumi-2")

    def test_apply_env_ignores_blanks(self):
        os.environ["WSCAN_LLM_BASE_URL"] = "https://keep/v1"
        e.apply_env(base_url="", api_key=None)
        self.assertEqual(os.environ["WSCAN_LLM_BASE_URL"], "https://keep/v1")

    def test_set_base_url_sets_and_clears(self):
        e.set_base_url("https://x/v1")
        self.assertEqual(os.environ["WSCAN_LLM_BASE_URL"], "https://x/v1")
        # 空値は明示的にクリア（前スキャンの持ち越し防止）。
        e.set_base_url("")
        self.assertNotIn("WSCAN_LLM_BASE_URL", os.environ)
        self.assertEqual(e.chat_completions_url(), "https://api.openai.com/v1/chat/completions")

    def test_configure_endpoint_explicit_base_wins(self):
        e.configure_endpoint("openai_compatible", "https://tsuzumi/v1")
        self.assertEqual(os.environ["WSCAN_LLM_BASE_URL"], "https://tsuzumi/v1")

    def test_configure_endpoint_official_openai_clears_stale(self):
        # 前スキャンのカスタム値が残っている状態で公式 openai を明示選択 → クリア。
        os.environ["WSCAN_LLM_BASE_URL"] = "https://stale/v1"
        e.configure_endpoint("openai", "")
        self.assertNotIn("WSCAN_LLM_BASE_URL", os.environ)

    def test_configure_endpoint_compatible_blank_preserves_env(self):
        # openai_compatible で明示 base URL なし → env フォールバックを保持する
        # （WSCAN_LLM_BASE_URL だけで運用するケースを壊さない）。
        os.environ["WSCAN_LLM_BASE_URL"] = "https://tsuzumi.env/v1"
        e.configure_endpoint("openai_compatible", "")
        self.assertEqual(os.environ["WSCAN_LLM_BASE_URL"], "https://tsuzumi.env/v1")
        self.assertEqual(
            e.chat_completions_url(), "https://tsuzumi.env/v1/chat/completions"
        )

    def test_configure_endpoint_compatible_blank_preserves_openai_base_env(self):
        # OPENAI_BASE_URL だけで運用するケースも保持される。
        os.environ["OPENAI_BASE_URL"] = "https://compat.env/v1"
        e.configure_endpoint("openai_compatible", "")
        self.assertEqual(e.resolve_base_url(), "https://compat.env/v1")

    def test_configure_endpoint_other_provider_untouched(self):
        os.environ["WSCAN_LLM_BASE_URL"] = "https://keep/v1"
        e.configure_endpoint("claude", "")
        self.assertEqual(os.environ["WSCAN_LLM_BASE_URL"], "https://keep/v1")


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
