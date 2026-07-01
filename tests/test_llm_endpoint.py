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


class PayloadGeneratorCanonicalizeTests(unittest.TestCase):
    def setUp(self):
        for k in ("WSCAN_LLM_BASE_URL", "OPENAI_BASE_URL"):
            os.environ.pop(k, None)

    tearDown = setUp

    def test_openai_compatible_canonicalized_and_base_url_applied(self):
        from wscan.payload_gen import PayloadGenerator
        pg = PayloadGenerator(
            provider="openai_compatible",
            openai_model="tsuzumi-2",
            openai_base_url="https://tsuzumi.example/v1",
        )
        # 内部プロバイダは openai に正規化される。
        self.assertEqual(pg.provider, "openai")
        # ベース URL は env に集約され、エンドポイント解決へ反映される。
        self.assertEqual(
            e.chat_completions_url(), "https://tsuzumi.example/v1/chat/completions"
        )
        # openai_compatible のモデルは openai_model 経由で使われる。
        self.assertEqual(pg.get_model("payload"), "tsuzumi-2")


if __name__ == "__main__":
    unittest.main()
