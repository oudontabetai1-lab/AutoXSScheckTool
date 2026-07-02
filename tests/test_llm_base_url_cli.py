"""_effective_llm_base_url（CLI/config の provider 別ベース URL 解決）のテスト。

config に llm.openai_base_url があっても、公式 openai には流用しないことを検証。
"""
import types
import unittest

import main


class EffectiveLlmBaseUrlTests(unittest.TestCase):
    def setUp(self):
        self._orig = dict(main._CFG)

    def tearDown(self):
        main._CFG.clear()
        main._CFG.update(self._orig)

    @staticmethod
    def _args(llm, llm_base_url=None):
        return types.SimpleNamespace(llm=llm, llm_base_url=llm_base_url)

    def test_explicit_flag_wins_for_any_provider(self):
        self.assertEqual(
            main._effective_llm_base_url(self._args("openai", "https://x/v1")),
            "https://x/v1",
        )
        self.assertEqual(
            main._effective_llm_base_url(self._args("openai_compatible", "https://y/v1")),
            "https://y/v1",
        )

    def test_compatible_uses_config_when_no_flag(self):
        main._CFG["openai_base_url"] = "https://tsuzumi/v1"
        self.assertEqual(
            main._effective_llm_base_url(self._args("openai_compatible", None)),
            "https://tsuzumi/v1",
        )

    def test_official_ignores_config_when_no_flag(self):
        # config が互換用に設定されていても、--llm openai(公式) には流用しない。
        main._CFG["openai_base_url"] = "https://tsuzumi/v1"
        self.assertEqual(main._effective_llm_base_url(self._args("openai", None)), "")

    def test_official_honours_explicit_flag(self):
        main._CFG["openai_base_url"] = "https://tsuzumi/v1"
        self.assertEqual(
            main._effective_llm_base_url(self._args("openai", "https://explicit/v1")),
            "https://explicit/v1",
        )


if __name__ == "__main__":
    unittest.main()
