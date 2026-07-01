"""generate_fix が (text, is_ai) を返し、LLM 未使用時は is_ai=False になることの検証。

レポートで静的テンプレートを「AI 推奨修正」と偽って表示しないための土台。
"""
import asyncio
import types
import unittest

from wscan.remediation import generate_fix


def _finding(check_type="xss"):
    return types.SimpleNamespace(
        check_type=check_type,
        url="http://t/",
        field_name="q",
        payload="<x>",
        evidence="reflected",
    )


class GenerateFixFlagTests(unittest.TestCase):
    def test_no_llm_returns_static_with_is_ai_false(self):
        gen = types.SimpleNamespace(provider="none")
        text, is_ai = asyncio.run(generate_fix(_finding(), gen))
        self.assertFalse(is_ai)
        self.assertIn("XSS", text)  # 静的テンプレート本文

    def test_unknown_check_still_returns_tuple(self):
        gen = types.SimpleNamespace(provider="none")
        text, is_ai = asyncio.run(generate_fix(_finding("some_new_check"), gen))
        self.assertFalse(is_ai)
        self.assertIsInstance(text, str)
        self.assertTrue(text)


if __name__ == "__main__":
    unittest.main()
