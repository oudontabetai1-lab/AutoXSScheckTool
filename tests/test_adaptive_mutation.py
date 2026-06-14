"""AdaptivePayloadEngine.mutate_payload（LLM 版ペイロード変異）のゲーティング回帰テスト。

LLM プロバイダが ``none`` のとき、または LLM 不在のときは空 list を返し、
呼び出し側（BaseScanner.mutated_payloads）が LLM 非依存の変異へフォールバックできる
ことを保証する。実 API 呼び出しはここでは行わない（キー不要）。
"""
import unittest

from wscan.adaptive_payload import AdaptivePayloadEngine, _MUTATION_PROMPT, _parse_payload_lines


class _FakePG:
    """provider だけを持つ最小の PayloadGenerator スタブ。"""
    def __init__(self, provider="none"):
        self.provider = provider

    async def _check_llm_available(self):  # pragma: no cover - 呼ばれない想定
        return False


class MutatePayloadGatingTests(unittest.IsolatedAsyncioTestCase):
    async def test_provider_none_returns_empty(self):
        eng = AdaptivePayloadEngine(_FakePG(provider="none"))
        out = await eng.mutate_payload("sqli", ["1 AND 1=1"], field_name="rx", url="http://x")
        self.assertEqual(out, [])

    async def test_empty_seeds_returns_empty(self):
        eng = AdaptivePayloadEngine(_FakePG(provider="claude"))
        out = await eng.mutate_payload("sqli", [], field_name="rx", url="http://x")
        self.assertEqual(out, [])

    async def test_llm_unavailable_returns_empty(self):
        # provider はあるが _check_llm_available が False → 空。
        eng = AdaptivePayloadEngine(_FakePG(provider="claude"))
        out = await eng.mutate_payload("sqli", ["1 AND 1=1"])
        self.assertEqual(out, [])


class MutationPromptParseTests(unittest.TestCase):
    def test_prompt_includes_seeds_and_type(self):
        prompt = _MUTATION_PROMPT.format(
            check_type="sqli", field_name="rx", url="http://x",
            cheatsheet="(cheatsheet)", seeds="  1 AND 1=1",
        )
        self.assertIn("1 AND 1=1", prompt)
        self.assertIn("sqli", prompt)

    def test_parser_extracts_payloads_block(self):
        raw = "<analysis>x</analysis>\n<payloads>\n%2527\n1/**/AND/**/1=1\n</payloads>"
        out = _parse_payload_lines(raw, already_tried=["1 AND 1=1"])
        self.assertIn("%2527", out)
        self.assertIn("1/**/AND/**/1=1", out)


if __name__ == "__main__":
    unittest.main()
