"""LLM 出力パーサ（D7）のフォールバック連鎖テスト。

2026-08-20 の4モデルプローブで抽出失敗した形（配列内 `]`／前置き／コードフェンス／
`<think>`）を回帰として固定する。壊れた入力は None（安全側）を守る。
"""
import unittest

from wscan.llm_output_parser import (
    extract_json_array_of_strings,
    extract_json_object,
    strip_code_fences,
    strip_reasoning,
)


class StripHelpersTests(unittest.TestCase):
    def test_strip_reasoning_closed(self):
        self.assertNotIn("secret", strip_reasoning("<think>secret plan</think>['a']"))

    def test_strip_reasoning_unclosed_drops_tail(self):
        out = strip_reasoning("ok <think>never closed reasoning")
        self.assertIn("ok", out)
        self.assertNotIn("never closed", out)

    def test_strip_fences_keeps_inner(self):
        self.assertIn('["a"]', strip_code_fences('```json\n["a"]\n```'))


class ArrayExtractionTests(unittest.TestCase):
    def test_plain_array(self):
        self.assertEqual(extract_json_array_of_strings('["a", "b"]'), ["a", "b"])

    def test_preamble_prose_before_array(self):
        # dolphin/lexi 形: 説明文 → 配列
        text = 'Here are the payloads you requested:\n["<script>", "<svg/onload=1>"]'
        self.assertEqual(
            extract_json_array_of_strings(text), ["<script>", "<svg/onload=1>"]
        )

    def test_bracket_inside_string_element_qwen_case(self):
        # WhiteRabbitNeo-Qwen 形: 要素文字列に `]` を含み、非貪欲 regex が途中終了していた
        text = 'Sure! ["a[0]=1", "arr[]=x", "b]c"] done'
        self.assertEqual(
            extract_json_array_of_strings(text), ["a[0]=1", "arr[]=x", "b]c"]
        )

    def test_code_fence_wrapped_llama_case(self):
        # WhiteRabbitNeo-Llama 形: コードフェンスで包む
        text = '```json\n["\' OR 1=1--", "admin\'--"]\n```'
        self.assertEqual(
            extract_json_array_of_strings(text), ["' OR 1=1--", "admin'--"]
        )

    def test_think_prefix_then_array(self):
        text = "<think>Let me craft bypasses</think>\n[\"payload1\", \"payload2\"]"
        self.assertEqual(
            extract_json_array_of_strings(text), ["payload1", "payload2"]
        )

    def test_array_nested_in_object_is_extracted(self):
        text = '{"payloads": ["x", "y"]}'
        self.assertEqual(extract_json_array_of_strings(text), ["x", "y"])

    def test_rejects_non_string_list(self):
        # 数値配列は payload list でない＝採らない（安全側）
        self.assertIsNone(extract_json_array_of_strings("[1, 2, 3]"))

    def test_think_inside_payload_preserved_with_prose_prefix(self):
        # Codex #92 指摘1: prose前置き付きで payload 文字列内に <think> を含む攻撃を
        # reasoning とみなして [" "] に破壊しない。
        text = 'Here are payloads:\n["<think onmouseover=alert(1)>x</think>"]'
        self.assertEqual(
            extract_json_array_of_strings(text),
            ["<think onmouseover=alert(1)>x</think>"],
        )

    def test_stray_prose_quote_before_array(self):
        # Codex #92 指摘2: prose 中の孤立クオートで有効な配列を取り逃さない。
        text = 'Use a literal " here:\n["a", "b"]'
        self.assertEqual(extract_json_array_of_strings(text), ["a", "b"])

    def test_ignores_draft_array_inside_think(self):
        # <think> 内の下書き配列は無視し、最終の配列を採る。
        text = '<think>["draft"]</think>\n["final1", "final2"]'
        self.assertEqual(
            extract_json_array_of_strings(text), ["final1", "final2"]
        )

    def test_single_line_fence_preserved(self):
        # Codex #92 r2 指摘2(P2): 1行フェンスの中身を空にしない。
        self.assertEqual(extract_json_array_of_strings('```json["a", "b"]```'), ["a", "b"])
        self.assertEqual(extract_json_array_of_strings('```["x"]```'), ["x"])

    def test_broken_returns_none(self):
        self.assertIsNone(extract_json_array_of_strings("no json here at all"))
        self.assertIsNone(extract_json_array_of_strings("[unterminated"))
        self.assertIsNone(extract_json_array_of_strings(""))


class ObjectExtractionTests(unittest.TestCase):
    def test_plain_object(self):
        self.assertEqual(extract_json_object('{"a": 1}'), {"a": 1})

    def test_think_and_prose_prefix(self):
        text = '<think>planning</think>\nHere is the plan:\n{"page_purpose": "login", "fields": []}'
        self.assertEqual(
            extract_json_object(text), {"page_purpose": "login", "fields": []}
        )

    def test_fenced_object(self):
        text = '```json\n{"k": "v"}\n```'
        self.assertEqual(extract_json_object(text), {"k": "v"})

    def test_brace_inside_string_value(self):
        text = 'result: {"rationale": "use ${IFS} and }{ tricks", "risk_score": 9}'
        self.assertEqual(
            extract_json_object(text),
            {"rationale": "use ${IFS} and }{ tricks", "risk_score": 9},
        )

    def test_trailing_prose_after_object(self):
        text = '{"a": {"b": 1}} and that is the answer.'
        self.assertEqual(extract_json_object(text), {"a": {"b": 1}})

    def test_stray_prose_quote_before_object(self):
        # 指摘2 の object 版: 前置き prose の孤立クオートに影響されない。
        text = 'Say " to me:\n{"page_purpose": "login"}'
        self.assertEqual(extract_json_object(text), {"page_purpose": "login"})

    def test_ignores_draft_object_inside_think(self):
        # Codex #92 r2 指摘1(P1): <think> 内の下書きJSONを拾わず、最終回答を採る。
        text = ('<think>{"page_purpose":"draft","fields":[]}</think> '
                '{"page_purpose":"login","fields":[{"name":"user"}]}')
        self.assertEqual(
            extract_json_object(text),
            {"page_purpose": "login", "fields": [{"name": "user"}]},
        )

    def test_broken_returns_none(self):
        self.assertIsNone(extract_json_object("no object"))
        self.assertIsNone(extract_json_object("{unterminated"))


class CallSiteDelegationTests(unittest.TestCase):
    def test_payload_gen_extract_delegates(self):
        from wscan.payload_gen import PayloadGenerator
        pg = PayloadGenerator(provider="none")
        text = 'Payloads:\n```json\n["a[]=1", "b]c"]\n```'
        self.assertEqual(pg._extract_json_list(text), ["a[]=1", "b]c"])


if __name__ == "__main__":
    unittest.main()
