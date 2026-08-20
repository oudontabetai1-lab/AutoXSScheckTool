"""attack_planner の LLM 応答パースが完全 plan スキーマを要求することの回帰テスト。"""
import unittest

from wscan.attack_planner import AttackPlanner


class ParseLlmResponseTests(unittest.TestCase):
    def _planner(self):
        from wscan.payload_gen import PayloadGenerator
        return AttackPlanner(PayloadGenerator(provider="none"), ["xss", "sqli"])

    def test_partial_metadata_object_falls_back_to_real_plan(self):
        # Codex #92 r4: 前置きの page_purpose だけの metadata を plan と誤認しない。
        planner = self._planner()
        raw = ('Metadata: {"page_purpose":"login"}\n'
               '{"page_purpose":"login","fields":[{"name":"user","priority_checks":["xss"]}]}')
        plan = planner._parse_llm_response("http://t/login", raw)
        self.assertIsNotNone(plan)
        self.assertEqual([f.name for f in plan.fields], ["user"])

    def test_empty_fields_draft_falls_back_to_real_plan(self):
        # Codex #92 r5: {"fields":[]} 下書きを plan と誤認せず、非空の本物を採る。
        planner = self._planner()
        raw = ('{"page_purpose":"draft","fields":[]}\n'
               '{"page_purpose":"login","fields":[{"name":"user","priority_checks":["xss"]}]}')
        plan = planner._parse_llm_response("http://t/login", raw)
        self.assertIsNotNone(plan)
        self.assertEqual([f.name for f in plan.fields], ["user"])

    def test_string_field_entries_draft_falls_back_to_real_plan(self):
        # Codex #92 r6: {"fields":["username"]}（文字列要素）を plan 誤認せず AttributeError も
        # 出さない。本物の dict-field plan を採る。
        planner = self._planner()
        raw = ('{"fields":["username"]}\n'
               '{"page_purpose":"login","fields":[{"name":"user","priority_checks":["xss"]}]}')
        plan = planner._parse_llm_response("http://t/login", raw)
        self.assertIsNotNone(plan)
        self.assertEqual([f.name for f in plan.fields], ["user"])

    def test_mixed_field_entries_skips_non_dict(self):
        # 非 dict 要素が混ざっても例外にせず skip、dict 要素のみ採用。
        planner = self._planner()
        raw = '{"page_purpose":"x","fields":["junk", {"name":"user","priority_checks":["xss"]}]}'
        plan = planner._parse_llm_response("http://t/login", raw)
        self.assertIsNotNone(plan)
        self.assertEqual([f.name for f in plan.fields], ["user"])

    def test_malformed_collection_values_do_not_crash(self):
        # Codex #92 r7: null priority_checks / null custom_payloads / 非数値 form_index/risk_score
        # でも例外にせず parse し切る（malformed 値耐性）。
        planner = self._planner()
        raw = ('{"page_purpose":"x","fields":[{"name":"user","priority_checks":null,'
               '"custom_payloads":null,"form_index":"nope","risk_score":"high"}]}')
        plan = planner._parse_llm_response("http://t/login", raw)
        self.assertIsNotNone(plan)
        self.assertEqual([f.name for f in plan.fields], ["user"])
        self.assertEqual(plan.fields[0].form_index, 0)      # 非数値→default
        self.assertEqual(plan.fields[0].risk_score, 5)      # 非数値→default(範囲内)
        # priority_checks が null でも heuristic fallback で埋まる
        self.assertTrue(plan.fields[0].priority_checks)

    def test_object_without_fields_list_returns_none(self):
        planner = self._planner()
        raw = 'Note: {"page_purpose":"login"}'
        self.assertIsNone(planner._parse_llm_response("http://t/login", raw))


if __name__ == "__main__":
    unittest.main()
