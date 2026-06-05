import unittest

from wscan import equivalence_probe as eqp


class MakeMarkerTests(unittest.TestCase):
    def test_marker_is_concatenation_and_quote_free(self):
        left, right, marker = eqp.make_marker()
        self.assertEqual(marker, left + right)
        for ch in ("'", '"', " ", "|", "+"):
            self.assertNotIn(ch, marker)

    def test_markers_are_random(self):
        self.assertNotEqual(eqp.make_marker()[2], eqp.make_marker()[2])


class SqlProbeSetTests(unittest.TestCase):
    def setUp(self):
        # Fixed marker so we can build deterministic fake responses.
        self.marker = ("AA", "BB", "AABB")
        self.ps = eqp.sql_probe_set(self.marker)

    def test_contains_expected_variants(self):
        names = {p.name for p in self.ps.probes}
        self.assertIn("baseline", names)
        self.assertIn("adjacent", names)
        self.assertIn("pipe", names)
        self.assertIn("plus", names)
        self.assertIn("broken", names)
        self.assertEqual(self.ps.marker, "AABB")

    def test_injectable_when_equivalent_collapses(self):
        # adjacent variant collapsed to the marker (quote interpreted as syntax),
        # baseline reflects the plain marker, broken variant errors out.
        responses = {
            "baseline": "<p>result for AABB</p>",
            "adjacent": "<p>result for AABB</p>",      # collapsed
            "pipe": "<p>result for AA'||'BB</p>",       # reflected raw (Oracle-only)
            "plus": "<p>result for AA'+'BB</p>",
            "concat": "<p>result for AA'+CONCAT('BB')-- -</p>",
            "broken": "SQL syntax error near ''BB'",
        }
        verdict = eqp.evaluate(self.ps, responses)
        self.assertTrue(verdict.injectable)
        self.assertEqual(verdict.matched_probe, "adjacent")
        self.assertEqual(verdict.matched_dialect, "ansi")
        self.assertGreaterEqual(verdict.confidence, 0.85)

    def test_not_injectable_when_only_reflected(self):
        # Every variant is reflected verbatim — no collapse, just echoed input.
        responses = {
            "baseline": "echo: AABB",
            "adjacent": "echo: AA' 'BB",
            "pipe": "echo: AA'||'BB",
            "plus": "echo: AA'+'BB",
            "concat": "echo: AA'+CONCAT('BB')-- -",
            "broken": "echo: AA'BB",
        }
        verdict = eqp.evaluate(self.ps, responses)
        self.assertFalse(verdict.injectable)
        self.assertEqual(verdict.confidence, 0.0)

    def test_not_injectable_when_no_reflection(self):
        responses = {"baseline": "generic page with no marker"}
        verdict = eqp.evaluate(self.ps, responses)
        self.assertFalse(verdict.injectable)
        self.assertIn("N/A", verdict.rationale)

    def test_confidence_lowered_when_broken_also_collapses(self):
        # If even the broken (mismatched-quote) variant collapses to the marker,
        # the result is ambiguous → lower confidence.
        responses = {
            "baseline": "AABB",
            "adjacent": "AABB",
            "pipe": "AA'||'BB",
            "plus": "AA'+'BB",
            "concat": "AA'+CONCAT('BB')-- -",
            "broken": "AABB",
        }
        verdict = eqp.evaluate(self.ps, responses)
        self.assertTrue(verdict.injectable)
        self.assertLess(verdict.confidence, 0.85)


class ContextProbeSetTests(unittest.TestCase):
    def test_html_attr_probe_set(self):
        ps = eqp.html_attr_probe_set(("AA", "BB", "AABB"))
        self.assertEqual(ps.context, "html_attr")
        responses = {
            "baseline": 'value="AABB"',
            "attr_break": 'value="AABB"',   # collapsed → quote broke the attribute
            "attr_break_sq": "value='AA' 'BB'",
            "broken": 'value="AA"BB"',
        }
        verdict = eqp.evaluate(ps, responses)
        self.assertTrue(verdict.injectable)
        self.assertEqual(verdict.matched_probe, "attr_break")

    def test_js_string_probe_set(self):
        ps = eqp.js_string_probe_set(("AA", "BB", "AABB"))
        self.assertEqual(ps.context, "js_string")
        responses = {
            "baseline": "var x='AABB'",
            "js_plus_sq": "var x='AABB'",   # 'AA'+'BB' concatenated by JS engine
            "js_plus_dq": 'var x="AA"+"BB"',
            "broken": "var x='AA'BB'",
        }
        verdict = eqp.evaluate(ps, responses)
        self.assertTrue(verdict.injectable)


if __name__ == "__main__":
    unittest.main()
