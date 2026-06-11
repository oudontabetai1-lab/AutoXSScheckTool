import unittest

from wscan import js_analysis as ja


class TaintedFlowTests(unittest.TestCase):
    def test_location_hash_into_innerHTML_is_high_tainted(self):
        src = "var x = location.hash.slice(1);\n" "el.innerHTML = x;"
        risks = ja.analyze_js(src)
        inner = [r for r in risks if r.sink == "innerHTML"]
        self.assertEqual(len(inner), 1)
        self.assertTrue(inner[0].tainted)
        self.assertEqual(inner[0].severity, "high")

    def test_location_search_into_eval_is_critical(self):
        src = "eval(location.search);"
        risks = ja.analyze_js(src)
        ev = [r for r in risks if r.sink == "eval"]
        self.assertTrue(ev and ev[0].tainted)
        self.assertEqual(ev[0].severity, "critical")

    def test_taint_propagates_through_variables(self):
        src = (
            "var a = document.location.href;\n"
            "var b = a + '<br>';\n"
            "document.write(b);"
        )
        risks = ja.analyze_js(src)
        dw = [r for r in risks if r.sink == "document.write"]
        self.assertTrue(dw and dw[0].tainted)
        self.assertEqual(dw[0].severity, "critical")

    def test_postMessage_event_data_is_source_only_with_handler(self):
        with_handler = (
            "window.addEventListener('message', function(e){\n"
            "  document.getElementById('o').innerHTML = e.data;\n"
            "});"
        )
        risks = ja.analyze_js(with_handler)
        inner = [r for r in risks if r.sink == "innerHTML"]
        self.assertTrue(inner and inner[0].tainted)


class CleanSinkTests(unittest.TestCase):
    def test_static_innerHTML_is_not_tainted(self):
        src = "el.innerHTML = '<b>hello</b>';"
        risks = ja.analyze_js(src)
        inner = [r for r in risks if r.sink == "innerHTML"]
        self.assertEqual(len(inner), 1)
        self.assertFalse(inner[0].tainted)
        self.assertEqual(inner[0].severity, "medium")

    def test_equality_comparison_is_not_a_sink(self):
        # innerHTML == 'x' は代入ではないので検出しない。
        src = "if (el.innerHTML == 'x') doThing();"
        risks = ja.analyze_js(src)
        self.assertEqual([r for r in risks if r.sink == "innerHTML"], [])

    def test_empty_source(self):
        self.assertEqual(ja.analyze_js(""), [])
        self.assertEqual(ja.analyze_js("   \n  "), [])

    def test_property_assignment_does_not_taint_sibling_sink(self):
        # `el.innerHTML = ... + name` の左辺プロパティ名 innerHTML を「汚染変数」と
        # 誤認し、別の静的 innerHTML を tainted 扱いにしない（誤検知回帰防止）。
        src = (
            'a.innerHTML = "x" + location.hash;\n'
            'b.innerHTML = "<b>static</b>";'
        )
        risks = [r for r in ja.analyze_js(src) if r.sink == "innerHTML"]
        by_line = {r.line: r for r in risks}
        self.assertTrue(by_line[1].tainted)
        self.assertFalse(by_line[2].tainted)


class HtmlExtractionTests(unittest.TestCase):
    def test_extract_inline_scripts_skips_external(self):
        html = (
            "<html><head>"
            '<script src="/app.js"></script>'
            "<script>var x = location.hash; el.innerHTML = x;</script>"
            '<script type="application/json">{"a":1}</script>'
            "</head></html>"
        )
        scripts = ja.extract_inline_scripts(html)
        self.assertEqual(len(scripts), 1)
        self.assertIn("innerHTML", scripts[0])

    def test_is_javascript_response(self):
        self.assertTrue(ja.is_javascript_response("http://x.test/a.js"))
        self.assertTrue(
            ja.is_javascript_response("http://x.test/a", "application/javascript")
        )
        self.assertFalse(ja.is_javascript_response("http://x.test/a.css"))


class LineReportingTests(unittest.TestCase):
    def test_line_numbers_reported(self):
        src = "// header\n// header2\neval(location.hash);"
        risks = ja.analyze_js(src)
        ev = [r for r in risks if r.sink == "eval"]
        self.assertEqual(ev[0].line, 3)


if __name__ == "__main__":
    unittest.main()
