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

    def test_same_line_duplicate_sinks_are_both_reported(self):
        # minify/bundle された 1 行に同じシンクが複数あっても両方残す。
        src = "eval(location.hash); eval(location.search);"
        ev = [r for r in ja.analyze_js(src) if r.sink == "eval"]
        self.assertEqual(len(ev), 2)
        self.assertTrue(all(r.tainted for r in ev))

    def test_multiline_eval_argument_is_tainted(self):
        # 引数が改行で続く eval も汚染ソースを取りこぼさない。
        src = "eval(\n  location.search\n);"
        ev = [r for r in ja.analyze_js(src) if r.sink == "eval"]
        self.assertTrue(ev and ev[0].tainted)
        self.assertEqual(ev[0].severity, "critical")

    def test_multiline_innerHTML_rhs_is_tainted(self):
        # 代入の右辺が次行にある innerHTML も汚染として扱う。
        src = "el.innerHTML =\n  location.hash;"
        inner = [r for r in ja.analyze_js(src) if r.sink == "innerHTML"]
        self.assertTrue(inner and inner[0].tainted)
        self.assertEqual(inner[0].severity, "high")

    def test_postMessage_event_data_is_source_only_with_handler(self):
        with_handler = (
            "window.addEventListener('message', function(e){\n"
            "  document.getElementById('o').innerHTML = e.data;\n"
            "});"
        )
        risks = ja.analyze_js(with_handler)
        inner = [r for r in risks if r.sink == "innerHTML"]
        self.assertTrue(inner and inner[0].tainted)


class TimerSinkTests(unittest.TestCase):
    def _timers(self, src):
        return [r for r in ja.analyze_js(src) if r.sink == "setTimeout/setInterval"]

    def test_tainted_nonliteral_setTimeout_is_detected(self):
        risks = self._timers("setTimeout(location.hash, 0);")
        self.assertEqual(len(risks), 1)
        self.assertTrue(risks[0].tainted)
        self.assertEqual(risks[0].severity, "high")

    def test_tainted_variable_setInterval_is_detected(self):
        risks = self._timers("var x = location.hash;\nsetInterval(x, 50);")
        self.assertTrue(risks and risks[0].tainted)

    def test_multiline_tainted_setTimeout_is_detected(self):
        # 引数が改行で続く setTimeout も汚染として high で報告する。
        risks = self._timers("setTimeout(\n  location.hash,\n  0\n);")
        self.assertEqual(len(risks), 1)
        self.assertTrue(risks[0].tainted)
        self.assertEqual(risks[0].severity, "high")

    def test_literal_string_setTimeout_is_low_not_tainted(self):
        risks = self._timers('setTimeout("alert(1)", 100);')
        self.assertEqual(len(risks), 1)
        self.assertFalse(risks[0].tainted)
        self.assertEqual(risks[0].severity, "low")

    def test_benign_function_reference_timer_is_ignored(self):
        # 関数参照の timer は危険でないため報告しない（誤検知防止）。
        self.assertEqual(self._timers("setTimeout(doStuff, 100);"), [])
        self.assertEqual(self._timers("setTimeout(() => render(), 100);"), [])


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

    def test_clean_sink_after_block_on_one_line_is_not_tainted(self):
        # 1 行コードで手前のブロック条件 `if (h){}` を文に取り込まず、リテラル
        # 代入のクリーンなシンクを汚染扱いにしない（誤検知回帰防止）。
        src = "const h=location.hash; if (h){} el.innerHTML='<b>safe</b>';"
        inner = [r for r in ja.analyze_js(src) if r.sink == "innerHTML"]
        self.assertEqual(len(inner), 1)
        self.assertFalse(inner[0].tainted)


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


class ScannerDedupTests(unittest.TestCase):
    def test_multiple_sinks_in_one_script_yield_distinct_dedup_keys(self):
        # 1スクリプト内の複数シンクが record_finding の重複排除で潰れないこと。
        # js_static は sink/line を field_name に含めて一意化する。
        from wscan.scanners.base import finding_dedup_key

        src = "eval(location.search);\ndocument.write(location.hash);"
        risks = ja.analyze_js(src)
        self.assertGreaterEqual(len(risks), 2)
        label = "(inline script #1)"
        keys = {
            finding_dedup_key(
                "js_static",
                "http://x.test/",
                f"{label} [{r.sink} L{r.line}]",
                "js_dangerous_sink",
            )
            for r in risks
        }
        self.assertEqual(len(keys), len(risks))


class LineReportingTests(unittest.TestCase):
    def test_line_numbers_reported(self):
        src = "// header\n// header2\neval(location.hash);"
        risks = ja.analyze_js(src)
        ev = [r for r in risks if r.sink == "eval"]
        self.assertEqual(ev[0].line, 3)


if __name__ == "__main__":
    unittest.main()
