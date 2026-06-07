import types
import unittest

from wscan import context_mutator as cm
from wscan.scanners.base import BaseScanner


class ContextMutatorTests(unittest.TestCase):
    def test_marker_and_char_probe_are_plain_and_ordered(self):
        marker = cm.make_marker()

        self.assertRegex(marker, r"^wscanEVO\d+$")
        self.assertEqual(cm.make_char_probe(marker), marker + cm.SPECIAL_CHARS)

    def test_surviving_chars_ignores_html_entities(self):
        marker = "wscanEVO100"
        response = f"{marker}&lt;&gt;&quot;&#x27;`/();={{}}|&amp;$"

        survived = cm.surviving_chars(response, marker)

        self.assertNotIn("<", survived)
        self.assertNotIn(">", survived)
        self.assertNotIn('"', survived)
        self.assertNotIn("'", survived)
        self.assertNotIn("&", survived)
        self.assertIn("`", survived)
        self.assertIn("/", survived)
        self.assertIn("$", survived)

    def test_surviving_chars_collects_raw_chars_after_marker(self):
        marker = "wscanEVO101"
        response = f"<p>{marker}<>\"'</p>"

        self.assertEqual(cm.surviving_chars(response, marker), {"<", ">", "'", '"'})

    def test_detect_contexts(self):
        cases = [
            ("<p>wscanEVO1</p>", "html_text", ""),
            ('<input value="wscanEVO1">', "double_quoted_attr", "value"),
            ("<input value='wscanEVO1'>", "single_quoted_attr", "value"),
            ("<input value=wscanEVO1>", "unquoted_attr", "value"),
            ('<a href="wscanEVO1">x</a>', "url_attribute", "href"),
            ("<script>var x='wscanEVO1';</script>", "script_string_single", ""),
            ('<script>var x="wscanEVO1";</script>', "script_string_double", ""),
            ("<script>wscanEVO1</script>", "script_block", ""),
            ("<!-- wscanEVO1 -->", "html_comment", ""),
        ]

        for html, expected_context, expected_attr in cases:
            with self.subTest(expected_context=expected_context):
                detected = cm.detect_context(html, "wscanEVO1")
                self.assertEqual(detected["context"], expected_context)
                if expected_attr:
                    self.assertEqual(detected["attribute"], expected_attr)

    def test_mutate_xss_html_text_requires_tag_chars(self):
        context = {"context": "html_text"}

        payloads = cm.mutate(
            "xss",
            context=context,
            surviving=set("<>=()"),
            marker="wscanEVO1",
        )
        blocked = cm.mutate(
            "xss",
            context=context,
            surviving=set("=()"),
            marker="wscanEVO1",
        )

        self.assertIn("<svg onload=alert(1)>", payloads)
        self.assertIn("<img src=x onerror=alert(1)>", payloads)
        self.assertEqual(blocked, [])

    def test_mutate_xss_quoted_attrs_respects_delimiter(self):
        double_payloads = cm.mutate(
            "xss",
            context={"context": "double_quoted_attr"},
            surviving=set('"<>=( )'.replace(" ", "")),
            marker="wscanEVO1",
        )
        single_payloads = cm.mutate(
            "xss",
            context={"context": "single_quoted_attr"},
            surviving=set("'<>=( )".replace(" ", "")),
            marker="wscanEVO1",
        )
        blocked = cm.mutate(
            "xss",
            context={"context": "double_quoted_attr"},
            surviving=set("<>=()"),
            marker="wscanEVO1",
        )

        self.assertIn('"><svg onload=alert(1)>', double_payloads)
        self.assertIn('" onmouseover=alert(1) x="', double_payloads)
        self.assertIn("'><svg onload=alert(1)>", single_payloads)
        self.assertIn("' onmouseover=alert(1) x='", single_payloads)
        self.assertEqual(blocked, [])

    def test_mutate_xss_unquoted_url_and_script_contexts(self):
        self.assertIn(
            " onmouseover=alert(1) ",
            cm.mutate(
                "xss",
                context={"context": "unquoted_attr"},
                surviving=set("=()"),
                marker="wscanEVO1",
            ),
        )
        self.assertIn(
            "javascript:alert(1)",
            cm.mutate(
                "xss",
                context={"context": "url_attribute"},
                surviving=set("()"),
                marker="wscanEVO1",
            ),
        )
        self.assertIn(
            "';alert(1);//",
            cm.mutate(
                "xss",
                context={"context": "script_string_single"},
                surviving=set("';()/"),
                marker="wscanEVO1",
            ),
        )
        self.assertIn(
            '";alert(1);//',
            cm.mutate(
                "dom_xss",
                context={"context": "script_string_double"},
                surviving=set('";()/'),
                marker="wscanEVO1",
            ),
        )
        self.assertIn(
            "alert(1)//",
            cm.mutate(
                "xss",
                context={"context": "script_block"},
                surviving=set("()/"),
                marker="wscanEVO1",
            ),
        )

    def test_mutate_xss_does_not_generate_impossible_breakout(self):
        payloads = cm.mutate(
            "xss",
            context={"context": "script_string_single"},
            surviving=set(";()/"),
            marker="wscanEVO1",
        )

        self.assertEqual(payloads, [])

    def test_mutate_non_xss_payload_sets(self):
        marker = "wscanEVO999"

        self.assertIn("' OR '1'='1", cm.mutate("sqli", context={}, surviving=set(), marker=marker))
        self.assertIn("{{7*7}}", cm.mutate("ssti", context={}, surviving=set(), marker=marker))
        self.assertIn(f"; echo {marker}", cm.mutate("os", context={}, surviving=set(), marker=marker))
        self.assertIn('{"$regex":".*"}', cm.mutate("nosql", context={}, surviving=set(), marker=marker))
        self.assertIn("*)(|(uid=*))", cm.mutate("ldap", context={}, surviving=set(), marker=marker))
        self.assertIn(
            "..%2f..%2f..%2fetc%2fpasswd",
            cm.mutate("path_traversal", context={}, surviving=set(), marker=marker),
        )

    def test_mutate_unknown_empty_and_deduped(self):
        payloads = cm.mutate("ssti", context={}, surviving=set(), marker="wscanEVO1")

        self.assertEqual(len(payloads), len(set(payloads)))
        self.assertEqual(cm.mutate("unknown", context={}, surviving=set(), marker="wscanEVO1"), [])


class _FlagScanner(BaseScanner):
    CHECK_TYPE = "xss"

    async def scan_field(self, *args, **kwargs):
        return []


class BaseEvolutionHelperTests(unittest.IsolatedAsyncioTestCase):
    async def test_evolved_payloads_returns_empty_when_flag_disabled(self):
        engine = types.SimpleNamespace(
            enable_payload_evolution=False,
            browser=object(),
            monitor=None,
            payload_gen=object(),
            _finding_dedup=set(),
            max_payloads=0,
        )
        scanner = _FlagScanner(engine)

        self.assertEqual(
            await scanner.evolved_payloads("http://fixture.test", 0, "q", True),
            [],
        )


if __name__ == "__main__":
    unittest.main()
