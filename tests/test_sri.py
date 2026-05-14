"""Unit tests for the SRIScanner.find_unprotected_externals helper."""
import unittest

from wscan.scanners.sri import find_unprotected_externals


PAGE = "https://app.example.com/dashboard"


class SRIDetectionTests(unittest.TestCase):
    def test_third_party_script_without_integrity_is_flagged(self):
        html = (
            '<html><head>'
            '<script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>'
            '</head></html>'
        )
        hits = find_unprotected_externals(html, PAGE)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["tag"], "script")
        self.assertEqual(hits[0]["host"], "cdn.jsdelivr.net")
        self.assertTrue(hits[0]["is_known_cdn"])

    def test_third_party_script_with_integrity_is_not_flagged(self):
        html = (
            '<script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js" '
            'integrity="sha384-abcdef" crossorigin="anonymous"></script>'
        )
        self.assertEqual(find_unprotected_externals(html, PAGE), [])

    def test_same_origin_script_is_not_flagged(self):
        html = '<script src="/static/app.js"></script>'
        self.assertEqual(find_unprotected_externals(html, PAGE), [])

    def test_same_origin_absolute_script_is_not_flagged(self):
        html = '<script src="https://app.example.com/static/app.js"></script>'
        self.assertEqual(find_unprotected_externals(html, PAGE), [])

    def test_inline_script_is_not_flagged(self):
        html = "<script>console.log('hi');</script>"
        self.assertEqual(find_unprotected_externals(html, PAGE), [])

    def test_third_party_stylesheet_without_integrity_is_flagged(self):
        html = (
            '<link rel="stylesheet" '
            'href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">'
        )
        hits = find_unprotected_externals(html, PAGE)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["tag"], "link")
        self.assertEqual(hits[0]["host"], "maxcdn.bootstrapcdn.com")

    def test_link_rel_icon_is_ignored(self):
        html = '<link rel="icon" href="https://cdn.example.org/favicon.ico">'
        self.assertEqual(find_unprotected_externals(html, PAGE), [])

    def test_link_preload_script_without_integrity_is_flagged(self):
        html = (
            '<link rel="preload" as="script" '
            'href="https://cdn.jsdelivr.net/foo.js">'
        )
        hits = find_unprotected_externals(html, PAGE)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["tag"], "link")

    def test_unknown_third_party_host_flagged_at_low_severity(self):
        html = '<script src="https://random.example.org/widget.js"></script>'
        hits = find_unprotected_externals(html, PAGE)
        self.assertEqual(len(hits), 1)
        self.assertFalse(hits[0]["is_known_cdn"])

    def test_duplicate_scripts_reported_once(self):
        html = (
            '<script src="https://cdnjs.cloudflare.com/ajax/libs/lib/1/lib.js"></script>'
            '<script src="https://cdnjs.cloudflare.com/ajax/libs/lib/1/lib.js"></script>'
        )
        hits = find_unprotected_externals(html, PAGE)
        self.assertEqual(len(hits), 1)

    def test_protocol_relative_third_party_script_is_flagged(self):
        html = '<script src="//unpkg.com/react@18/umd/react.production.min.js"></script>'
        hits = find_unprotected_externals(html, PAGE)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["host"], "unpkg.com")

    def test_empty_html_returns_no_results(self):
        self.assertEqual(find_unprotected_externals("", PAGE), [])
        self.assertEqual(find_unprotected_externals(None, PAGE), [])


if __name__ == "__main__":
    unittest.main()
