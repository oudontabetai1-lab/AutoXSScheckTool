"""Unit tests for the SRIScanner.find_unprotected_externals helper."""
import types
import unittest

from wscan.scanners import SCANNERS
from wscan.scanners.base import PageDocumentUnavailable, _body_looks_like_html
from wscan.scanners.sri import find_unprotected_externals


PAGE = "https://app.example.com/dashboard"


class DocumentBodyTransientHtmlTests(unittest.IsolatedAsyncioTestCase):
    """_document_body(html_only=True, allow_non_2xx=False)＝SRI の取得経路（Codex #147）。"""

    def _sri(self, raw):
        engine = types.SimpleNamespace(browser=None, monitor=None, payload_gen=None,
                                       wave_errors=[])
        scanner = SCANNERS["sri"](engine)

        async def _raw(url):
            return raw
        scanner._raw_document_cached = _raw
        return scanner

    async def test_transient_html_body_is_audited_not_retried(self):
        # 5xx でもブラウザが描画する HTML（Content-Type: text/html）は監査対象として本文を返す。
        html = '<html><body><script src="https://cdn.test/x.js"></script></body></html>'
        scanner = self._sri({"status": 503, "url": PAGE,
                             "headers": {"Content-Type": "text/html"}, "body": html})
        out = await scanner._document_body(PAGE, allow_non_2xx=False, html_only=True)
        self.assertEqual(out, html)

    async def test_transient_non_html_body_still_retries(self):
        # 5xx の JSON error 本文は SRI 監査対象でないので resume へ回す（retry 維持）。
        scanner = self._sri({"status": 500, "url": PAGE,
                             "headers": {"Content-Type": "application/json"},
                             "body": '{"error":"boom"}'})
        with self.assertRaises(PageDocumentUnavailable):
            await scanner._document_body(PAGE, allow_non_2xx=False, html_only=True)

    async def test_transient_empty_body_retries(self):
        scanner = self._sri({"status": 502, "url": PAGE, "headers": {}, "body": ""})
        with self.assertRaises(PageDocumentUnavailable):
            await scanner._document_body(PAGE, allow_non_2xx=False, html_only=True)


class BodyLooksLikeHtmlTests(unittest.TestCase):
    def test_content_type_html(self):
        self.assertTrue(_body_looks_like_html("", {"Content-Type": "text/html; charset=utf-8"},
                                              is_2xx=False))

    def test_explicit_non_html_false(self):
        self.assertFalse(_body_looks_like_html("<html>", {"Content-Type": "application/json"},
                                               is_2xx=True))

    def test_missing_ctype_sniffs_on_non_2xx(self):
        self.assertTrue(_body_looks_like_html("<!DOCTYPE html><html>", {}, is_2xx=False))
        self.assertFalse(_body_looks_like_html("plain text", {}, is_2xx=False))
        self.assertTrue(_body_looks_like_html("no tags", {}, is_2xx=True))


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
