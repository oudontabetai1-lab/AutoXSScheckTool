import types
import unittest

from wscan.scanners.js_static import JsStaticScanner


class _FakeNetwork:
    """latest_for_url が指定 URL のときだけ本文付き pair を返す簡易ネットワーク。"""

    def __init__(self, bodies=None):
        self._bodies = bodies or {}

    def latest_for_url(self, url, match_query=True):
        body = self._bodies.get(url)
        if body is None:
            return None
        return {"request": {"url": url}, "response": {"url": url, "body": body}}


def _make_scanner(bodies=None):
    async def _screenshot_b64(label=""):
        return ""

    browser = types.SimpleNamespace(
        network=_FakeNetwork(bodies),
        dialog_screenshot_b64="",
        screenshot_b64=_screenshot_b64,
        page=None,
    )
    engine = types.SimpleNamespace(
        browser=browser,
        monitor=None,
        payload_gen=object(),
        _finding_dedup=set(),
        all_findings=[],
    )
    return JsStaticScanner(engine)


def _page(url, html):
    return types.SimpleNamespace(url=url, html=html)


class JsStaticScannerContextTests(unittest.IsolatedAsyncioTestCase):
    async def test_uses_crawled_page_html_not_current_tab(self):
        # ブラウザのタブ(page=None)に依存せず、渡された page.html を解析する。
        html = "<script>var x = location.hash; el.innerHTML = x;</script>"
        scanner = _make_scanner()
        findings = await scanner.scan_page_context(_page("http://t.test/a", html))
        self.assertTrue(findings)
        self.assertTrue(any(f.evidence_details.get("sink") == "innerHTML" for f in findings))

    async def test_multiple_sinks_in_one_inline_script_all_recorded(self):
        # 同一スクリプト内の複数シンクが重複排除で潰れないこと（dedup 回帰）。
        html = (
            "<script>eval(location.search);\n"
            "document.write(location.hash);</script>"
        )
        scanner = _make_scanner()
        findings = await scanner.scan_page_context(_page("http://t.test/b", html))
        sinks = {f.evidence_details.get("sink") for f in findings}
        self.assertIn("eval", sinks)
        self.assertIn("document.write", sinks)

    async def test_external_script_limited_to_page_referenced_srcs(self):
        # ページが参照する src の本文だけを解析する（別ページ資源を取り込まない）。
        page_url = "http://t.test/c"
        js_url = "http://t.test/app.js"
        html = f'<script src="/app.js"></script>'
        scanner = _make_scanner(bodies={js_url: "eval(location.hash);"})
        findings = await scanner.scan_page_context(_page(page_url, html))
        self.assertTrue(any(js_url in f.field_name for f in findings))

    async def test_no_findings_for_clean_page(self):
        scanner = _make_scanner()
        html = "<script>console.log('hello');</script>"
        findings = await scanner.scan_page_context(_page("http://t.test/d", html))
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
