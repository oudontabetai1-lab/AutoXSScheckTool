"""0018: HTTP メソッド設定不備（危険メソッド告知 / XST / WebDAV）の単体テスト。

純粋判定関数はオフライン検証。スキャナは httpx.AsyncClient を fake へ差し替えて
実ネットワークなしで scan_page の分岐を検証する。
"""
import unittest
from unittest import mock

from wscan.scanners import SCANNERS
from wscan.scanners import http_methods as hm


class PureFunctionTests(unittest.TestCase):
    def test_parse_allow(self):
        self.assertEqual(hm.parse_allow_methods("GET, POST , put"), {"GET", "POST", "PUT"})
        self.assertEqual(hm.parse_allow_methods(""), set())

    def test_dangerous_and_webdav(self):
        allowed = {"GET", "POST", "PUT", "DELETE", "PROPFIND", "MKCOL"}
        self.assertEqual(hm.dangerous_methods(allowed), {"PUT", "DELETE"})
        self.assertEqual(hm.webdav_methods(allowed), {"PROPFIND", "MKCOL"})

    def test_trace_reflects(self):
        self.assertTrue(hm.trace_reflects(200, {"Content-Type": "message/http"},
                                          "TRACE / HTTP/1.1\nX-Xst-Probe: TOK", "TOK"))
        self.assertTrue(hm.trace_reflects(200, {}, "...X-Xst-Probe: TOK...", "TOK"))
        self.assertFalse(hm.trace_reflects(405, {}, "", "TOK"))
        self.assertFalse(hm.trace_reflects(200, {"Content-Type": "text/html"}, "<html>", "TOK"))


class _FakeResp:
    def __init__(self, status_code, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text


class _FakeClient:
    """httpx.AsyncClient の最小ダブル（request(method,url,headers=) を canned 応答へ）。"""

    def __init__(self, responses):
        self._responses = responses  # {method: _FakeResp}
        self.requested = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def request(self, method, url, headers=None):
        self.requested.append((method, url, headers or {}))
        resp = self._responses.get(method)
        if resp is None:
            raise RuntimeError("method not mocked")
        # TRACE の token 反射をシミュレート（probe token を本文へ差し込む）。
        if method == "TRACE" and getattr(resp, "_echo", False):
            tok = (headers or {}).get("X-Xst-Probe", "")
            resp = _FakeResp(resp.status_code, resp.headers, resp.text + tok)
        return resp


class _FakeEngine:
    def __init__(self):
        self.browser = None
        self.monitor = None
        self.payload_gen = None
        self.wave_errors = []
        self.proxy = ""
        self.timeout = 10


class ScannerTests(unittest.IsolatedAsyncioTestCase):
    def _scanner(self):
        engine = _FakeEngine()
        return engine, SCANNERS["http_methods"](engine)

    async def _run(self, responses):
        engine, scanner = self._scanner()
        recorded = []

        async def _rec(**kw):
            recorded.append(kw)
            return object()

        scanner.record_finding = _rec
        client = _FakeClient(responses)
        with mock.patch.object(hm.httpx, "AsyncClient", return_value=client):
            await scanner.scan_page("http://app.test/")
        return recorded

    async def test_dangerous_webdav_and_xst(self):
        trace = _FakeResp(200, {"Content-Type": "message/http"}, "TRACE / HTTP/1.1\n")
        trace._echo = True
        responses = {
            "OPTIONS": _FakeResp(200, {"allow": "GET, POST, PUT, DELETE, PROPFIND", "dav": "1,2"}),
            "TRACE": trace,
            "PROPFIND": _FakeResp(207, {}, "<multistatus/>"),
        }
        rec = await self._run(responses)
        types = {r["evidence_type"] for r in rec}
        self.assertIn("http_dangerous_methods", types)
        self.assertIn("http_webdav_enabled", types)
        self.assertIn("http_trace_xst", types)

    async def test_safe_origin_no_findings(self):
        responses = {
            "OPTIONS": _FakeResp(200, {"allow": "GET, POST, HEAD, OPTIONS"}),
            "TRACE": _FakeResp(405, {}, ""),
            "PROPFIND": _FakeResp(405, {}, ""),
        }
        rec = await self._run(responses)
        self.assertEqual(rec, [])

    async def test_probe_failure_is_graceful(self):
        engine, scanner = self._scanner()

        class _Boom:
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            async def request(self, *a, **k): raise RuntimeError("boom")

        with mock.patch.object(hm.httpx, "AsyncClient", return_value=_Boom()):
            out = await scanner.scan_page("http://app.test/")
        self.assertEqual(out, [])  # raise せず []


if __name__ == "__main__":
    unittest.main()
