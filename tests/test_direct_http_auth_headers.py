import unittest
from unittest.mock import patch

from wscan.scanners.cors import CORSScanner
from wscan.scanners.request_smuggling import RequestSmugglingScanner


class _Response:
    status_code = 200
    text = "OK"


class _CaptureClient:
    calls = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs, self.kwargs))
        return _Response()

    async def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs, self.kwargs))
        return _Response()


class _Engine:
    monitor = None
    payload_gen = object()
    browser = object()
    timeout = 3
    proxy = ""
    all_findings = []
    _finding_dedup = set()

    def auth_headers(self, extra=None, include_cookie=True):
        headers = {"Authorization": "Bearer test", "Cookie": "sid=abc"}
        headers.update(extra or {})
        return headers


class _ScopedEngine(_Engine):
    def headers_for_url(self, url):
        if url.startswith("http://fixture.test/"):
            return {"Authorization": "Bearer test"}
        return {}

    def auth_headers(self, extra=None, include_cookie=True, url=""):
        headers = self.headers_for_url(url)
        if include_cookie:
            headers["Cookie"] = "sid=abc"
        headers.update(extra or {})
        return headers


class DirectHttpAuthHeaderTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        _CaptureClient.calls = []

    async def test_cors_origin_probe_keeps_auth_headers(self):
        scanner = CORSScanner(_Engine())

        with patch("wscan.scanners.cors.httpx.AsyncClient", _CaptureClient):
            await scanner._get_with_origin("http://fixture.test/private", "https://evil.example")

        _method, _url, _request_kwargs, client_kwargs = _CaptureClient.calls[0]
        self.assertEqual(client_kwargs["headers"]["Authorization"], "Bearer test")
        self.assertEqual(client_kwargs["headers"]["Cookie"], "sid=abc")
        self.assertEqual(client_kwargs["headers"]["Origin"], "https://evil.example")

    async def test_request_smuggling_baseline_keeps_auth_headers(self):
        scanner = RequestSmugglingScanner(_Engine())

        with patch("wscan.scanners.request_smuggling.httpx.AsyncClient", _CaptureClient):
            await scanner._measure_normal("http://fixture.test/private", 3.0, None)

        _method, _url, request_kwargs, _client_kwargs = _CaptureClient.calls[0]
        self.assertEqual(request_kwargs["headers"]["Authorization"], "Bearer test")
        self.assertEqual(request_kwargs["headers"]["Cookie"], "sid=abc")

    async def test_cors_external_url_omits_custom_auth_and_keeps_probe_header(self):
        scanner = CORSScanner(_ScopedEngine())

        with patch("wscan.scanners.cors.httpx.AsyncClient", _CaptureClient):
            await scanner._get_with_origin(
                "https://external.example/private",
                "https://origin-probe.example",
            )

        _method, _url, _request_kwargs, client_kwargs = _CaptureClient.calls[0]
        self.assertNotIn("Authorization", client_kwargs["headers"])
        self.assertEqual(
            client_kwargs["headers"]["Origin"],
            "https://origin-probe.example",
        )


if __name__ == "__main__":
    unittest.main()
