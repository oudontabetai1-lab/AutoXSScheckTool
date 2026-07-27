"""通常スキャンの CDP Fetch ヘッダ傍受を実 Chromium で検証する。

opt-in（WSCAN_E2E=1）かつ Playwright Chromium が利用できる場合だけ実行する。

    WSCAN_E2E=1 python -m pytest tests/test_browser_header_cdp_e2e.py -v
"""
from __future__ import annotations

import asyncio
import os
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from wscan.browser import BrowserManager


_TEST_AUTH = "Bearer cdp-e2e-test"


def _e2e_enabled() -> bool:
    return os.environ.get("WSCAN_E2E", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _chromium_available() -> bool:
    if not _e2e_enabled():
        return False
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return False
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False


class _FixtureServer(ThreadingHTTPServer):
    daemon_threads = True


def _start_server(handler):
    server = _FixtureServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _external_handler(records: list[tuple[str, str | None]]):
    class ExternalHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            records.append((self.path, self.headers.get("Authorization")))
            if self.path.startswith("/third-party.js"):
                body = b"window.thirdPartyLoaded = true;"
                content_type = "application/javascript"
            else:
                body = b"<html><body>external</body></html>"
                content_type = "text/html"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    return ExternalHandler


def _scoped_handler(
    records: list[tuple[str, str | None]],
    external_origin: str,
):
    html = (
        "<html><body><div id='out'>none</div>"
        f"<script src='{external_origin}/third-party.js'></script>"
        "<script>"
        "const stream = new EventSource('/sse');"
        "stream.onmessage = () => {"
        "document.getElementById('out').textContent = 'got:1';"
        "};"
        "</script></body></html>"
    ).encode()

    class ScopedHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            records.append((self.path, self.headers.get("Authorization")))
            if self.path.startswith("/sse"):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                try:
                    # 最初のイベント後も応答を閉じず、ストリームを流し続ける。
                    for index in range(50):
                        self.wfile.write(f"data: tick-{index}\n\n".encode())
                        self.wfile.flush()
                        time.sleep(0.2)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
            if self.path.startswith("/go"):
                self.send_response(302)
                self.send_header("Location", f"{external_origin}/landed")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            response_body = (
                b"<html><body>popup</body></html>"
                if self.path.startswith("/popup.html")
                else html
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)

        def log_message(self, *_args):
            pass

    return ScopedHandler


@unittest.skipUnless(_e2e_enabled(), "set WSCAN_E2E=1 to run the CDP browser test")
@unittest.skipUnless(
    _chromium_available(),
    "Playwright Chromium browser is not installed (run: playwright install chromium)",
)
class BrowserHeaderCDPEndToEndTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.scoped_records = []
        cls.external_records = []
        cls.external_server, cls.external_thread = _start_server(
            _external_handler(cls.external_records)
        )
        cls.external_origin = (
            f"http://127.0.0.1:{cls.external_server.server_address[1]}"
        )
        cls.scoped_server, cls.scoped_thread = _start_server(
            _scoped_handler(cls.scoped_records, cls.external_origin)
        )
        cls.scoped_origin = (
            f"http://127.0.0.1:{cls.scoped_server.server_address[1]}"
        )

    @classmethod
    def tearDownClass(cls):
        for server, thread in (
            (cls.scoped_server, cls.scoped_thread),
            (cls.external_server, cls.external_thread),
        ):
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    async def test_streaming_redirect_and_subresource_scope(self):
        browser = BrowserManager(
            headless=True,
            timeout=10,
            target_url=self.scoped_origin,
            extra_headers={"Authorization": _TEST_AUTH},
            header_scope_origins={self.scoped_origin},
        )
        try:
            await browser.init()
            self.assertEqual(browser._header_intercept_mode, "cdp")
            self.assertTrue(browser._header_auto_attach_active)

            # auto-attach 有効時も通常の worker 生成・終了が停止しないことを確認する。
            worker = await browser.create_worker()
            await worker.close()

            navigated = await browser.navigate(
                f"{self.scoped_origin}/index.html",
                retries=0,
            )
            self.assertTrue(navigated)

            async with browser._context.expect_page() as popup_info:
                await browser.page.evaluate("window.open('/popup.html')")
            popup = await popup_info.value
            await popup.wait_for_load_state("domcontentloaded")
            self.assertTrue(popup.url.endswith("/popup.html"))

            deadline = asyncio.get_running_loop().time() + 5
            streamed = False
            while asyncio.get_running_loop().time() < deadline:
                if await browser.page.text_content("#out") == "got:1":
                    streamed = True
                    break
                await asyncio.sleep(0.1)
            self.assertTrue(streamed, "SSE の最初のイベントがブラウザへ届かない")

            redirected = await browser.navigate(
                f"{self.scoped_origin}/go",
                wait_until="commit",
                retries=0,
            )
            self.assertTrue(redirected)
            await asyncio.sleep(0.3)
        finally:
            await browser.close()

        scoped_paths = [path for path, _auth in self.scoped_records]
        self.assertTrue(any(path.startswith("/index.html") for path in scoped_paths))
        self.assertTrue(any(path.startswith("/sse") for path in scoped_paths))
        self.assertTrue(any(path.startswith("/go") for path in scoped_paths))
        self.assertTrue(any(path.startswith("/popup.html") for path in scoped_paths))
        self.assertTrue(
            all(auth == _TEST_AUTH for _path, auth in self.scoped_records)
        )

        external_paths = [path for path, _auth in self.external_records]
        self.assertIn("/third-party.js", external_paths)
        self.assertIn("/landed", external_paths)
        self.assertTrue(
            all(auth is None for _path, auth in self.external_records),
            "スコープ外オリジンへ認証ヘッダが送信された",
        )
