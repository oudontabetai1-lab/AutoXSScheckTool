"""F06: get_page_source が page.content() の無限ハングで停止しないことを検証する。

realistic_site 通し E2E が SQLi 再検証の page.content() 待ちで 900 秒 timeout していた。
待機を asyncio.wait_for で有界化したので、(1) ハングしても "" を返して速やかに戻る、
(2) 呼び出し側 cancel（scan 全体の SCAN_TIMEOUT_S 等）は内側 task を drain した上で
握りつぶさず伝播する、ことを確認する。
"""
import asyncio
import time
from unittest.mock import patch

import wscan.browser as browser_mod
from wscan.browser import BrowserManager


class _HangingPage:
    def __init__(self):
        self.cancelled = False

    async def content(self):
        try:
            await asyncio.sleep(5)  # patched timeout より十分長い
            return "<html>late</html>"
        except asyncio.CancelledError:
            self.cancelled = True
            raise


class _FastPage:
    async def content(self):
        return "<html>ok</html>"


def _make_bm(page):
    bm = BrowserManager.__new__(BrowserManager)  # __init__ を通さず page だけ差す
    bm.page = page
    return bm


def test_get_page_source_returns_quickly_when_content_hangs():
    page = _HangingPage()
    bm = _make_bm(page)
    with patch.object(browser_mod, "_PAGE_CONTENT_TIMEOUT", 0.05):
        start = time.monotonic()
        result = asyncio.run(bm.get_page_source())
        elapsed = time.monotonic() - start
    assert result == ""          # 取得不能は空に合流（ハングしない）
    assert elapsed < 2.0         # 5秒待たず有界時間で戻る
    assert page.cancelled        # 内側 task は cancel＋drain 済み（orphan を残さない）


def test_get_page_source_returns_content_when_available():
    bm = _make_bm(_FastPage())
    assert asyncio.run(bm.get_page_source()) == "<html>ok</html>"


def test_caller_cancel_propagates_after_inner_drained():
    # scan 全体の cancel が来た場合、内側 page.content の cleanup を drain してから
    # CancelledError を伝播する（"" を返して cancel 済み scan を継続しない）。
    finished = {"v": False}

    class _SlowCleanupPage:
        async def content(self):
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                await asyncio.sleep(0.05)   # cleanup（drain されるべき）
                finished["v"] = True
                raise

    async def run():
        inner = asyncio.ensure_future(browser_mod._bounded_page_content(_SlowCleanupPage()))
        await asyncio.sleep(0.05)  # wait_for の await に入らせる
        inner.cancel()
        try:
            await inner
            return "no-raise"
        except asyncio.CancelledError:
            return "cancelled"

    assert asyncio.run(run()) == "cancelled"  # cancellation は握りつぶさず伝播
    assert finished["v"]                       # 内側 task の cleanup 完了後に伝播した
