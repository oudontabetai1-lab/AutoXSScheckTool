"""F06: get_page_source が page.content() の無限ハングで停止しないことを検証する。

realistic_site 通し E2E が SQLi 再検証の page.content() 待ちで 900 秒 timeout していた。
待機を有界化したので、ハングしても "" を返して速やかに戻ることを確認する。
"""
import asyncio
import time
from unittest.mock import patch

import wscan.browser as browser_mod
from wscan.browser import BrowserManager


class _HangingPage:
    async def content(self):
        await asyncio.sleep(5)  # patched timeout より十分長い
        return "<html>late</html>"


class _FastPage:
    async def content(self):
        return "<html>ok</html>"


def _make_bm(page):
    bm = BrowserManager.__new__(BrowserManager)  # __init__ を通さず page だけ差す
    bm.page = page
    return bm


def test_get_page_source_returns_quickly_when_content_hangs():
    bm = _make_bm(_HangingPage())
    with patch.object(browser_mod, "_PAGE_CONTENT_TIMEOUT", 0.05):
        start = time.monotonic()
        result = asyncio.run(bm.get_page_source())
        elapsed = time.monotonic() - start
    assert result == ""          # 取得不能は空に合流（ハングしない）
    assert elapsed < 2.0         # 5秒待たず有界時間で戻る


def test_get_page_source_returns_content_when_available():
    bm = _make_bm(_FastPage())
    assert asyncio.run(bm.get_page_source()) == "<html>ok</html>"
