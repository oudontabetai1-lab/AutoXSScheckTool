"""ダッシュボードからの検査停止(abort)が即時かつ確実に効くことを守るテスト。

回帰対象:
  - abort はフィールド完了を待たず、payload 単位（log_payload_test）で即時反映される。
  - crawl フェーズ中も abort/pause が尊重される（wait_if_paused_or_abort）。
  - コマンド処理中の単発例外で監視リーダーが死なず、以降の abort を拾い続ける。
"""
import asyncio
import unittest

from wscan.intervention import ScanController, AbortScan


class AbortRequestedTest(unittest.TestCase):
    def test_only_when_active_and_abort(self):
        c = ScanController()
        # 未 start（_active=False）: abort を立てても per-payload では停止しない。
        c._abort = True
        self.assertFalse(c.abort_requested())
        # attack 実行中相当: active かつ abort → True。
        c._active = True
        self.assertTrue(c.abort_requested())
        # abort 解除中は False。
        c._abort = False
        self.assertFalse(c.abort_requested())

    def test_stop_disables_per_payload_abort(self):
        # 検証フェーズ（stop 後）は _active=False になり、abort 残留でも再投入を止めない。
        c = ScanController()
        c._active = True
        c._abort = True
        self.assertTrue(c.abort_requested())
        c.stop()
        self.assertFalse(c.abort_requested())


class _StubEngine:
    """log_payload_test が参照する最小の engine スタブ。"""
    def __init__(self, controller):
        self.controller = controller
        self.request_logger = None


class LogPayloadTestAbortTest(unittest.TestCase):
    def _make_scanner(self, controller):
        from wscan.scanners.base import BaseScanner

        class _S(BaseScanner):
            CHECK_TYPE = "xss"
            async def scan_field(self, *a, **k):  # abstract 充足
                return []

        s = _S.__new__(_S)
        s.engine = _StubEngine(controller)
        s.monitor = None
        return s

    def test_raises_abort_before_injection(self):
        c = ScanController()
        c._active = True
        c._abort = True
        s = self._make_scanner(c)
        with self.assertRaises(AbortScan):
            asyncio.run(s.log_payload_test("q", "<script>", "xss", "http://t/"))

    def test_no_abort_when_not_requested(self):
        c = ScanController()
        c._active = True
        s = self._make_scanner(c)
        # 例外を出さずに完了する（monitor/logger 未配線でも no-op）。
        asyncio.run(s.log_payload_test("q", "<script>", "xss", "http://t/"))


class WaitIfPausedOrAbortTest(unittest.TestCase):
    def test_abort_raises(self):
        c = ScanController()
        c._abort = True
        with self.assertRaises(AbortScan):
            asyncio.run(c.wait_if_paused_or_abort())

    def test_passes_when_idle(self):
        c = ScanController()
        asyncio.run(c.wait_if_paused_or_abort())  # 例外なし

    def test_abort_wins_after_pause(self):
        async def scenario():
            c = ScanController()
            c._pause_event.clear()  # paused
            waiter = asyncio.ensure_future(c.wait_if_paused_or_abort())
            await asyncio.sleep(0.05)
            self.assertFalse(waiter.done())  # まだ待機中
            # abort 要求 → pause 解除して再チェックで AbortScan。
            c._abort = True
            c._pause_event.set()
            with self.assertRaises(AbortScan):
                await waiter
        asyncio.run(scenario())


class _StubQueue:
    """command_queue の最小スタブ（順に返し、尽きたら永久待機）。"""
    def __init__(self, items):
        self._items = list(items)

    async def get(self):
        if self._items:
            return self._items.pop(0)
        await asyncio.Event().wait()  # 以降はタイムアウト経由で回る


class _StubMonitor:
    def __init__(self, items):
        self.command_queue = _StubQueue(items)


class MonitorReaderResilienceTest(unittest.TestCase):
    def test_reader_survives_command_handler_exception(self):
        """先行コマンドの処理が例外を投げても、後続の abort を確実に拾う。"""
        async def scenario():
            c = ScanController()
            c._active = True

            calls = {"n": 0}
            original = c._handle_command

            async def flaky(cmd, monitor=None):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise RuntimeError("WS send failed")  # 1回目は失敗
                await original(cmd, monitor)

            c._handle_command = flaky
            monitor = _StubMonitor(["pause", "abort"])
            reader = asyncio.ensure_future(c._monitor_reader(monitor))
            # abort が反映されるまで待つ（死んでいれば永遠に立たない）。
            for _ in range(50):
                if c._abort:
                    break
                await asyncio.sleep(0.02)
            c._active = False
            reader.cancel()
            try:
                await reader
            except asyncio.CancelledError:
                pass
            self.assertTrue(c._abort, "リーダーが1回目の例外で死に、abort を拾えていない")

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
