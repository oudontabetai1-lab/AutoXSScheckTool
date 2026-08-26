"""per-finding 通知タスクの並行 drain 回帰（#107 Codex P2）。

検出/昇格通知は ensure_future で非ブロッキングに投げ、_drain_notifications が
gather する。await 直列化（低速 webhook で verify がブロック）を避けつつ取りこぼさない。
"""
import asyncio

from wscan.engine import ScanEngine


def test_drain_gathers_pending_tasks_and_clears():
    async def run():
        eng = ScanEngine.__new__(ScanEngine)  # __init__ を通さず method だけ検証
        done = []

        async def _work(i):
            await asyncio.sleep(0)
            done.append(i)

        eng._notify_tasks = [asyncio.ensure_future(_work(i)) for i in range(5)]
        await eng._drain_notifications()
        return done, eng._notify_tasks

    done, remaining = asyncio.run(run())
    assert sorted(done) == [0, 1, 2, 3, 4]
    assert remaining == []


def test_drain_swallows_exceptions():
    async def run():
        eng = ScanEngine.__new__(ScanEngine)

        async def _boom():
            raise RuntimeError("webhook down")

        eng._notify_tasks = [asyncio.ensure_future(_boom())]
        await eng._drain_notifications()  # return_exceptions=True → 例外を伝播しない
        return True

    assert asyncio.run(run()) is True


def test_drain_noop_without_tasks():
    async def run():
        eng = ScanEngine.__new__(ScanEngine)
        await eng._drain_notifications()  # _notify_tasks 未設定でも安全
        return True

    assert asyncio.run(run()) is True
