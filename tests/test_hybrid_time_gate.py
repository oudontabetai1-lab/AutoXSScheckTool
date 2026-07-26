"""serve Hybrid の Phase 1 前に検査時間帯ゲートが効くことを検証する。"""
import asyncio
from datetime import datetime

import main


class _Monitor:
    def __init__(self):
        self.command_queue = asyncio.Queue()
        self.statuses = []

    async def emit_status(self, message, state="running"):
        self.statuses.append((message, state))


def test_hybrid_recon_window_allows_immediately_inside_window():
    wait = main._hybrid_recon_wait_seconds(
        datetime(2024, 1, 1, 11, 0),
        ["Mon 10:00-12:00"],
        None,
    )

    assert wait == 0.0


def test_hybrid_recon_window_is_disabled_when_unconfigured():
    assert (
        main._hybrid_recon_wait_seconds(
            datetime(2024, 1, 1, 11, 0), None, None
        )
        is None
    )


def test_hybrid_recon_inside_window_does_not_sleep():
    monitor = _Monitor()

    async def unexpected_sleep(_delay):
        raise AssertionError("許可時間内では sleep してはならない")

    result = asyncio.run(
        main._wait_for_hybrid_recon_window(
            monitor,
            ["Mon 10:00-12:00"],
            None,
            now_fn=lambda: datetime(2024, 1, 1, 11, 0),
            sleep_fn=unexpected_sleep,
        )
    )

    assert result is True
    assert monitor.statuses == []


def test_hybrid_recon_waits_outside_window_without_real_sleep():
    monitor = _Monitor()
    current = [datetime(2024, 1, 1, 9, 59, 59)]
    sleeps = []

    async def fake_sleep(delay):
        sleeps.append(delay)
        current[0] = datetime(2024, 1, 1, 10, 0)

    result = asyncio.run(
        main._wait_for_hybrid_recon_window(
            monitor,
            ["Mon 10:00-12:00"],
            None,
            now_fn=lambda: current[0],
            sleep_fn=fake_sleep,
        )
    )

    assert result is True
    assert sleeps == [0.5]
    assert [state for _message, state in monitor.statuses] == ["paused", "running"]


def test_hybrid_recon_unconfigured_does_not_sleep():
    monitor = _Monitor()

    async def unexpected_sleep(_delay):
        raise AssertionError("時間帯未設定では sleep してはならない")

    result = asyncio.run(
        main._wait_for_hybrid_recon_window(
            monitor,
            None,
            None,
            sleep_fn=unexpected_sleep,
        )
    )

    assert result is True
    assert monitor.statuses == []


def test_hybrid_recon_wait_can_be_aborted_from_monitor_command_queue():
    monitor = _Monitor()
    sleeps = []

    async def request_abort_while_waiting(delay):
        sleeps.append(delay)
        monitor.command_queue.put_nowait("abort")

    result = asyncio.run(
        main._wait_for_hybrid_recon_window(
            monitor,
            ["Mon 10:00-12:00"],
            None,
            now_fn=lambda: datetime(2024, 1, 1, 9, 0),
            sleep_fn=request_abort_while_waiting,
        )
    )

    assert result is False
    assert sleeps == [0.5]
    assert monitor.statuses[0][1] == "paused"
    assert monitor.statuses[-1][1] == "done"
