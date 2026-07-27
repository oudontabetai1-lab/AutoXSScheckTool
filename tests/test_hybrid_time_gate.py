"""serve Hybrid の Phase 1 前に検査時間帯ゲートが効くことを検証する。"""
import asyncio
from datetime import datetime
from types import SimpleNamespace

import main


class _Monitor:
    def __init__(self):
        self.command_queue = asyncio.Queue()
        self.statuses = []
        self.api_scan_status = "scanning"

    async def emit_status(self, message, state="running"):
        self.statuses.append((message, state))
        if state == "done":
            self.api_scan_status = "done"
        elif state == "error":
            self.api_scan_status = "error"


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


def test_agent_mode_waits_outside_window_without_real_sleep():
    monitor = _Monitor()
    current = [datetime(2024, 1, 1, 9, 59, 59)]
    sleeps = []

    async def fake_sleep(delay):
        sleeps.append(delay)
        current[0] = datetime(2024, 1, 1, 10, 0)

    result = asyncio.run(
        main._wait_for_scan_window(
            monitor,
            ["Mon 10:00-12:00"],
            None,
            phase_label="Agent Browser スキャン",
            now_fn=lambda: current[0],
            sleep_fn=fake_sleep,
        )
    )

    assert result is True
    assert sleeps == [0.5]
    assert "Agent Browser スキャン" in monitor.statuses[0][0]
    assert [state for _message, state in monitor.statuses] == ["paused", "running"]


def test_hybrid_recon_is_cancelled_when_window_closes_without_real_sleep():
    monitor = _Monitor()
    current = [datetime(2024, 1, 1, 11, 59, 59)]
    operation_started = asyncio.Event()
    operation_stopped = []
    sleeps = []

    async def fake_sleep(delay):
        sleeps.append(delay)
        current[0] = datetime(2024, 1, 1, 12, 0)

    async def recon_operation():
        operation_started.set()
        try:
            await asyncio.Event().wait()
        finally:
            operation_stopped.append(True)

    async def run_test():
        result = await main._run_with_time_window_monitor(
            recon_operation,
            monitor,
            ["Mon 10:00-12:00"],
            None,
            phase_label="ハイブリッド Phase 1",
            now_fn=lambda: current[0],
            sleep_fn=fake_sleep,
        )
        assert operation_started.is_set()
        return result

    result, interrupted = asyncio.run(run_test())

    assert result is None
    assert interrupted is True
    assert sleeps == [0.5]
    assert operation_stopped == [True]
    assert monitor.statuses == [
        ("検査可能時間外へ移行したため ハイブリッド Phase 1 を停止しました。", "paused")
    ]
    assert monitor.api_scan_status == "scanning"


def test_agent_scan_is_cancelled_when_window_closes_without_real_sleep():
    monitor = _Monitor()
    current = [datetime(2024, 1, 1, 11, 59, 59)]
    operation_stopped = []

    async def fake_sleep(_delay):
        current[0] = datetime(2024, 1, 1, 12, 0)

    async def agent_operation():
        try:
            await asyncio.Event().wait()
        finally:
            operation_stopped.append(True)

    result, interrupted = asyncio.run(
        main._run_with_time_window_monitor(
            agent_operation,
            monitor,
            ["Mon 10:00-12:00"],
            None,
            phase_label="Agent Browser スキャン",
            terminal_on_interrupt=True,
            now_fn=lambda: current[0],
            sleep_fn=fake_sleep,
        )
    )

    assert result is None
    assert interrupted is True
    assert operation_stopped == [True]
    assert monitor.statuses == [
        (
            "検査時間帯を外れたため Agent Browser スキャン を中断しました。",
            "done",
        )
    ]
    assert monitor.api_scan_status == "done"


def test_hybrid_recon_retries_after_next_window_and_keeps_handoff():
    monitor = _Monitor()
    current = [datetime(2024, 1, 1, 11, 59, 59)]
    attempts = []
    expected = SimpleNamespace(
        discovered_urls=["https://fixture.test/discovered"],
        findings=[{"kind": "agent"}],
    )

    async def fake_sleep(_delay):
        if current[0] == datetime(2024, 1, 1, 11, 59, 59):
            current[0] = datetime(2024, 1, 1, 12, 0)
        elif current[0] == datetime(2024, 1, 1, 12, 0):
            current[0] = datetime(2024, 1, 8, 10, 0)
        else:
            await asyncio.sleep(0)

    async def recon_operation():
        attempts.append(len(attempts) + 1)
        if len(attempts) == 1:
            await asyncio.Event().wait()
        return expected

    handoff, continue_to_phase2 = asyncio.run(
        main._run_hybrid_recon_with_retries(
            recon_operation,
            monitor,
            ["Mon 10:00-12:00"],
            None,
            now_fn=lambda: current[0],
            sleep_fn=fake_sleep,
        )
    )

    assert attempts == [1, 2]
    assert handoff is expected
    assert continue_to_phase2 is True
    assert monitor.api_scan_status == "scanning"
    assert any("再試行 1/2" in message for message, _state in monitor.statuses)


def test_hybrid_recon_retry_limit_falls_back_without_seed():
    monitor = _Monitor()
    current = [datetime(2024, 1, 1, 11, 59, 59)]
    attempts = []

    async def fake_sleep(_delay):
        if current[0].hour in (10, 11):
            current[0] = datetime(2024, 1, 1, 12, 0)
        else:
            current[0] = datetime(2024, 1, 8, 10, 0)

    async def interrupted_recon():
        attempts.append(len(attempts) + 1)
        await asyncio.Event().wait()

    handoff, continue_to_phase2 = asyncio.run(
        main._run_hybrid_recon_with_retries(
            interrupted_recon,
            monitor,
            ["Mon 10:00-12:00"],
            None,
            now_fn=lambda: current[0],
            sleep_fn=fake_sleep,
        )
    )

    assert attempts == [1, 2, 3]
    assert handoff is None
    assert continue_to_phase2 is True
    assert monitor.api_scan_status == "scanning"
    assert monitor.statuses[-1][1] == "warning"
    assert "再試行上限 (2 回)" in monitor.statuses[-1][0]


def test_window_monitor_is_disabled_when_unconfigured():
    monitor = _Monitor()
    sleeps = []

    async def unexpected_sleep(delay):
        sleeps.append(delay)
        raise AssertionError("時間帯未設定では監視 sleep してはならない")

    async def completed_operation():
        return "completed"

    result, interrupted = asyncio.run(
        main._run_with_time_window_monitor(
            completed_operation,
            monitor,
            None,
            None,
            phase_label="ハイブリッド Phase 1",
            sleep_fn=unexpected_sleep,
        )
    )

    assert result == "completed"
    assert interrupted is False
    assert sleeps == []


def test_hybrid_recon_retry_wrapper_is_unchanged_when_unconfigured():
    monitor = _Monitor()
    attempts = []

    async def unexpected_sleep(_delay):
        raise AssertionError("時間帯未設定では sleep してはならない")

    async def completed_recon():
        attempts.append(True)
        return "handoff"

    handoff, continue_to_phase2 = asyncio.run(
        main._run_hybrid_recon_with_retries(
            completed_recon,
            monitor,
            None,
            None,
            sleep_fn=unexpected_sleep,
        )
    )

    assert handoff == "handoff"
    assert continue_to_phase2 is True
    assert attempts == [True]
    assert monitor.statuses == []
