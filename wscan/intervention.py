"""
Intervention system for real-time scan control.

Two operating modes:
  1. Web mode (preferred): intervention commands arrive from the web dashboard
     via MonitorServer.command_queue.  The dashboard shows Pause / Skip Field /
     Skip Page / Abort buttons that send JSON messages over WebSocket.

  2. Keyboard fallback (no monitor / non-TTY ignored silently):
     p = pause / resume
     s = skip current field
     n = skip current page
     q = abort scan (saves partial report)

Call ``start(loop, monitor)`` once at scan start.
Call ``await checkpoint()`` frequently inside scan loops.
"""
import asyncio
import sys
import threading
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .monitor import MonitorServer


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------

class AbortScan(BaseException):
    """Raised to abort the entire scan; triggers partial-report save."""


class SkipField(Exception):
    """Raised to skip the current field and move to the next one."""


class SkipPage(Exception):
    """Raised to skip the current page and move to the next crawled URL."""


# ---------------------------------------------------------------------------
# ScanController
# ---------------------------------------------------------------------------

class ScanController:
    """
    Thread-safe scan controller.

    With a MonitorServer: reads commands from monitor.command_queue (web UI).
    Without a MonitorServer: reads single keypresses from stdin (keyboard fallback).

    Call ``start(loop, monitor)`` once, then ``await checkpoint()`` in scan loops.
    """

    def __init__(self) -> None:
        self._paused = False
        self._skip_field = False
        self._skip_page = False
        self._abort = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._pause_event: asyncio.Event = asyncio.Event()
        self._pause_event.set()          # initially not paused
        self._thread: Optional[threading.Thread] = None
        self._active = False
        self._monitor: "Optional[MonitorServer]" = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(
        self,
        loop: asyncio.AbstractEventLoop,
        monitor: "Optional[MonitorServer]" = None,
    ) -> None:
        """Start the intervention listener."""
        self._loop = loop
        self._active = True
        self._monitor = monitor

        if monitor is not None:
            # Web mode: consume monitor.command_queue in a background coroutine
            asyncio.run_coroutine_threadsafe(
                self._monitor_reader(monitor), loop
            )
            print(
                "\n[Intervention] Web controls active — "
                "use the dashboard to pause / skip / abort.\n",
                flush=True,
            )
        else:
            # Keyboard fallback
            self._thread = threading.Thread(target=self._key_reader, daemon=True)
            self._thread.start()
            print(
                "\n[Intervention] Keys: p=pause/resume  s=skip field  "
                "n=skip page  q=abort\n",
                flush=True,
            )

    def stop(self) -> None:
        """Stop the intervention listener."""
        self._active = False
        if self._loop and not self._pause_event.is_set():
            self._loop.call_soon_threadsafe(self._pause_event.set)

    async def checkpoint(self) -> None:
        """
        Yield control point inside a scan loop.

        - abort requested  → raise AbortScan
        - skip-page        → raise SkipPage  (clears flag)
        - skip-field       → raise SkipField (clears flag)
        - paused           → waits until resumed
        """
        if self._abort:
            raise AbortScan("Scan aborted by operator")
        if self._skip_page:
            self._skip_page = False
            raise SkipPage("Page skipped by operator")
        if self._skip_field:
            self._skip_field = False
            raise SkipField("Field skipped by operator")

        if not self._pause_event.is_set():
            print("[Intervention] Paused — resume via dashboard or press 'p'…", flush=True)
            await self._pause_event.wait()

        # Re-check after wake
        if self._abort:
            raise AbortScan("Scan aborted by operator")
        if self._skip_page:
            self._skip_page = False
            raise SkipPage("Page skipped by operator")
        if self._skip_field:
            self._skip_field = False
            raise SkipField("Field skipped by operator")

    # ------------------------------------------------------------------
    # Web mode: drain monitor.command_queue
    # ------------------------------------------------------------------

    async def _monitor_reader(self, monitor: "MonitorServer") -> None:
        """Background coroutine: read commands from the web dashboard."""
        while self._active:
            try:
                cmd = await asyncio.wait_for(monitor.command_queue.get(), timeout=0.2)
                await self._handle_command(cmd, monitor)
            except asyncio.TimeoutError:
                continue
            except Exception:
                break

    async def _handle_command(self, cmd: str, monitor: "Optional[MonitorServer]" = None) -> None:
        """Handle a single command string (web or keyboard)."""
        cmd = cmd.lower().strip()

        if cmd in ("pause", "p"):
            if self._paused:
                self._paused = False
                self._pause_event.set()
                print("[Intervention] Resumed.", flush=True)
                if monitor:
                    await monitor.emit_intervention_state(paused=False)
            else:
                self._paused = True
                self._pause_event.clear()
                print("[Intervention] Paused.", flush=True)
                if monitor:
                    await monitor.emit_intervention_state(paused=True)

        elif cmd in ("resume",):
            self._paused = False
            self._pause_event.set()
            print("[Intervention] Resumed.", flush=True)
            if monitor:
                await monitor.emit_intervention_state(paused=False)

        elif cmd in ("skip_field", "s"):
            self._skip_field = True
            self._pause_event.set()
            print("[Intervention] Skip-field requested.", flush=True)

        elif cmd in ("skip_page", "n"):
            self._skip_page = True
            self._pause_event.set()
            print("[Intervention] Skip-page requested.", flush=True)

        elif cmd in ("abort", "q"):
            self._abort = True
            self._pause_event.set()
            print("[Intervention] Abort requested — finishing current action…", flush=True)

    # ------------------------------------------------------------------
    # Keyboard fallback
    # ------------------------------------------------------------------

    def _key_reader(self) -> None:
        """Background thread: reads single keypresses without Enter."""
        try:
            import tty
            import termios
            import select as sel

            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                while self._active:
                    r, _, _ = sel.select([sys.stdin], [], [], 0.1)
                    if not r:
                        continue
                    ch = sys.stdin.read(1)
                    if self._loop:
                        asyncio.run_coroutine_threadsafe(
                            self._handle_command(ch), self._loop
                        )
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except Exception:
            self._active = False
