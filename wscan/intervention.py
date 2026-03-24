"""
Intervention system for real-time scan control.

Allows the inspector to pause, resume, skip a field, skip a page, or abort
the scan entirely by pressing a single key while scanning is in progress.

  p  — pause / resume
  s  — skip current field
  n  — skip current page
  q  — abort scan (saves partial report)
"""
import asyncio
import sys
import threading
from typing import Optional


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

    Call ``start(loop)`` once to launch the background key-reader thread.
    Call ``await checkpoint()`` frequently inside scan loops; it will:
      - block (pause) until resumed when paused,
      - raise SkipField / SkipPage / AbortScan as appropriate.
    """

    def __init__(self) -> None:
        self._paused = False
        self._skip_field = False
        self._skip_page = False
        self._abort = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._pause_event = asyncio.Event()
        self._pause_event.set()  # initially not paused
        self._thread: Optional[threading.Thread] = None
        self._active = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        """Start the background keyboard-reader thread."""
        self._loop = loop
        self._active = True
        self._thread = threading.Thread(target=self._key_reader, daemon=True)
        self._thread.start()
        print(
            "\n[Intervention] Keys: p=pause/resume  s=skip field  "
            "n=skip page  q=abort\n",
            flush=True,
        )

    def stop(self) -> None:
        """Stop the key-reader thread."""
        self._active = False
        # Unblock any waiting checkpoint so the scan can exit cleanly.
        if self._loop and self._pause_event:
            self._loop.call_soon_threadsafe(self._pause_event.set)

    async def checkpoint(self) -> None:
        """
        Yield control point inside a scan loop.

        - If abort is requested → raise AbortScan
        - If skip-page is requested → raise SkipPage (clears flag)
        - If skip-field is requested → raise SkipField (clears flag)
        - If paused → waits until resumed
        """
        if self._abort:
            raise AbortScan("Scan aborted by operator")

        if self._skip_page:
            self._skip_page = False
            raise SkipPage("Page skipped by operator")

        if self._skip_field:
            self._skip_field = False
            raise SkipField("Field skipped by operator")

        # Block while paused
        if not self._pause_event.is_set():
            print("[Intervention] Paused — press 'p' to resume …", flush=True)
            await self._pause_event.wait()

        # Re-check after waking from pause
        if self._abort:
            raise AbortScan("Scan aborted by operator")
        if self._skip_page:
            self._skip_page = False
            raise SkipPage("Page skipped by operator")
        if self._skip_field:
            self._skip_field = False
            raise SkipField("Field skipped by operator")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _key_reader(self) -> None:
        """Background thread: reads single keypresses without Enter."""
        try:
            import tty
            import termios
            import select as sel

            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                while self._active:
                    # Non-blocking poll with 0.1 s timeout
                    r, _, _ = sel.select([sys.stdin], [], [], 0.1)
                    if not r:
                        continue
                    ch = sys.stdin.read(1)
                    if self._loop:
                        asyncio.run_coroutine_threadsafe(
                            self._handle_key(ch), self._loop
                        )
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        except Exception:
            # Non-TTY environment (CI, pipes, etc.) — silently disable
            self._active = False

    async def _handle_key(self, ch: str) -> None:
        """Handle a single keypress (runs on the main asyncio loop)."""
        ch = ch.lower()

        if ch == "p":
            if self._paused:
                self._paused = False
                self._pause_event.set()
                print("[Intervention] Resumed.", flush=True)
            else:
                self._paused = True
                self._pause_event.clear()
                print("[Intervention] Paused.", flush=True)

        elif ch == "s":
            self._skip_field = True
            # Unblock pause so the exception can be raised
            self._pause_event.set()
            print("[Intervention] Skip-field requested.", flush=True)

        elif ch == "n":
            self._skip_page = True
            self._pause_event.set()
            print("[Intervention] Skip-page requested.", flush=True)

        elif ch == "q":
            self._abort = True
            self._pause_event.set()
            print("[Intervention] Abort requested — finishing current action …", flush=True)
