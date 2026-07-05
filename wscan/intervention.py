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
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from . import time_window

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
        # 検査時間帯ゲート（WindowRule のリスト）。空なら常時許可。
        self._allowed_windows: list = []
        self._forbidden_windows: list = []
        self._gate_failclosed = False
        self._in_time_gate = False

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

    def abort_requested(self) -> bool:
        """attack 実行中に operator が停止(abort)を要求しているか。

        per-payload の即時停止判定に使う。``checkpoint()`` はページ/フィールド境界
        でしか呼ばれないため、1 フィールドの全 payload 掃射が終わるまで abort が
        反映されない。scanner は payload 投入直前に必ず ``log_payload_test`` を通す
        不変条件があるので、そこで本メソッドを見て AbortScan を送出すれば 1 payload
        単位で停止できる。``stop()`` 後（検証フェーズ）は ``_active=False`` になるため
        False を返し、後処理の再投入を中断しない。"""
        return self._active and self._abort

    def set_time_windows(self, allowed: Optional[list] = None, forbidden: Optional[list] = None) -> None:
        """検査を許可する/禁止する時間帯を設定する。

        ``allowed`` / ``forbidden`` は仕様文字列のリスト（``time_window.parse_windows``
        が解釈）。両方空なら時間帯ゲートは無効（常時許可）。
        """
        self._allowed_windows = time_window.parse_windows(allowed)
        self._forbidden_windows = time_window.parse_windows(forbidden)
        # 利用者が --allowed-hours / --forbidden-hours を指定したのに有効ルールが
        # 1 つも無い（全て誤記）場合は fail-closed にする。空＝「ゲート無し（常時許可）」
        # と区別できないと、誤記で安全ゲートが無効化され 24/7 で走ってしまうため。
        self._gate_failclosed = (
            (bool(allowed) and not self._allowed_windows)
            or (bool(forbidden) and not self._forbidden_windows)
        )

    def is_within_window(self, now: Optional[datetime] = None) -> bool:
        """現在が検査許可時間帯か。ゲート未設定なら常に True。"""
        if getattr(self, "_gate_failclosed", False):
            return False
        if not self._allowed_windows and not self._forbidden_windows:
            return True
        return time_window.is_allowed(
            now or datetime.now(), self._allowed_windows, self._forbidden_windows
        )

    async def _time_gate(self) -> None:
        """許可時間帯外なら、許可される時刻まで待機する（abort で中断可能）。"""
        if getattr(self, "_gate_failclosed", False):
            # 許可窓が全て不正 → 安全のため fail-closed で中断（無言で走らせない）。
            print(
                "[TimeWindow] 時間帯指定(--allowed-hours/--forbidden-hours)が全て不正です。"
                "安全のためスキャンを中断します（fail closed）。",
                flush=True,
            )
            if self._monitor:
                try:
                    await self._monitor.emit_status(
                        "許可時間帯の指定が不正 — 安全のため中断", "error"
                    )
                except Exception:
                    pass
            raise AbortScan("All --allowed-hours entries are invalid (fail closed)")
        if not self._allowed_windows and not self._forbidden_windows:
            return
        announced = False
        # NOTE: `_active` には依存しない。非 TTY/--no-monitor 実行では
        # `_key_reader()` が termios 失敗で `_active=False` にするため、これに
        # 依存すると時間帯ゲートが無言で無効化され、禁止時間帯でも攻撃が流れる。
        # ゲートは abort でのみ抜ける。
        while not self.is_within_window():
            if self._abort:
                raise AbortScan("Scan aborted by operator")
            self._in_time_gate = True
            wait = time_window.seconds_until_allowed(
                datetime.now(), self._allowed_windows, self._forbidden_windows
            )
            if wait == float("inf"):
                # 到達不能な設定（終日禁止など）。本機能は本番保護スロットルなので
                # 「素通りして攻撃を流す」のは最も危険。fail-closed としてスキャンを
                # 中断する（操作者が時間帯設定を見直せるよう明示メッセージを出す）。
                print(
                    "[TimeWindow] 設定された許可時間帯に到達できません"
                    "（終日禁止など）。安全のためスキャンを中断します。",
                    flush=True,
                )
                if self._monitor:
                    try:
                        await self._monitor.emit_status(
                            "検査可能時間帯に到達不能 — 安全のため中断", "error"
                        )
                    except Exception:
                        pass
                raise AbortScan("No reachable scan window — aborting (fail closed)")
            if not announced:
                print(
                    f"[TimeWindow] 検査可能時間外です。約 {int(wait)} 秒後に再開します…",
                    flush=True,
                )
                if self._monitor:
                    try:
                        await self._monitor.emit_status(
                            f"検査可能時間外 — 約 {int(wait)} 秒後に再開", "paused"
                        )
                    except Exception:
                        pass
                announced = True
            # 細かく刻んで待ち、abort/解除に素早く反応する
            await asyncio.sleep(min(5.0, max(0.5, wait)))
        self._in_time_gate = False

    async def wait_if_paused_or_abort(self) -> None:
        """crawl 等、skip の概念が無いフェーズ用の軽量チェックポイント。

        abort が要求されていれば AbortScan を送出し、pause 中なら解除まで待機する。
        skip_field / skip_page / 時間帯ゲートは扱わない（crawl は非注入の「訪問のみ」で
        フィールド単位の skip が意味を持たないため）。従来 crawl ループは
        ``checkpoint()`` を呼ばず、停止要求が attack 開始まで無視されていた。
        """
        if self._abort:
            raise AbortScan("Scan aborted by operator")
        if not self._pause_event.is_set():
            print("[Intervention] Paused — resume via dashboard or press 'p'…", flush=True)
            await self._pause_event.wait()
        if self._abort:
            raise AbortScan("Scan aborted by operator")

    async def checkpoint(self) -> None:
        """
        Yield control point inside a scan loop.

        - abort requested  → raise AbortScan
        - skip-page        → raise SkipPage  (clears flag)
        - skip-field       → raise SkipField (clears flag)
        - paused           → waits until resumed
        - outside scan window → waits until the next allowed window
        """
        if self._abort:
            raise AbortScan("Scan aborted by operator")
        # 時間帯ゲート: 許可時間外なら待機（abort で抜けられる）
        await self._time_gate()
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
            except asyncio.TimeoutError:
                continue
            except Exception:
                # キュー自体が壊れた等の致命時のみ終了する。
                break
            try:
                await self._handle_command(cmd, monitor)
            except Exception:
                # 単一コマンドの処理失敗（WS 送信エラー等）でリーダーを終わらせない。
                # ここで break すると以降の abort/pause を一切拾えなくなり、
                # 「ダッシュボードから停止できない」状態に陥る。
                continue

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
