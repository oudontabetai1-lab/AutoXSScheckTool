"""
HeaderManager — central source of HTTP headers (Authorization, X-API-Key, etc.)
used by both the Playwright browser context and httpx clients across the engine.

Why this exists:
  * Modern systems authenticate with bearer tokens or signed headers, not just cookies.
  * Tokens often rotate every few minutes; long-running scans previously failed once
    the initial token expired with no way to refresh.
  * The same headers must reach the Playwright crawl AND every direct httpx call
    (scanners, planner, verifier). A single source of truth prevents drift.

Refresh modes:
  * ``refresh_cmd``  : shell command whose stdout is parsed as ``Name: Value`` lines
                      (also accepts JSON object). Re-executed every ``refresh_interval``
                      seconds while the scan is running.
  * ``refresh_interval`` only: useful with a static command-less manager when the
                      caller updates ``headers`` externally; no-op here.

Concurrency safety:
  * ``current()`` returns a *copy* — callers may mutate freely.
  * Updates take ``self._lock`` so concurrent scanners never observe a partial set.
"""
from __future__ import annotations

import asyncio
import json
import os
import shlex
import time
from pathlib import Path
from typing import Awaitable, Callable, Optional


def parse_header_lines(text: str) -> dict[str, str]:
    """Parse ``Name: Value`` lines or a JSON object into a header dict."""
    text = (text or "").strip()
    if not text:
        return {}
    # Try JSON first — exporters commonly emit objects.
    if text[:1] in "{[":
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items() if k}
            if isinstance(data, list):
                # List of {"name":..,"value":..} (HAR-style) or ["Name: Value", ...]
                out: dict[str, str] = {}
                for item in data:
                    if isinstance(item, dict) and "name" in item:
                        out[str(item["name"])] = str(item.get("value", ""))
                    elif isinstance(item, str) and ":" in item:
                        k, v = item.split(":", 1)
                        out[k.strip()] = v.strip()
                return out
        except Exception:
            pass
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip()
        value = value.strip()
        if name:
            out[name] = value
    return out


def parse_header_args(values: Optional[list[str]]) -> dict[str, str]:
    """Parse CLI ``--header "Name: Value"`` arguments."""
    out: dict[str, str] = {}
    for raw in values or []:
        if not raw or ":" not in raw:
            continue
        name, value = raw.split(":", 1)
        name = name.strip()
        value = value.strip()
        if name:
            out[name] = value
    return out


def load_header_file(path: str) -> dict[str, str]:
    """Load headers from a JSON / YAML / plain ``Name: Value`` file."""
    if not path:
        return {}
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Header file not found: {path}")
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
            data = yaml.safe_load(text) or {}
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items() if k}
        except Exception:
            pass
    return parse_header_lines(text)


class HeaderManager:
    """Mutable, async-safe HTTP header store with optional periodic refresh."""

    def __init__(
        self,
        headers: Optional[dict[str, str]] = None,
        refresh_cmd: str = "",
        refresh_interval: float = 0.0,
        on_change: Optional[Callable[[dict[str, str]], Awaitable[None]]] = None,
    ):
        self._headers: dict[str, str] = dict(headers or {})
        self.refresh_cmd: str = (refresh_cmd or "").strip()
        self.refresh_interval: float = max(0.0, float(refresh_interval or 0.0))
        self._lock = asyncio.Lock()
        self._last_refresh: float = time.monotonic()
        self._on_change = on_change
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()

    # ---- read helpers --------------------------------------------------
    def current(self) -> dict[str, str]:
        """Snapshot of current headers (safe to mutate)."""
        return dict(self._headers)

    def merged(self, extra: Optional[dict[str, str]] = None) -> dict[str, str]:
        """Snapshot merged with ``extra`` (extra wins on conflict)."""
        out = dict(self._headers)
        if extra:
            for k, v in extra.items():
                if v is None:
                    continue
                out[k] = v
        return out

    def has(self, name: str) -> bool:
        target = name.lower()
        return any(k.lower() == target for k in self._headers)

    # ---- mutation ------------------------------------------------------
    async def update(self, new_headers: dict[str, str]) -> dict[str, str]:
        """Merge ``new_headers`` in (case-insensitive overwrite) and notify listeners."""
        if not new_headers:
            return self.current()
        async with self._lock:
            # Case-insensitive replacement so "authorization" doesn't duplicate "Authorization".
            existing_lower = {k.lower(): k for k in self._headers}
            for name, value in new_headers.items():
                key_lower = name.lower()
                if key_lower in existing_lower and existing_lower[key_lower] != name:
                    del self._headers[existing_lower[key_lower]]
                self._headers[name] = str(value)
                existing_lower[key_lower] = name
            snapshot = dict(self._headers)
        if self._on_change:
            try:
                await self._on_change(snapshot)
            except Exception:
                pass
        return snapshot

    # ---- refresh -------------------------------------------------------
    async def refresh(self) -> bool:
        """Run ``refresh_cmd`` once and merge its output. Returns True on success."""
        if not self.refresh_cmd:
            return False
        try:
            # ``shell=True`` semantics via /bin/sh -c so users can use pipes/env vars.
            proc = await asyncio.create_subprocess_shell(
                self.refresh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=os.environ.copy(),
            )
            try:
                stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=30.0)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass
                return False
        except Exception:
            return False
        self._last_refresh = time.monotonic()
        if proc.returncode != 0:
            return False
        parsed = parse_header_lines(stdout.decode("utf-8", errors="replace"))
        if not parsed:
            return False
        await self.update(parsed)
        return True

    def start_background_refresh(self) -> None:
        """Start the periodic refresh task if a refresh command + interval are set."""
        if self._task is not None or not self.refresh_cmd or self.refresh_interval <= 0:
            return
        self._stop.clear()

        async def _loop():
            # Initial refresh so the very first request uses up-to-date headers.
            await self.refresh()
            while not self._stop.is_set():
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self.refresh_interval)
                except asyncio.TimeoutError:
                    pass
                if self._stop.is_set():
                    break
                await self.refresh()

        self._task = asyncio.create_task(_loop(), name="header-refresh")

    async def stop_background_refresh(self) -> None:
        if self._task is None:
            return
        self._stop.set()
        try:
            await asyncio.wait_for(self._task, timeout=2.0)
        except Exception:
            self._task.cancel()
        self._task = None

    @classmethod
    def from_sources(
        cls,
        cli_headers: Optional[list[str]] = None,
        header_file: str = "",
        extra: Optional[dict[str, str]] = None,
        refresh_cmd: str = "",
        refresh_interval: float = 0.0,
    ) -> "HeaderManager":
        merged: dict[str, str] = {}
        if header_file:
            merged.update(load_header_file(header_file))
        merged.update(parse_header_args(cli_headers))
        if extra:
            merged.update(extra)
        return cls(
            headers=merged,
            refresh_cmd=refresh_cmd,
            refresh_interval=refresh_interval,
        )
