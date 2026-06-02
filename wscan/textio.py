"""
Resilient text I/O helpers
==========================
Reading user-supplied files (config YAML, cookie/accounts exports, exclude
lists, …) with a hard-coded ``encoding="utf-8"`` crashes with a
``UnicodeDecodeError: 'utf-8' codec can't decode byte …`` when the file was
actually saved in another encoding.  On Japanese Windows this is common —
Notepad (older versions), Excel exports and some editors emit Shift-JIS /
cp932.

``read_text_resilient`` tries a sequence of likely encodings before giving up,
so a Shift-JIS config file no longer aborts the whole scan.

``configure_console`` makes stdout/stderr tolerant of non-ASCII output (LLM
responses, payload snippets) on consoles whose native codec cannot encode the
characters, replacing un-encodable characters instead of raising.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Order matters: utf-8-sig strips a BOM if present; utf-8 is the common case;
# cp932 / shift_jis cover Japanese Windows exports; latin-1 never fails and is
# the last-resort fallback so we degrade gracefully rather than crash.
_FALLBACK_ENCODINGS = ("utf-8-sig", "utf-8", "cp932", "shift_jis", "latin-1")


def read_text_resilient(path: str | Path) -> str:
    """Read a text file, trying several encodings before failing.

    Tries UTF-8 (with/without BOM) first, then Japanese Windows codecs, then
    a latin-1 last resort that decodes any byte sequence. Raises only if the
    file genuinely cannot be opened (missing / permission), never on a mere
    encoding mismatch.
    """
    p = Path(path)
    data = p.read_bytes()
    last_exc: Exception | None = None
    for enc in _FALLBACK_ENCODINGS:
        try:
            return data.decode(enc)
        except UnicodeDecodeError as exc:
            last_exc = exc
            continue
    # latin-1 above can decode anything, so we should never get here; keep a
    # final guard with replacement so callers always receive a string.
    if last_exc is not None:
        return data.decode("utf-8", errors="replace")
    return data.decode("utf-8", errors="replace")


def safe_decode(data: bytes, limit: int | None = None) -> str:
    """Decode raw response/body bytes to text, tolerating non-UTF-8 content.

    Tries the same encoding ladder as :func:`read_text_resilient`.  Unlike
    httpx's ``Response.text`` (which already replaces undecodable bytes), this
    is for paths that decode raw ``bytes`` directly — e.g. Playwright's
    ``response.body()`` — where a strict ``bytes.decode()`` would raise
    ``UnicodeDecodeError`` on a malformed or binary body.
    """
    if not data:
        return ""
    if limit is not None:
        data = data[:limit]
    for enc in _FALLBACK_ENCODINGS:
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def configure_console() -> None:
    """Make stdout/stderr resilient to characters the console codec can't encode.

    Uses ``errors="replace"`` so streaming LLM output / non-ASCII payload
    snippets never raise ``UnicodeEncodeError`` on cp932 / cp1252 consoles.
    No-op on interpreters whose streams don't support ``reconfigure``.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(errors="replace")
        except (ValueError, OSError):
            # Detached/redirected streams may reject reconfigure; ignore.
            continue
