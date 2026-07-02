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

# gzip マジックバイト。HAR / cookie エクスポート等が gzip 圧縮されて渡されると、
# 生バイトを UTF-8 で読もうとして ``can't decode byte 0x8b in position 1``
# （0x1f 0x8b = gzip）で落ちる。読み込み前に透過的に解凍する。
_GZIP_MAGIC = b"\x1f\x8b"

# gzip 展開の既定上限（伸張爆弾対策）。小さな圧縮データが巨大に展開される
# gzip bomb で `gzip.decompress` が全量を一括確保しメモリを食い潰す/スキャンを
# 止めるのを防ぐため、ストリーム展開してこのバイト数で打ち切る。
_MAX_GUNZIP_BYTES = 64 * 1024 * 1024  # 64 MB


def _maybe_gunzip(data: bytes, max_bytes: int | None = None) -> bytes:
    """gzip マジックで始まるなら **上限付きで** 解凍して返す（失敗時は元データ）。

    ``gzip.decompress`` は展開後の全量を一度に確保するため、信頼できない応答
    本文（例: ``NetworkCapture.enrich_response`` の ``safe_decode``）が gzip bomb
    だとメモリ枯渇/停止を招く。``max_bytes`` までストリーム展開し、超過分は
    捨てることで確保量を上限に抑える（呼び出し側が必要なバイト数を渡せば、
    そのぶんだけ展開する）。
    """
    if data[:2] != _GZIP_MAGIC:
        return data
    cap = max_bytes if (max_bytes is not None and max_bytes > 0) else _MAX_GUNZIP_BYTES
    try:
        import gzip
        import io

        out = bytearray()
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
            while len(out) < cap:
                chunk = gz.read(min(65536, cap - len(out)))
                if not chunk:
                    break
                out.extend(chunk)
        return bytes(out)
    except Exception:
        # 壊れた gzip 等。元バイトのまま後段のエンコーディング判定に委ねる。
        return data


def read_text_resilient(path: str | Path) -> str:
    """Read a text file, trying several encodings before failing.

    Tries UTF-8 (with/without BOM) first, then Japanese Windows codecs, then
    a latin-1 last resort that decodes any byte sequence. Raises only if the
    file genuinely cannot be opened (missing / permission), never on a mere
    encoding mismatch.
    """
    p = Path(path)
    data = _maybe_gunzip(p.read_bytes())
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
    # 呼び出し側が limit を渡していれば、そのバイト数までしか展開しない
    # （応答本文の gzip bomb でメモリを食い潰さないための上限）。
    data = _maybe_gunzip(data, max_bytes=limit)
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
