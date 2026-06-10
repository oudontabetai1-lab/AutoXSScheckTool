"""MFA（多要素認証）コード取得 — 外部 MCP サーバ経由。

認可済みターゲットへの「認証付きスキャン」で、ログイン時に要求される
ワンタイムコード（TOTP / メール送付のコード）を自動入力するための補助。
コード取得は外部 MCP サーバへ委譲する:

- TOTP: ``mcp-totp-authenticator`` (Node) … ``get_totp_code`` でコード生成。
- メール: ``mcp-email-server`` (Python) … 受信メールを取得しコードを抽出。

設計方針（CLAUDE.md の不変条件に準拠）:
- 反射文脈の検出やコード抽出など **判定ロジックは純粋関数**に分離し、
  ネットワーク／MCP 非依存で単体テストできる（``extract_otp`` /
  ``looks_like_mfa_page`` / ``collect_tool_text`` / ``parse_command``）。
- TOTP シークレットやメール認証情報など **秘匿情報は環境変数**で外部 MCP に
  渡す（このコード／設定ファイルに埋め込まない）。``MFAConfig.from_env``。
- MCP 接続（stdio クライアント）は失敗しても例外を握りつぶし ``None`` を返す。
  ログインの従来挙動（MFA 無し）を壊さない。
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
import time
from dataclasses import dataclass, field as dc_field
from typing import Optional


# ── 純粋関数（MCP 非依存・テスト対象） ─────────────────────────────────────

# MFA チャレンジ画面の強いシグナル（日本語/英語）。通常のログインフォームでの
# 誤検知を避けるため、"code" 単体のような弱い語は含めない。
_MFA_SIGNALS = (
    "one-time code",
    "one time code",
    "one-time password",
    "verification code",
    "authentication code",
    "security code",
    "authenticator app",
    "two-factor",
    "two factor",
    "2fa",
    "multi-factor",
    "multifactor",
    "mfa code",
    "otp",
    "passcode",
    "ワンタイム",
    "認証コード",
    "確認コード",
    "二段階",
    "二要素",
    "ワンタイムパスワード",
)


def looks_like_mfa_page(html: str) -> bool:
    """ページ HTML が MFA（2FA）コード入力画面に見えるか判定する（純粋関数）。"""
    if not html:
        return False
    low = html.lower()
    return any(sig in low for sig in _MFA_SIGNALS)


def extract_otp(text: str, length: int = 6, regex: str = "") -> Optional[str]:
    """テキストからワンタイムコードを抽出する（純粋関数）。

    *regex* 指定時はそれを使う（グループ1があればその値、無ければ全体）。
    未指定時は前後が数字でない *length* 桁の連続数字を拾う。
    """
    if not text:
        return None
    if regex:
        try:
            m = re.search(regex, text)
        except re.error:
            return None
        if not m:
            return None
        value = m.group(1) if m.groups() else m.group(0)
        return value.strip() or None
    n = int(length)
    m = re.search(rf"(?<!\d)(\d{{{n}}})(?!\d)", text)
    return m.group(1) if m else None


def parse_command(value) -> list:
    """コマンド引数文字列をリストへ。JSON 配列 or shlex で解釈（純粋関数）。"""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    s = str(value).strip()
    if not s:
        return []
    if s.startswith("["):
        try:
            arr = json.loads(s)
            if isinstance(arr, list):
                return [str(v) for v in arr]
        except (ValueError, TypeError):
            pass
    return shlex.split(s)


def parse_json_obj(value) -> dict:
    """JSON オブジェクト文字列を dict へ（空/不正は ``{}``）。純粋関数。"""
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    s = str(value).strip()
    if not s:
        return {}
    try:
        obj = json.loads(s)
        return obj if isinstance(obj, dict) else {}
    except (ValueError, TypeError):
        return {}


def collect_tool_text(result) -> str:
    """MCP ``call_tool`` 結果からテキストを集約する（純粋関数）。

    ``content`` の各要素の ``text`` と ``structuredContent`` の JSON 文字列を
    連結して返す。dict / オブジェクトどちらの形でも拾えるようにする。
    """
    parts: list[str] = []

    def _get(obj, key):
        if isinstance(obj, dict):
            return obj.get(key)
        return getattr(obj, key, None)

    content = _get(result, "content") or []
    for item in content:
        text = _get(item, "text")
        if text:
            parts.append(str(text))
    structured = _get(result, "structuredContent")
    if structured:
        try:
            parts.append(json.dumps(structured, ensure_ascii=False))
        except (TypeError, ValueError):
            parts.append(str(structured))
    return "\n".join(parts)


# ── 設定 ──────────────────────────────────────────────────────────────────
@dataclass
class MFAConfig:
    type: str = "none"               # "totp" | "email" | "none"
    field: str = "otp"               # ログインフォーム側のコード入力欄 name/id
    code_length: int = 6
    code_regex: str = ""
    extra_env: dict = dc_field(default_factory=dict)

    # TOTP (mcp-totp-authenticator)
    totp_command: str = "node"
    totp_args: list = dc_field(default_factory=list)
    totp_tool: str = "get_totp_code"
    totp_label: str = ""
    totp_label_arg: str = "label"

    # メール (mcp-email-server)
    email_command: str = "uvx"
    email_args: list = dc_field(
        default_factory=lambda: ["mcp-email-server@latest", "stdio"]
    )
    email_tool: str = "get_emails"
    email_tool_args: dict = dc_field(default_factory=dict)
    email_timeout: float = 60.0
    email_interval: float = 5.0

    @property
    def enabled(self) -> bool:
        if self.type == "totp":
            return bool(self.totp_command and self.totp_args)
        if self.type == "email":
            return bool(self.email_command and self.email_args)
        return False

    @classmethod
    def from_env(
        cls, env: Optional[dict] = None, overrides: Optional[dict] = None
    ) -> "MFAConfig":
        e = env if env is not None else os.environ
        ov = overrides or {}

        def _s(key: str, default: str) -> str:
            v = ov.get(_short(key))
            if v:
                return str(v)
            return (e.get(key, default) or default).strip()

        def _f(key: str, default: float) -> float:
            try:
                return float(e.get(key, default))
            except (TypeError, ValueError):
                return default

        def _short(key: str) -> str:
            # WSCAN_MFA_FIELD -> "field" のような overrides キー名
            return key.replace("WSCAN_MFA_", "").lower()

        mtype = _s("WSCAN_MFA_TYPE", "none").lower()
        if mtype not in ("totp", "email", "none"):
            mtype = "none"

        cfg = cls(
            type=mtype,
            field=_s("WSCAN_MFA_FIELD", "otp") or "otp",
            code_length=int(_f("WSCAN_MFA_CODE_LENGTH", 6)),
            code_regex=_s("WSCAN_MFA_CODE_REGEX", ""),
            totp_command=_s("WSCAN_MFA_TOTP_COMMAND", "node") or "node",
            totp_args=parse_command(e.get("WSCAN_MFA_TOTP_ARGS", "")),
            totp_tool=_s("WSCAN_MFA_TOTP_TOOL", "get_totp_code") or "get_totp_code",
            totp_label=_s("WSCAN_MFA_TOTP_LABEL", ""),
            totp_label_arg=_s("WSCAN_MFA_TOTP_LABEL_ARG", "label") or "label",
            email_command=_s("WSCAN_MFA_EMAIL_COMMAND", "uvx") or "uvx",
            email_args=parse_command(
                e.get("WSCAN_MFA_EMAIL_ARGS", "mcp-email-server@latest stdio")
            ),
            email_tool=_s("WSCAN_MFA_EMAIL_TOOL", "get_emails") or "get_emails",
            email_tool_args=parse_json_obj(e.get("WSCAN_MFA_EMAIL_TOOL_ARGS", "")),
            email_timeout=_f("WSCAN_MFA_EMAIL_TIMEOUT", 60.0),
            email_interval=_f("WSCAN_MFA_EMAIL_INTERVAL", 5.0),
        )
        return cfg


# ── MCP クライアント呼び出し ───────────────────────────────────────────────
async def _call_mcp_tool(
    command: str, args: list, env: dict, tool: str, arguments: dict
):
    """stdio MCP サーバを起動し 1 ツールを呼んで結果を返す。"""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command=command, args=list(args), env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await session.call_tool(tool, arguments or {})


class MFASolver:
    """設定済みの外部 MCP からワンタイムコードを取得する。"""

    def __init__(self, config: MFAConfig):
        self.config = config

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    @property
    def field(self) -> str:
        return self.config.field

    def _env(self) -> dict:
        # 秘匿情報（TOTP_SECRET_* / MCP_EMAIL_SERVER_*）は親プロセスの環境を
        # 引き継ぐ。extra_env で追加・上書きできる。
        merged = dict(os.environ)
        merged.update(self.config.extra_env or {})
        return merged

    async def solve(self) -> Optional[str]:
        """MFA 種別に応じてコードを取得する。失敗時は ``None``。"""
        try:
            if self.config.type == "totp":
                return await self._solve_totp()
            if self.config.type == "email":
                return await self._solve_email()
        except Exception:
            return None
        return None

    async def _solve_totp(self) -> Optional[str]:
        cfg = self.config
        arguments: dict = {}
        if cfg.totp_label:
            arguments[cfg.totp_label_arg] = cfg.totp_label
        result = await _call_mcp_tool(
            cfg.totp_command, cfg.totp_args, self._env(), cfg.totp_tool, arguments
        )
        text = collect_tool_text(result)
        return extract_otp(text, cfg.code_length, cfg.code_regex)

    async def _solve_email(self) -> Optional[str]:
        cfg = self.config
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        params = StdioServerParameters(
            command=cfg.email_command, args=list(cfg.email_args), env=self._env()
        )
        deadline = time.monotonic() + max(0.0, cfg.email_timeout)
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                while True:
                    try:
                        result = await session.call_tool(
                            cfg.email_tool, dict(cfg.email_tool_args)
                        )
                        text = collect_tool_text(result)
                        code = extract_otp(text, cfg.code_length, cfg.code_regex)
                        if code:
                            return code
                    except Exception:
                        pass
                    if time.monotonic() >= deadline:
                        return None
                    await asyncio.sleep(max(1.0, cfg.email_interval))
