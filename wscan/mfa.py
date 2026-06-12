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


def mfa_field_present(html: str, field: str) -> bool:
    """設定された MFA コード入力欄（name/id == *field*）が HTML 内にあるか（純粋関数）。

    "code" のような汎用語シグナルに乗らない素っ気ない MFA 画面でも、ユーザーが
    明示指定した入力欄の存在を手掛かりに検出できるようにする。
    """
    if not html or not field:
        return False
    pat = rf'(?:name|id)\s*=\s*["\']?{re.escape(field)}\b'
    return re.search(pat, html, re.IGNORECASE) is not None


def mfa_challenge_present(html: str, field: str = "") -> bool:
    """MFA チャレンジ画面か（強いシグナル or 設定欄の存在）を判定する（純粋関数）。"""
    return looks_like_mfa_page(html) or mfa_field_present(html, field)


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


def extract_subjects(text: str) -> str:
    """メタデータ JSON から件名（subject）だけを連結して返す（純粋関数）。

    一覧（``list_emails_metadata``）の本文取得前にコードを拾う際、UID や日時など
    無関係な数値を誤って OTP と判定しないよう、抽出対象を件名に限定するために使う。
    """
    if not text:
        return ""
    subs = re.findall(r'"subject"\s*:\s*"((?:[^"\\]|\\.)*)"', text, re.IGNORECASE)
    return "\n".join(subs)


# メール ID として扱うキー（IMAP では uid が安定識別子）。
_ID_KEYS = ("uid", "id", "email_id", "message_id", "sequence", "seq")


def _coerce_id(value):
    """ID 値を正規化（数字文字列は int、その他は str）。無効値は None。"""
    if value is None:
        return None
    s = str(value).strip()
    if not s or s.lower() in ("null", "none"):
        return None
    return int(s) if s.isdigit() else s


def email_item_id(item):
    """メール 1 件の dict から識別子を取り出す（純粋関数）。優先順位は ``_ID_KEYS``。"""
    if not isinstance(item, dict):
        return None
    low = {str(k).lower(): v for k, v in item.items()}
    for k in _ID_KEYS:
        if k in low:
            cid = _coerce_id(low[k])
            if cid is not None:
                return cid
    return None


def parse_email_items(text: str) -> list:
    """メタデータ応答からメール dict のリストを取り出す（純粋関数）。

    ``list_emails_metadata`` の戻り（JSON）をゆるくパースし、各メールの dict を
    返す。list / {"emails":[...]} / 単一 dict のいずれの形でも拾う。古いメールの
    取りこぼし防止（ID ベースの重複排除）に使う。
    """
    if not text:
        return []
    data = _loads_loose(text)
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        for k in ("emails", "data", "items", "messages", "results"):
            v = data.get(k)
            if isinstance(v, list):
                return [d for d in v if isinstance(d, dict)]
        # 件名/ID らしきキーを持つなら単一メールとして扱う
        low = {str(kk).lower() for kk in data}
        if low & set(_ID_KEYS) or "subject" in low:
            return [data]
    return []


def extract_email_texts(text: str, fields=("subject", "body")) -> str:
    """メール応答(JSON)から指定フィールド（既定: subject/body）のみ連結する（純粋関数）。

    ``get_emails_content`` の応答は ``email_id`` / ``message_id`` / ``date`` 等を含むため、
    本文全体から OTP を拾うと識別子（6桁 UID 等）を誤検出する。抽出対象を本文系
    フィールドに限定してそれを防ぐ。構造解析できなければ空文字を返す。
    """
    items = parse_email_items(text)
    if not items:
        return ""
    low_fields = [f.lower() for f in fields]
    parts: list = []
    for it in items:
        low = {str(k).lower(): v for k, v in it.items()}
        for f in low_fields:
            v = low.get(f)
            if v:
                parts.append(str(v))
    return "\n".join(parts)


def _loads_loose(text: str):
    """テキストから JSON 配列/オブジェクトをゆるく読み出す（失敗時 None）。"""
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        pass
    for opener, closer in (("[", "]"), ("{", "}")):
        i = text.find(opener)
        j = text.rfind(closer)
        if 0 <= i < j:
            try:
                return json.loads(text[i:j + 1])
            except (ValueError, TypeError):
                continue
    return None


def extract_email_ids(text: str, limit: int = 5) -> list:
    """メール一覧（メタデータ）JSON/テキストからメール ID を抽出する（純粋関数）。

    ``list_emails_metadata`` の戻りから id/uid/email_id 等を拾い、本文取得
    （``get_emails_content``）へ渡す。数字 ID は int、その他は文字列で返す。
    重複は順序保持で除去し、先頭 *limit* 件まで。
    """
    if not text:
        return []
    out: list = []
    seen: set = set()
    pat = re.compile(
        r'"(?:id|uid|email_id|message_id|sequence|seq)"\s*:\s*"?([^",}\s]+)"?',
        re.IGNORECASE,
    )
    for raw in pat.findall(text):
        val = raw.strip()
        if not val or val.lower() in ("null", "none"):
            continue
        if val in seen:
            continue
        seen.add(val)
        out.append(int(val) if val.isdigit() else val)
        if len(out) >= limit:
            break
    return out


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
    totp_label_arg: str = "account_label"   # gosusnkr/mcp-totp-authenticator の get_totp_code

    # メール (mcp-email-server / ai-zerolab)
    # 受信箱はメタデータ一覧 → 本文取得の 2 段で読む（list-then-fetch）。
    # 実在ツール: list_emails_metadata / get_emails_content（いずれも account_name 必須）。
    email_command: str = "uvx"
    email_args: list = dc_field(
        default_factory=lambda: ["mcp-email-server@latest", "stdio"]
    )
    email_account: str = ""                 # account_name（mcp-email-server 側で登録済みの名前）
    # 動的 IMAP 設定: ここに値を入れると、spawn する mcp-email-server サブプロセスへ
    # MCP_EMAIL_SERVER_* env として注入し、サーバ側に事前登録が無い任意のメール
    # アドレスでも受信できる（ツールから IMAP 認証情報ごと動的に渡す）。
    email_address: str = ""                 # MCP_EMAIL_SERVER_EMAIL_ADDRESS
    email_user: str = ""                    # MCP_EMAIL_SERVER_USER_NAME（既定はアドレス）
    email_password: str = ""                # MCP_EMAIL_SERVER_PASSWORD
    email_imap_host: str = ""               # MCP_EMAIL_SERVER_IMAP_HOST
    email_imap_port: str = ""               # MCP_EMAIL_SERVER_IMAP_PORT（既定 993）
    email_imap_ssl: bool = True             # MCP_EMAIL_SERVER_IMAP_SSL
    email_server_env: dict = dc_field(default_factory=dict)  # 生 env の追加上書き
    email_list_tool: str = "list_emails_metadata"
    email_content_tool: str = "get_emails_content"
    email_page_size: int = 5
    email_list_args: dict = dc_field(default_factory=dict)    # subject/from_address 等の追加フィルタ
    email_content_args: dict = dc_field(default_factory=dict)
    email_timeout: float = 60.0
    email_interval: float = 5.0

    @property
    def resolved_email_account(self) -> str:
        """list/get ツールへ渡す account_name。未指定ならメールアドレスで代替する。

        動的 IMAP 設定（``email_address`` + ``email_imap_host`` 等）だけ与えて
        ``email_account`` を省略した場合でも、アドレスを account_name として使える。
        """
        return self.email_account or self.email_address

    @property
    def enabled(self) -> bool:
        if self.type == "totp":
            return bool(self.totp_command and self.totp_args)
        if self.type == "email":
            # account_name（またはアドレス）が無いと list/get が必ず失敗するため必須扱い。
            return bool(self.email_command and self.email_args and self.resolved_email_account)
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

        def _b(key: str, default: bool, ov_key: str) -> bool:
            ov_val = ov.get(ov_key)
            if ov_val is not None:
                if isinstance(ov_val, bool):
                    return ov_val
                return str(ov_val).strip().lower() not in ("0", "false", "no", "off", "")
            raw = e.get(key)
            if raw is None or str(raw).strip() == "":
                return default
            return str(raw).strip().lower() not in ("0", "false", "no", "off")

        # type は overrides を最優先。明示的に "none"/"" を渡されたら env を無視して無効化。
        if "type" in ov:
            mtype = (str(ov.get("type") or "none")).lower()
        else:
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
            totp_label_arg=_s("WSCAN_MFA_TOTP_LABEL_ARG", "account_label")
            or "account_label",
            email_command=_s("WSCAN_MFA_EMAIL_COMMAND", "uvx") or "uvx",
            email_args=parse_command(
                e.get("WSCAN_MFA_EMAIL_ARGS", "mcp-email-server@latest stdio")
            ),
            email_account=_s("WSCAN_MFA_EMAIL_ACCOUNT", ""),
            email_address=_s("WSCAN_MFA_EMAIL_ADDRESS", ""),
            email_user=_s("WSCAN_MFA_EMAIL_USER", ""),
            # UI/CLI の override（短縮キー email_password）を最優先で拾うため、
            # それを担う WSCAN_MFA_EMAIL_PASSWORD を先に評価し、ドキュメントの
            # WSCAN_MFA_EMAIL_IMAP_PASSWORD env にもフォールバックする。
            email_password=_s("WSCAN_MFA_EMAIL_PASSWORD", "")
            or _s("WSCAN_MFA_EMAIL_IMAP_PASSWORD", ""),
            email_imap_host=_s("WSCAN_MFA_EMAIL_IMAP_HOST", ""),
            email_imap_port=_s("WSCAN_MFA_EMAIL_IMAP_PORT", ""),
            email_imap_ssl=_b("WSCAN_MFA_EMAIL_IMAP_SSL", True, "email_imap_ssl"),
            email_server_env={
                **parse_json_obj(e.get("WSCAN_MFA_EMAIL_SERVER_ENV", "")),
                **(ov.get("email_server_env") or {}),
            },
            email_list_tool=_s("WSCAN_MFA_EMAIL_LIST_TOOL", "list_emails_metadata")
            or "list_emails_metadata",
            email_content_tool=_s("WSCAN_MFA_EMAIL_CONTENT_TOOL", "get_emails_content")
            or "get_emails_content",
            email_page_size=int(_f("WSCAN_MFA_EMAIL_PAGE_SIZE", 5)),
            email_list_args=parse_json_obj(e.get("WSCAN_MFA_EMAIL_LIST_ARGS", "")),
            email_content_args=parse_json_obj(e.get("WSCAN_MFA_EMAIL_CONTENT_ARGS", "")),
            email_timeout=_f("WSCAN_MFA_EMAIL_TIMEOUT", 60.0),
            email_interval=_f("WSCAN_MFA_EMAIL_INTERVAL", 5.0),
        )
        return cfg


def build_email_server_env(config: "MFAConfig") -> dict:
    """動的 IMAP 設定を mcp-email-server 用の ``MCP_EMAIL_SERVER_*`` env へ変換する（純粋関数）。

    ``email_imap_host`` か ``email_server_env`` が与えられている時のみ env を返す
    （= ユーザが「ツールから IMAP 認証情報を動的に渡した」とき）。これにより、
    サーバ側に事前登録が無い任意のメールアドレスでも、spawn する mcp-email-server
    サブプロセスへ認証情報を注入して受信できる。host を与えない既存フロー
    （サーバ側 env で account を登録済み）の挙動は変えない。

    ``email_server_env`` の生の上書きが最優先（厳密な変数名で微調整できる逃げ道）。
    """
    dynamic = bool(config.email_imap_host or config.email_server_env)
    if not dynamic:
        return {}
    env: dict = {}
    account = config.resolved_email_account
    if account:
        env["MCP_EMAIL_SERVER_ACCOUNT_NAME"] = account
    if config.email_address:
        env["MCP_EMAIL_SERVER_EMAIL_ADDRESS"] = config.email_address
    if config.email_user:
        env["MCP_EMAIL_SERVER_USER_NAME"] = config.email_user
    if config.email_password:
        env["MCP_EMAIL_SERVER_PASSWORD"] = config.email_password
    if config.email_imap_host:
        env["MCP_EMAIL_SERVER_IMAP_HOST"] = config.email_imap_host
        env["MCP_EMAIL_SERVER_IMAP_SSL"] = "true" if config.email_imap_ssl else "false"
    if config.email_imap_port:
        env["MCP_EMAIL_SERVER_IMAP_PORT"] = str(config.email_imap_port)
    # 生 env の追加上書き（厳密な変数名指定や SMTP 等）。値は文字列化。
    for k, v in (config.email_server_env or {}).items():
        env[str(k)] = str(v)
    return env


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
        # メール: パスワード送信前に確保する「既存メール ID」の baseline。
        # prime() で設定し、solve() が新着判定の基準に使う（古いコードの誤投入防止）。
        self._email_baseline: Optional[set] = None

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    @property
    def field(self) -> str:
        return self.config.field

    def _env(self) -> dict:
        # 秘匿情報（TOTP_SECRET_* / MCP_EMAIL_SERVER_*）は親プロセスの環境を
        # 引き継ぐ。extra_env で追加・上書きでき、さらに動的 IMAP 設定があれば
        # MCP_EMAIL_SERVER_* に変換して注入する（ツールから渡した認証情報が最優先）。
        merged = dict(os.environ)
        merged.update(self.config.extra_env or {})
        merged.update(build_email_server_env(self.config))
        return merged

    async def prime(self) -> None:
        """コード送信のトリガ（パスワード送信）前に呼ぶ事前準備。

        メール方式では、この時点で受信箱にある既存メール ID を baseline として
        記録する。これにより solve() は「送信後に届いた新着メールのみ」を対象に
        でき、前回ログインの期限切れコードを拾わない。TOTP では何もしない。
        失敗しても無視（solve() 側が初回ポーリングで baseline を作る従来動作へ）。
        """
        if self.config.type != "email":
            return
        try:
            ids = await self._list_email_ids()
            if ids is not None:
                self._email_baseline = ids
        except Exception:
            self._email_baseline = None

    async def _list_email_ids(self) -> Optional[set]:
        """現在の受信箱メタデータからメール ID 集合を取得する。"""
        cfg = self.config
        list_args = {
            "account_name": cfg.resolved_email_account,
            "page": 1,
            "page_size": cfg.email_page_size,
            "order": "desc",
        }
        list_args.update(cfg.email_list_args or {})
        result = await _call_mcp_tool(
            cfg.email_command, cfg.email_args, self._env(),
            cfg.email_list_tool, list_args,
        )
        items = parse_email_items(collect_tool_text(result))
        return {i for i in (email_item_id(it) for it in items) if i is not None}

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
        """受信箱から MFA コードを取得する（list-then-fetch）。

        mcp-email-server (ai-zerolab) の実ツールに合わせ、まず
        ``list_emails_metadata`` で直近メールのメタデータ（件名等）を取得し、
        件名でコードが拾えなければ ``get_emails_content`` で本文を取って抽出する。
        コードが届くまで ``email_timeout`` 秒ポーリングする。

        **古いメール対策**: ポーリング開始時点で既に受信箱にあるメール ID を
        baseline として記録し、以降は **その後に届いた新着メールのみ**を対象に
        する。これにより前回ログインの期限切れコードを誤って投入しない。
        構造解析に失敗するサーバでは baseline を作れないため、従来の
        件名→本文の総当り（重複排除なし）にフォールバックする。
        """
        cfg = self.config
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        list_args = {
            "account_name": cfg.resolved_email_account,
            "page": 1,
            "page_size": cfg.email_page_size,
            "order": "desc",
        }
        list_args.update(cfg.email_list_args or {})

        params = StdioServerParameters(
            command=cfg.email_command, args=list(cfg.email_args), env=self._env()
        )
        deadline = time.monotonic() + max(0.0, cfg.email_timeout)

        async def _fetch_code(session, ids):
            """指定 ID 群の本文を取得してコードを抽出する。"""
            if not ids:
                return None
            content_args = {"account_name": cfg.resolved_email_account, "email_ids": ids}
            content_args.update(cfg.email_content_args or {})
            body = await session.call_tool(cfg.email_content_tool, content_args)
            raw = collect_tool_text(body)
            # 応答は email_id/message_id/date を含むため、subject/body のみから抽出する
            # （識別子の 6桁 UID を OTP と誤検出しないため）。
            texts = extract_email_texts(raw)
            code = extract_otp(texts, cfg.code_length, cfg.code_regex)
            if code:
                return code
            # 構造解析できない応答のみ raw 全文へフォールバック（誤検出リスクは許容）。
            if not texts:
                return extract_otp(raw, cfg.code_length, cfg.code_regex)
            return None

        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                # prime() でパスワード送信前に baseline を確保済みなら、それを使い
                # 初回ポーリングから新着メールを検査する（送信直後に届く OTP を
                # baseline で握り潰さないため）。未 prime 時のみ初回で baseline 化。
                baseline: Optional[set] = self._email_baseline
                processed: set = set()           # 本文取得済みの新着 ID
                while True:
                    try:
                        meta = await session.call_tool(cfg.email_list_tool, dict(list_args))
                        meta_text = collect_tool_text(meta)
                        items = parse_email_items(meta_text)

                        if items:
                            ids_now = {
                                i for i in (email_item_id(it) for it in items) if i is not None
                            }
                            if baseline is None:
                                # 初回は既存メールを baseline 化（古いメールを除外）。
                                baseline = ids_now
                            else:
                                new_items = [
                                    it for it in items
                                    if (cid := email_item_id(it)) is not None
                                    and cid not in baseline and cid not in processed
                                ]
                                # まず新着メールの件名から（UID/日時の誤検出を避ける）。
                                subj = "\n".join(
                                    str(it.get("subject", "")) for it in new_items
                                )
                                code = extract_otp(subj, cfg.code_length, cfg.code_regex)
                                if code:
                                    return code
                                new_ids = [email_item_id(it) for it in new_items]
                                new_ids = [i for i in new_ids if i is not None]
                                code = await _fetch_code(session, new_ids)
                                if code:
                                    return code
                                processed.update(new_ids)
                        else:
                            # 構造解析できないサーバ向けフォールバック（重複排除なし）。
                            code = extract_otp(
                                extract_subjects(meta_text), cfg.code_length, cfg.code_regex
                            )
                            if code:
                                return code
                            code = await _fetch_code(
                                session, extract_email_ids(meta_text, limit=cfg.email_page_size)
                            )
                            if code:
                                return code
                    except Exception:
                        pass
                    if time.monotonic() >= deadline:
                        return None
                    await asyncio.sleep(max(1.0, cfg.email_interval))
