"""
LLM Agent Browser
=================
LLM がブラウザを直接操作して脆弱性を探索する自律型スキャナー。

browser-use (https://github.com/browser-use/browser-use) をバックエンドとして使い、
LLM が Playwright ブラウザをリアルタイムに制御しながらペネトレーションテストを実施する。
従来の「クロール→計画→攻撃」パイプラインとは異なり、LLM 自身が:
  1. ページを観察してどこにどんな入力があるかを判断
  2. どのペイロードをどのフィールドに入力するか自律的に決定
  3. 送信後のレスポンスを見て脆弱性の有無を判定
  4. 次のアクションを決定 (別ページへ移動 / 別フィールドをテスト / 終了)

対応 LLM プロバイダー
---------------------
  claude  → browser_use.llm.ChatAnthropic  (推奨: 視覚理解が最も優秀)
  openai  → browser_use.llm.ChatOpenAI
  ollama  → browser_use.llm.ChatOllama    (ツール呼び出し対応モデルが必要)
"""
from __future__ import annotations

import asyncio
import fnmatch
import inspect
import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING
from urllib.parse import urlparse

from rich.console import Console
from rich.rule import Rule

from .header_scope import (
    _BLANK_URLS,
    _url_origin,
    allowed_header_origins,
    effective_origin_url,
    expand_scheme_variants,
    headers_allowed_for_url,
)

if TYPE_CHECKING:
    from wscan.monitor import MonitorServer

console = Console()

_TARGET_HANDLER_TIMEOUT_SECONDS = 3.0


def _normalize_agent_url(url: str) -> str:
    """Agent が扱う URL を scheme 付きへ正規化する。"""
    value = str(url or "").strip().rstrip("/")
    if value and not re.match(r"^https?://", value, re.IGNORECASE):
        value = "http://" + value
    return value


def _normalize_scope_urls(urls: list[str]) -> list[str]:
    """通常スキャンと同じ比較用形式でスコープ URL を重複排除する。"""
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in urls:
        value = str(raw or "").strip().rstrip("/")
        if value and value not in seen:
            seen.add(value)
            normalized.append(value)
    return normalized


def _url_matches_scope(url: str, scopes: list[str]) -> bool:
    """URL が full URL または path 指定のスコープ内か判定する。"""
    candidate = str(url or "").strip().rstrip("/")
    parsed = urlparse(candidate)
    for scope in scopes:
        if scope.startswith(("http://", "https://")):
            if candidate == scope or candidate.startswith(scope + "/"):
                return True
            continue
        if parsed.path == scope or parsed.path.startswith(scope.rstrip("/") + "/"):
            return True
    return False


def _url_is_excluded(url: str, exclude_urls: list[str]) -> bool:
    """通常スキャンと同じ exclude URL 規則を Agent 偵察にも適用する。"""
    if not url or not exclude_urls:
        return False
    parsed = urlparse(url)
    url_lower = url.lower()
    path_lower = (parsed.path or "").lower()
    for pattern in exclude_urls:
        value = str(pattern or "").strip().replace("＊", "*").lower()
        if not value:
            continue
        is_full_url = value.startswith(("http://", "https://"))
        target = url_lower if is_full_url else path_lower
        if "*" in value:
            if fnmatch.fnmatch(target, value):
                return True
            if value.endswith("/*") and target == value[:-2]:
                return True
            continue
        if is_full_url:
            if url_lower == value or url_lower.startswith(value):
                return True
        elif value.startswith("/"):
            if path_lower == value or path_lower.startswith(value):
                return True
        elif value in path_lower:
            return True
    return False


def security_probe_allowed(
    url: str,
    target_urls: list[str],
    exclude_urls: list[str],
    *,
    field_name: str = "",
    exclude_fields: Optional[list[str]] = None,
) -> bool:
    """Agent の security probe が認可済み対象かを副作用なしで判定する。"""
    if not _url_matches_scope(url, _normalize_scope_urls(target_urls)):
        return False
    if _url_is_excluded(url, exclude_urls):
        return False
    excluded_fields = {str(name).strip().lower() for name in (exclude_fields or [])}
    return not field_name or field_name.strip().lower() not in excluded_fields


_PROBE_MUTATING_ACTIONS = frozenset({
    "evaluate",
    "execute_javascript",
    "input",
    "input_text",
    "select_dropdown",
    "select_option",
    "send_keys",
    "type",
    "upload_file",
})
_AUTH_INPUT_ACTIONS = frozenset({"input", "input_text", "type"})
_AUTH_INPUT_VALUE_KEYS = ("text", "value")


def _is_allowed_auth_input(
    action_name: str,
    action_value,
    allowed_auth_values: frozenset[str],
) -> bool:
    """入力 action が設定済み認証値だけを投入するか判定する。"""
    if action_name not in _AUTH_INPUT_ACTIONS or not allowed_auth_values:
        return False
    if isinstance(action_value, str):
        input_value = action_value
    elif isinstance(action_value, dict):
        values = [
            action_value[key]
            for key in _AUTH_INPUT_VALUE_KEYS
            if key in action_value
        ]
        # 想定外の複数値や値キー欠落は、安全側で mutation を許可しない。
        if len(values) != 1:
            return False
        input_value = values[0]
    else:
        return False
    return isinstance(input_value, str) and input_value in allowed_auth_values


def filter_probe_actions(
    actions: list,
    *,
    allow_mutation: bool,
    allowed_auth_values: tuple[str, ...] = (),
) -> tuple[list, int]:
    """対象外ページでは mutation を除き、login の認証値入力だけ例外許可する。"""
    if allow_mutation:
        return list(actions), 0
    auth_values = frozenset(value for value in allowed_auth_values if value)
    allowed: list = []
    blocked = 0
    for action in actions:
        try:
            action_data = action.model_dump(exclude_unset=True)
        except Exception:
            action_data = {}
        # browser-use の action は一度に1種類だけを持つ。形式不明や複数 action は
        # mutation の判別不能なので、安全側で実行しない。
        if not isinstance(action_data, dict) or len(action_data) != 1:
            blocked += 1
            continue
        action_name = next(iter(action_data))
        if action_name in _PROBE_MUTATING_ACTIONS:
            if _is_allowed_auth_input(
                action_name,
                action_data[action_name],
                auth_values,
            ):
                allowed.append(action)
                continue
            blocked += 1
            continue
        allowed.append(action)
    return allowed, blocked

# ── 検出する脆弱性の説明 ────────────────────────────────────────────────────

_CHECK_DESCRIPTIONS: dict[str, str] = {
    "xss":            "Cross-Site Scripting (XSS) — inject <script>alert(1)</script> and variants",
    "sqli":           "SQL Injection — inject ' OR '1'='1 and variants; watch for DB errors or logic bypass",
    "ssti":           "Server-Side Template Injection — inject {{7*7}} / ${7*7} and check for 49 in response",
    "os":             "OS Command Injection — inject ; id and ; whoami; check for command output",
    "path_traversal": "Path Traversal — inject ../../etc/passwd in file/path parameters",
    "ssrf":           "SSRF — inject http://169.254.169.254/latest/meta-data/ in URL parameters",
    "open_redirect":  "Open Redirect — inject https://evil.com in redirect/next/url parameters",
    "csrf":           "CSRF — check if state-changing forms lack CSRF tokens",
    "header_injection": "HTTP Header Injection — inject \\r\\n in header-reflected parameters",
}

# Per-session nonce prefix baked into the system prompt. Any
# "VULNERABILITY FOUND" block that does not carry this nonce is considered
# untrusted (likely reflected attacker content) and ignored during parsing.
# The placeholder "{SESSION_NONCE}" is substituted at agent start-up.
_SECURITY_SYSTEM_PROMPT = """You are an expert web application penetration tester conducting an authorized security assessment.

## Session Authenticity
Every finding you report MUST begin with this exact token on its own line,
placed immediately before the "VULNERABILITY FOUND:" marker:

    WSCAN-NONCE:{SESSION_NONCE}

This token is unknown to the target application. The operator will ignore any
report that is missing or has an incorrect token. Never echo the token inside
page input, URLs, payloads, or evidence fields — only as the literal marker line.

## CRITICAL: Browser Navigation Rules
- NEVER use go_back as your first action. The browser is already positioned at the target URL.
- If you ever land on about:blank or a blank page, use the navigate action to go directly to the target URL — do NOT use go_back.
- go_back is only useful after you have navigated away from a page and want to return to it.

## Authorization Scope
{SECURITY_SCOPE}

## Your Capabilities
You can control a real web browser. Use it to:
- Navigate to URLs
- Click buttons and links
- Fill in form fields with test payloads
- Read page content and HTTP responses
- Take screenshots to document findings

## Testing Methodology
For EACH form or URL parameter you discover inside ATTACK TARGETS and outside exclusions:
1. First understand what the field does (login, search, comment, file path, etc.)
2. Choose the most relevant payload for that field type
3. Submit and carefully observe the response
4. If a vulnerability is detected, document it precisely

## Vulnerability Detection Signals
- **XSS**: Browser alert/confirm dialog fires, OR <script> tag appears unescaped in page source
- **SQLi**: Database error message visible, OR login succeeded with ' OR '1'='1, OR response length differs between true/false conditions
- **SSTI**: Template expression evaluated (e.g. {{7*7}} rendered as 49)
- **OS Injection**: System command output visible (uid=, /bin/bash, etc.)
- **Path Traversal**: /etc/passwd content or system file contents visible
- **SSRF**: Internal service response or metadata endpoint content returned
- **Open Redirect**: Browser redirects to injected external URL

## Reporting Findings
When you discover a vulnerability, emit EXACTLY this block (nonce first):
```
WSCAN-NONCE:{SESSION_NONCE}
VULNERABILITY FOUND:
Type: <xss|sqli|ssti|os|path_traversal|ssrf|open_redirect|csrf>
Severity: <critical|high|medium|low>
URL: <exact URL>
Field: <field name or URL parameter>
Payload: <exact payload used>
Evidence: <what you observed that confirms the vulnerability>
```

Be thorough but efficient. Test all authorized discovered inputs. Do not stop after finding one vulnerability."""


# ── 結果データクラス ────────────────────────────────────────────────────────

@dataclass
class AgentMemory:
    """エージェントスキャン中に収集した情報（セッション内メモリ）。"""
    visited_urls: list = field(default_factory=list)
    step_summaries: list = field(default_factory=list)


@dataclass
class AgentFinding:
    """agent-browser が検出した脆弱性の1件。"""
    check_type: str
    severity: str
    url: str
    field_name: str
    payload: str
    evidence: str
    source: str = "agent"
    agent_verified: bool = False

    def to_dict(self) -> dict:
        return {
            "check_type": self.check_type,
            "severity": self.severity,
            "url": self.url,
            "field_name": self.field_name,
            "payload": self.payload,
            "evidence": self.evidence,
            "source": self.source,
            "agent_verified": self.agent_verified,
        }


@dataclass
class AgentScanResult:
    """エージェントスキャン全体の結果。"""
    target_url: str
    findings: list[AgentFinding] = field(default_factory=list)
    steps_taken: int = 0
    final_summary: str = ""
    raw_history: list[dict] = field(default_factory=list)
    error: Optional[str] = None
    success: bool = False
    memory: AgentMemory = field(default_factory=AgentMemory)


# ── LLM ファクトリ ──────────────────────────────────────────────────────────

def _build_llm(provider: str, model: str, ollama_url: str = "http://localhost:11434",
               base_url: str = ""):
    """
    browser-use の BaseChatModel インスタンスを provider 名から生成する。
    """
    if provider == "claude":
        from browser_use.llm import ChatAnthropic
        import os
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY 環境変数が設定されていません。")
        return ChatAnthropic(model=model or "claude-sonnet-4-5-20250929", api_key=api_key)

    elif provider in ("openai", "openai_compatible"):
        from browser_use.llm import ChatOpenAI
        from . import llm_endpoint
        api_key = llm_endpoint.resolve_api_key(provider)
        if not api_key:
            raise RuntimeError(
                "API キーが設定されていません（WSCAN_LLM_API_KEY または OPENAI_API_KEY）。"
            )
        # ベース URL は provider の意図で解決する（明示 base_url ＞ [互換のみ]env ＞
        # 公式既定）。公式 openai は env が設定されていても既定(公式)を使い、
        # openai_compatible のときだけカスタムエンドポイントへ向ける。値はここで
        # 解決して直接渡すため、グローバル env を書き換えない（operator 設定を壊さない）。
        kwargs = {"model": model or "gpt-4o-mini", "api_key": api_key}
        base = llm_endpoint.resolve_instance_base(provider, base_url)
        if base and base != llm_endpoint.DEFAULT_OPENAI_BASE:
            kwargs["base_url"] = base
        return ChatOpenAI(**kwargs)

    elif provider == "ollama":
        from browser_use.llm import ChatOllama
        host = ollama_url.rstrip("/")
        model_name = model or "llama3"
        # Warn if model is too small for reliable browser-use tool calling
        _SMALL_SUFFIXES = (":1b", ":3b", ":1.5b", ":2b", ":0.5b")
        if any(model_name.lower().endswith(s) for s in _SMALL_SUFFIXES):
            console.print(
                f"[yellow]⚠️  警告: {model_name!r} はブラウザ操作には小さすぎる可能性があります。"
                f" 最低でも 7B 以上 (例: qwen2.5-coder:7b, llama3:8b) を推奨します。[/yellow]"
            )
        return ChatOllama(model=model_name, host=host)

    else:
        raise RuntimeError(
            f"エージェントモードは provider='{provider}' に対応していません。"
            f" claude / openai / ollama を指定してください。"
        )


# ── ファインディング抽出 ────────────────────────────────────────────────────

def _build_vuln_block_re(nonce: str) -> re.Pattern:
    """Require the session nonce on the line directly before VULNERABILITY FOUND.

    This prevents a malicious target page whose content happens to reflect the
    literal "VULNERABILITY FOUND" template from generating fake findings:
    attacker content cannot contain the per-session nonce.
    """
    return re.compile(
        r"WSCAN-NONCE:" + re.escape(nonce) + r"\s*\n"
        r"VULNERABILITY FOUND:\s*"
        r"Type:\s*(?P<type>[^\n]+)\n"
        r"Severity:\s*(?P<severity>[^\n]+)\n"
        r"URL:\s*(?P<url>[^\n]+)\n"
        r"Field:\s*(?P<field>[^\n]+)\n"
        r"Payload:\s*(?P<payload>[^\n]+)\n"
        r"Evidence:\s*(?P<evidence>(?:.+\n?)+?)(?=\nWSCAN-NONCE:|$)",
        re.IGNORECASE,
    )


def _parse_findings_from_text(text: str, nonce: str = "") -> list[AgentFinding]:
    """エージェントの出力テキストから VULNERABILITY FOUND ブロックを解析する。

    ``nonce`` が空でない場合、各ブロックの直前に ``WSCAN-NONCE:<nonce>`` が
    存在することを要求する (LLM だけが知っている値なので、悪性ページの反射では
    偽のブロックを通過させられない)。
    """
    vuln_re = _build_vuln_block_re(nonce) if nonce else None
    _type_map = {
        "cross-site scripting": "xss",
        "sql injection": "sqli",
        "server-side template injection": "ssti",
        "os command injection": "os",
        "command injection": "os",
        "path traversal": "path_traversal",
        "directory traversal": "path_traversal",
        "server-side request forgery": "ssrf",
        "open redirect": "open_redirect",
        "cross-site request forgery": "csrf",
        "http header injection": "header_injection",
    }
    _valid_severities = {"critical", "high", "medium", "low"}

    findings: list[AgentFinding] = []
    seen: set[tuple] = set()  # BUG-4 fix: deduplicate on (url, field, check_type)

    active_re = vuln_re if vuln_re is not None else _build_vuln_block_re("")
    for m in active_re.finditer(text):
        check_type = m.group("type").strip().lower()
        check_type = _type_map.get(check_type, check_type)

        severity = m.group("severity").strip().lower()
        if severity not in _valid_severities:
            severity = "medium"  # fallback for unexpected values

        url = m.group("url").strip()
        field_name = m.group("field").strip()

        dedup_key = (url, field_name, check_type)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        findings.append(AgentFinding(
            check_type=check_type,
            severity=severity,
            url=url,
            field_name=field_name,
            payload=m.group("payload").strip(),
            evidence=m.group("evidence").strip(),
            source="agent",
        ))
    return findings


# ── メインスキャナー ────────────────────────────────────────────────────────

class AgentBrowserScanner:
    """
    browser-use Agent を使ってターゲット URL をペネトレーションテストする。

    Parameters
    ----------
    target_url      : スキャン対象 URL
    llm_provider    : 'claude' | 'openai' | 'ollama'
    llm_model       : モデル名 (空文字でデフォルト)
    ollama_url      : Ollama エンドポイント (ollama 使用時)
    checks          : テストする脆弱性タイプのリスト
    headless        : ヘッドレスモード
    auth_user       : ログインユーザー名 (省略可)
    auth_pass       : ログインパスワード (省略可)
    login_url       : ログインページ URL (省略可)
    max_steps       : エージェントの最大ステップ数
    monitor         : ダッシュボード通知用 MonitorServer (省略可)
    recon_mode      : True にすると URL 偵察を優先し、探索中の Finding も報告する
    target_urls     : security probe を許可する攻撃対象 URL
    access_urls     : 訪問・認証のみ許可し、security probe は禁止する URL
    exclude_urls    : 訪問は可能だが security probe を禁止する URL パターン
    exclude_fields  : security probe を禁止するフィールド名
    """

    def __init__(
        self,
        target_url: str,
        llm_provider: str = "claude",
        llm_model: str = "",
        ollama_url: str = "http://localhost:11434",
        checks: Optional[list[str]] = None,
        headless: bool = True,
        auth_user: str = "",
        auth_pass: str = "",
        login_url: str = "",
        max_steps: int = 100,
        monitor: Optional["MonitorServer"] = None,
        recon_mode: bool = False,
        llm_base_url: str = "",
        target_urls: Optional[list[str]] = None,
        access_urls: Optional[list[str]] = None,
        exclude_urls: Optional[list[str]] = None,
        exclude_fields: Optional[list[str]] = None,
        extra_headers: Optional[dict] = None,
    ):
        # CDP / SecurityWatchdog が scheme 無し URL を拒否するため補完する。
        raw_target_url = str(target_url or "").strip()
        raw_login_url = str(login_url or "").strip()
        urls_without_scheme = {
            raw_url
            for raw_url in (raw_target_url, raw_login_url)
            if raw_url and not re.match(r"^https?://", raw_url, re.IGNORECASE)
        }
        self.target_url = _normalize_agent_url(target_url)
        self.llm_provider = llm_provider
        self.llm_model = llm_model
        self.ollama_url = ollama_url
        self.checks = checks or ["xss", "sqli", "ssti", "os", "path_traversal", "ssrf"]
        self.headless = headless
        self.auth_user = auth_user
        self.auth_pass = auth_pass
        self.login_url = _normalize_agent_url(login_url) if login_url else login_url
        self.max_steps = max_steps
        self.monitor = monitor
        self.recon_mode = recon_mode
        self.llm_base_url = llm_base_url
        primary = urlparse(self.target_url)
        primary_origin = (
            f"{primary.scheme}://{primary.netloc}"
            if primary.scheme and primary.netloc
            else self.target_url
        )
        self.target_urls = _normalize_scope_urls(
            [primary_origin] + list(target_urls or [])
        )
        self.access_urls = _normalize_scope_urls(
            list(access_urls or []) + ([self.login_url] if self.login_url else [])
        )
        self.exclude_urls = [
            str(value).strip() for value in (exclude_urls or []) if str(value).strip()
        ]
        self.exclude_fields = [
            str(value).strip() for value in (exclude_fields or []) if str(value).strip()
        ]
        self.extra_headers = dict(extra_headers or {})
        self._header_origins = allowed_header_origins(
            self.target_url,
            self.target_urls,
            self.access_urls,
            self.login_url,
            urls_without_scheme,
        )
        self._request_scoped_headers = False
        self._fetch_enabled_targets: set[str] = set()
        self._target_event_client = None
        self._target_event_tasks: set[asyncio.Task] = set()
        self._headers_applied = False
        self._missing_header_url_api_warned = False
        self._header_application_failed_warned = False
        self._header_clear_failed_warned = False
        self._step_count = 0
        self._memory = AgentMemory()
        self._session_nonce = secrets.token_urlsafe(16)

    def _warn_missing_header_url_api(self) -> None:
        """現在 URL を安全に判定できない browser-use 版を一度だけ警告する。"""
        if self._missing_header_url_api_warned:
            return
        self._missing_header_url_api_warned = True
        console.print(
            "[yellow]警告: この browser-use では現在ページのオリジンを確認できないため、"
            "Agent 偵察は指定した認証ヘッダなしで実行されます"
            "（requirements-agent.txt の browser-use 0.12.6 では対応）。[/yellow]"
        )

    async def _warn_header_application_failed(self) -> None:
        """認証ヘッダの適用失敗を、秘匿値を含めず一度だけ通知する。"""
        if self._header_application_failed_warned:
            return
        self._header_application_failed_warned = True
        message = (
            "Agent ブラウザへ認証ヘッダを適用できませんでした。"
            "認証が必要なページを偵察できない可能性があります。"
        )
        if self.monitor:
            try:
                await self.monitor.emit_status(message, "running")
                return
            except Exception:
                # monitor 障害でも Agent の探索は止めず、コンソールへフォールバックする。
                pass
        console.print(f"[yellow]{message}[/yellow]")

    async def _warn_header_clear_failed(self) -> None:
        """認証ヘッダの解除失敗を、秘匿値を含めず一度だけ通知する。"""
        if self._header_clear_failed_warned:
            return
        self._header_clear_failed_warned = True
        message = (
            "Agent ブラウザの認証ヘッダを解除できませんでした。"
            "対象外ページへ認証情報が送信される可能性があります。"
        )
        if self.monitor:
            try:
                await self.monitor.emit_status(message, "running")
                return
            except Exception:
                # monitor 障害でも Agent の探索は止めず、コンソールへフォールバックする。
                pass
        console.print(f"[yellow]{message}[/yellow]")

    async def _clear_extra_headers(self, session) -> None:
        """直前に適用した追加ヘッダを、値を露出せず解除する。"""
        if not self._headers_applied:
            return
        try:
            await session.set_extra_headers({})
        except Exception:
            # ヘッダ値をログや例外へ出さず、Agent の探索を継続する。
            await self._warn_header_clear_failed()
        else:
            self._headers_applied = False

    async def _apply_extra_headers(self, session, intended_url: str = "") -> None:
        """許可オリジンの Agent 対象ページにだけ追加ヘッダを適用する。"""
        if not self.extra_headers or not hasattr(session, "set_extra_headers"):
            return
        if not hasattr(session, "get_current_page_url"):
            self._warn_missing_header_url_api()
            await self._clear_extra_headers(session)
            return
        try:
            current_url = await session.get_current_page_url()
        except Exception:
            await self._clear_extra_headers(session)
            await self._warn_header_application_failed()
            return
        origin_url = effective_origin_url(current_url, intended_url)
        if not headers_allowed_for_url(origin_url, self._header_origins):
            await self._clear_extra_headers(session)
            return
        try:
            await session.set_extra_headers(self.extra_headers)
        except Exception:
            # ヘッダ値をログや例外へ出さず、Agent の探索を継続する。
            await self._warn_header_application_failed()
        else:
            self._headers_applied = True

    async def _enable_fetch_for_cdp_target(
        self,
        cdp_client,
        cdp_session_id: str,
        target_id: str,
    ) -> bool:
        """指定した CDP target が未設定なら Fetch を有効化する。"""
        fetch_commands = None
        try:
            if not target_id:
                return False
            if target_id in self._fetch_enabled_targets:
                return True

            fetch_commands = cdp_client.send.Fetch
            fetch_registration = cdp_client.register.Fetch

            # cdp_use 1.4.5 / browser-use 0.12.6 の EventRegistry は async
            # callback を await する。Fetch.enable より先に登録し、有効化直後の
            # requestPaused に未処理区間が生じないようにする。
            async def _continue_paused_request(event, event_session_id=None):
                request_id = None
                continued = False
                continue_session_id = event_session_id or cdp_session_id
                try:
                    request_id = event.get("requestId") or event.get("request_id")
                    if not request_id:
                        return

                    request = event.get("request") or {}
                    request_url = request.get("url") or ""
                    params = {"requestId": request_id}
                    if headers_allowed_for_url(request_url, self._header_origins):
                        existing_headers = request.get("headers") or {}
                        overridden_names = {
                            str(name).lower() for name in self.extra_headers
                        }
                        headers = [
                            {"name": str(name), "value": str(value)}
                            for name, value in existing_headers.items()
                            if str(name).lower() not in overridden_names
                        ]
                        headers.extend(
                            {"name": str(name), "value": str(value)}
                            for name, value in self.extra_headers.items()
                        )
                        params["headers"] = headers

                    await asyncio.wait_for(
                        fetch_commands.continueRequest(
                            params=params,
                            session_id=continue_session_id,
                        ),
                        timeout=3.0,
                    )
                    continued = True
                except Exception:
                    # 判定・ヘッダ生成・CDP 送信のどこで失敗しても値は出力しない。
                    pass
                finally:
                    if request_id and not continued:
                        try:
                            await asyncio.wait_for(
                                fetch_commands.continueRequest(
                                    params={"requestId": request_id},
                                    session_id=continue_session_id,
                                ),
                                timeout=3.0,
                            )
                        except Exception:
                            # 最後の素通しも失敗した場合は Agent 全体を止めない。
                            pass

            # 登録を先に行うことで、登録失敗時には Fetch を有効化しない。
            fetch_registration.requestPaused(_continue_paused_request)
            await asyncio.wait_for(
                fetch_commands.enable(
                    params={"patterns": [{"urlPattern": "*"}]},
                    session_id=cdp_session_id,
                ),
                timeout=3.0,
            )
        except Exception:
            # 登録または有効化が部分的に成功していても paused request を残さない。
            if fetch_commands is not None:
                try:
                    await asyncio.wait_for(
                        fetch_commands.disable(session_id=cdp_session_id),
                        timeout=3.0,
                    )
                except Exception:
                    pass
            return False

        self._fetch_enabled_targets.add(target_id)
        return True

    async def _enable_fetch_for_current_target(self, session) -> bool:
        """現在の browser target が未設定なら CDP Fetch を有効化する。"""
        try:
            target_id = session.agent_focus_target_id
            if not target_id:
                return False
            if target_id in self._fetch_enabled_targets:
                return True
            cdp_session = await session.get_or_create_cdp_session(
                target_id,
                focus=False,
            )
            return await self._enable_fetch_for_cdp_target(
                cdp_session.cdp_client,
                cdp_session.session_id,
                target_id,
            )
        except Exception:
            return False

    async def _enable_fetch_for_attached_target(
        self,
        cdp_client,
        event: dict,
        before_resume=None,
    ) -> None:
        """停止中の新 target に Fetch を設定し、成否にかかわらず再開する。"""
        target_info = event.get("targetInfo") or {}
        target_id = target_info.get("targetId") or ""
        target_type = target_info.get("type") or ""
        cdp_session_id = event.get("sessionId") or ""
        try:
            if target_type in {"page", "tab"} and target_id and cdp_session_id:
                await self._enable_fetch_for_cdp_target(
                    cdp_client,
                    cdp_session_id,
                    target_id,
                )
        finally:
            if before_resume is not None:
                try:
                    # browser-use の既存 attachedToTarget ハンドラは、Fetch の
                    # 設定完了後、target を再開する前に引き渡す。
                    result = before_resume()
                    if inspect.isawaitable(result):
                        await asyncio.wait_for(
                            result,
                            timeout=_TARGET_HANDLER_TIMEOUT_SECONDS,
                        )
                except Exception:
                    # 既存ハンドラの失敗やタイムアウトで target を停止したままに
                    # せず、下の runIfWaitingForDebugger へ必ず進む。
                    pass
            if cdp_session_id:
                try:
                    # waitForDebuggerOnStart=True で停止させた target は、Fetch の
                    # 成否や対象種別にかかわらず必ず再開してブラウザをハングさせない。
                    await asyncio.wait_for(
                        cdp_client.send.Runtime.runIfWaitingForDebugger(
                            session_id=cdp_session_id,
                        ),
                        timeout=3.0,
                    )
                except Exception:
                    # browser-use の SessionManager も再開を試みる。ここで例外を
                    # 伝播してイベント処理や Agent 全体を停止させない。
                    pass

    async def _subscribe_fetch_for_new_targets(self, session) -> bool:
        """新 target を停止状態で検知し、初回リクエスト前に Fetch を有効化する。"""
        cdp_client = getattr(session, "_cdp_client_root", None)
        if cdp_client is None:
            return False
        if self._target_event_client is cdp_client:
            return True

        event_registry = None
        existing_handler = None
        target_registration = None
        try:
            event_registry = cdp_client._event_registry
            existing_handler = event_registry._handlers.get(
                "Target.attachedToTarget"
            )
            target_registration = cdp_client.register.Target

            # cdp_use 1.4.5 の EventRegistry はイベントごとに単一ハンドラ。
            # browser-use の SessionManager を壊さないよう既存ハンドラを包む。
            def _on_attached(event, event_session_id=None):
                def _forward_existing_handler():
                    if existing_handler is None:
                        return
                    return existing_handler(event, event_session_id)

                task = asyncio.create_task(
                    self._enable_fetch_for_attached_target(
                        cdp_client,
                        event,
                        before_resume=_forward_existing_handler,
                    )
                )
                self._target_event_tasks.add(task)
                task.add_done_callback(self._target_event_tasks.discard)
                return None

            target_registration.attachedToTarget(_on_attached)
            await cdp_client.send.Target.setAutoAttach(
                params={
                    "autoAttach": True,
                    "waitForDebuggerOnStart": True,
                    "flatten": True,
                }
            )
        except Exception:
            # 登録途中で失敗した場合は browser-use の元ハンドラを復元する。
            try:
                if existing_handler is not None:
                    target_registration.attachedToTarget(existing_handler)
                else:
                    event_registry.unregister("Target.attachedToTarget")
            except Exception:
                pass
            return False

        self._target_event_client = cdp_client
        return True

    async def _enable_request_scoped_headers(self, session) -> bool:
        """CDP Fetch でリクエスト単位のヘッダ付与を有効化する。

        失敗時は Fetch を無効化して False を返す。呼び出し側は従来の
        set_extra_headers 方式へフォールバックする。
        """
        if not self.extra_headers:
            return False

        required_apis = (
            "start",
            "get_current_page",
            "get_or_create_cdp_session",
            "agent_focus_target_id",
        )
        if not all(hasattr(session, name) for name in required_apis):
            return False

        try:
            # BrowserSession.start() は冪等。Fetch を有効化する target を先に確立する。
            await session.start()
            await session.get_current_page()
            enabled = await self._enable_fetch_for_current_target(session)
        except Exception:
            enabled = False

        if not enabled:
            self._request_scoped_headers = False
            return False

        self._request_scoped_headers = True
        # 利用可能な browser-use / cdp_use では新 target をイベントで即時設定する。
        # API 差異や登録失敗時も、各ステップの current target 確認を残して補完する。
        await self._subscribe_fetch_for_new_targets(session)
        return True

    async def _prepare_extra_headers_before_run(
        self, session, intended_url: str = ""
    ) -> None:
        """初期ナビゲーション前に対象ページを確立し、追加ヘッダを適用する。"""
        if not self.extra_headers:
            return
        required_apis = ("start", "get_current_page", "set_extra_headers")
        if not all(hasattr(session, name) for name in required_apis):
            # requirements-agent.txt が固定する browser-use 0.12.6 の BrowserSession は
            # set_extra_headers(CDP)を公開しているが、想定外の版では適用できない。
            # その場合に「未認証のまま静かに偵察する」のを避け、値は伏せて警告する。
            console.print(
                "[yellow]警告: この browser-use では追加リクエストヘッダを設定できず、"
                "Agent 偵察は指定した認証ヘッダなしで実行されます"
                "（requirements-agent.txt の browser-use 0.12.6 では対応）。[/yellow]"
            )
            return
        try:
            # BrowserSession.start() は冪等。先に target を確立しないと
            # set_extra_headers() が no-op になるため、この順序を維持する。
            await session.start()
            await session.get_current_page()
            await self._apply_extra_headers(session, intended_url)
        except Exception:
            # バージョン差異や起動失敗時も秘匿値を出さず Agent を継続する。
            await self._warn_header_application_failed()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(self) -> AgentScanResult:
        """エージェントスキャンを実行して結果を返す。"""
        console.print(Rule("[bold magenta] Agent Browser Scan [/bold magenta]", style="magenta"))
        console.print(
            f"  [bold]Target:[/bold] [cyan]{self.target_url}[/cyan]\n"
            f"  [bold]LLM:[/bold] {self.llm_provider} / {self.llm_model or '(default)'}\n"
            f"  [bold]Checks:[/bold] {', '.join(self.checks)}\n"
            f"  [bold]Max steps:[/bold] {self.max_steps}\n"
        )

        try:
            llm = _build_llm(self.llm_provider, self.llm_model, self.ollama_url,
                             base_url=self.llm_base_url)
        except RuntimeError as e:
            console.print(f"[red]LLM初期化エラー: {e}[/red]")
            return AgentScanResult(target_url=self.target_url, error=str(e))

        task = self._build_recon_task() if self.recon_mode else self._build_task()
        result = AgentScanResult(target_url=self.target_url)
        browser = None

        try:
            from browser_use import Agent, Browser

            def _build_legacy_browser():
                """ヘッダ無しの従来ブラウザ構築（API差異時のフォールバック兼用）。"""
                # browser_use ≥ 0.2 uses BrowserConfig; older versions accept direct kwargs.
                # BrowserConfig's disable_security properly disables SecurityWatchdog,
                # while the legacy Browser(disable_security=True) only affects Playwright flags.
                try:
                    from browser_use import BrowserConfig
                    return Browser(config=BrowserConfig(
                        headless=self.headless,
                        disable_security=True,
                    ))
                except (ImportError, TypeError):
                    return Browser(
                        headless=self.headless,
                        disable_security=True,
                    )

            # タスク文字列には SSRF/redirect ペイロードとして複数の URL が含まれる。
            # directly_open_url=True (デフォルト) は「複数 URL 検出 → スキップ」する仕様のため、
            # ブラウザが白紙ページのまま開始してしまう。
            # initial_actions で明示的に最初のページへ遷移する。
            # start_url is already scheme-normalized in __init__.
            start_url = self.login_url or self.target_url
            # ダブルナビゲートで about:blank → start_url → start_url という履歴を作る。
            # これにより go_back を実行しても start_url に戻るだけで
            # about:blank に落ちなくなる。
            initial_actions = [
                {"navigate": {"url": start_url, "new_tab": False}},
                {"navigate": {"url": start_url, "new_tab": False}},
            ]

            system_prompt = (
                _SECURITY_SYSTEM_PROMPT
                .replace("{SESSION_NONCE}", self._session_nonce)
                .replace("{SECURITY_SCOPE}", self._build_security_scope_policy())
            )
            agent_kwargs = dict(
                task=task,
                llm=llm,
                override_system_message=system_prompt,
                max_failures=5,
                use_vision=True,
                use_thinking=True,
                enable_planning=True,
                directly_open_url=False,           # 自動 URL 抽出を無効化 (複数 URL 問題を回避)
                initial_actions=initial_actions,   # 最初のページへ確実に遷移
                register_new_step_callback=self._on_step,
            )

            if self.extra_headers:
                # browser-use 0.12.6 の実 API:
                # BrowserSession(browser_profile=...) → Agent(browser_session=...)。
                # 注意: BrowserProfile.headers は「ブラウザ/CDP エンドポイントへの接続時
                # ヘッダ」であり、リモート/クラウド CDP ブラウザだと対象の Bearer が
                # ブラウザ提供者へ送られて漏れる。よって対象の認証ヘッダはここに載せず、
                # ページの HTTP リクエストには CDP set_extra_headers(下記)だけを使う。
                # 値はログやタスク文字列へ出さない。構築失敗時は従来経路へ戻す。
                try:
                    from browser_use import BrowserSession
                    from browser_use.browser.profile import BrowserProfile

                    browser_profile = BrowserProfile(
                        headless=self.headless,
                        disable_security=True,
                    )
                    browser = BrowserSession(browser_profile=browser_profile)
                    agent = Agent(browser_session=browser, **agent_kwargs)
                except Exception:
                    console.print(
                        "[yellow]追加HTTPヘッダをブラウザへ設定できなかったため、"
                        "従来構成で続行します。[/yellow]"
                    )
                    browser = _build_legacy_browser()
                    agent = Agent(browser=browser, **agent_kwargs)
            else:
                # ヘッダ未指定時は完全に従来どおりの構築経路を使う。
                browser = _build_legacy_browser()
                agent = Agent(browser=browser, **agent_kwargs)

            console.print("[dim]エージェント起動中...[/dim]")
            if self.monitor:
                await self.monitor.emit_status(
                    f"Agent Browser: {self.target_url} をスキャン中", "running"
                )

            self._request_scoped_headers = (
                await self._enable_request_scoped_headers(browser)
            )
            if not self._request_scoped_headers:
                await self._prepare_extra_headers_before_run(browser, start_url)

            if self.extra_headers and self._request_scoped_headers:
                async def _enable_fetch_on_step(_agent):
                    # イベント購読が使えない版や CDP 再接続後も、ポップアップや
                    # 新規タブの current target を各ステップで補完する。
                    await self._subscribe_fetch_for_new_targets(browser)
                    await self._enable_fetch_for_current_target(browser)

                history = await agent.run(
                    max_steps=self.max_steps,
                    on_step_start=_enable_fetch_on_step,
                )
            elif self.extra_headers and hasattr(browser, "set_extra_headers"):
                async def _apply_headers_on_step(_agent):
                    await self._apply_extra_headers(browser)

                history = await agent.run(
                    max_steps=self.max_steps,
                    on_step_start=_apply_headers_on_step,
                )
            else:
                history = await agent.run(max_steps=self.max_steps)

            result.steps_taken = self._step_count
            result.success = history.is_successful()

            # final_result() が構造化テキストを返す
            final_text = history.final_result() or ""
            result.final_summary = final_text

            # 全ステップのテキストを結合してファインディングを解析
            all_text = "\n".join(
                str(item) for item in (history.extracted_content() or [])
            )
            all_text += "\n" + final_text

            # recon_mode: PAGE_FOUND: <url> パターンを解析して memory に追加
            if self.recon_mode:
                page_found_re = re.compile(r"PAGE_FOUND:\s*(https?://\S+)", re.IGNORECASE)
                for m in page_found_re.finditer(all_text):
                    u = m.group(1).rstrip(".,;)")
                    if u not in self._memory.visited_urls:
                        self._memory.visited_urls.append(u)
                result.memory = self._memory

            result.findings = _parse_findings_from_text(all_text, nonce=self._session_nonce)

            # エラーがあればログに記録 (None エントリを除外)
            errors = [e for e in (history.errors() or []) if e is not None]
            if errors:
                console.print(
                    f"  [yellow]エージェントエラー {len(errors)} 件:[/yellow]"
                )
                for err in errors[:3]:
                    console.print(f"    [dim]{str(err)[:120]}[/dim]")

        except ImportError:
            result.error = "browser-use がインストールされていません。pip install browser-use を実行してください。"
            console.print(f"[red]{result.error}[/red]")
            return result
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            result.error = str(exc)
            console.print(f"[red]エージェントスキャンエラー: {exc}[/red]")
        finally:
            if browser is not None:
                try:
                    # BrowserSession は close() を持たない — stop() が正しい。
                    # Agent task の cancel 時もここを通し、プローブを確実に止める。
                    await browser.stop()
                except Exception as exc:
                    console.print(f"[yellow]ブラウザ終了エラー: {exc}[/yellow]")

        # サマリー表示
        console.print(Rule("[bold magenta] Agent Scan Complete [/bold magenta]", style="magenta"))
        if result.findings:
            console.print(
                f"  [bold green]{len(result.findings)} 件の脆弱性を検出[/bold green]"
            )
            for f in result.findings:
                sev_color = {
                    "critical": "bold red",
                    "high": "red",
                    "medium": "yellow",
                    "low": "cyan",
                }.get(f.severity, "white")
                console.print(
                    f"    [{sev_color}][{f.severity.upper()}][/{sev_color}] "
                    f"{f.check_type.upper()} @ {f.url} [{f.field_name}]"
                )
        else:
            console.print("  [dim]脆弱性は検出されませんでした。[/dim]")

        if self.monitor:
            await self.monitor.emit_status(
                f"Agent Browser 完了: {len(result.findings)} 件検出", "done"
            )

        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_task(self) -> str:
        # BUG-2 fix: Include concrete payloads per check type so the LLM
        # knows exactly what to test, not just vague "relevant payloads".
        _PAYLOADS: dict[str, list[str]] = {
            "xss":            ['<script>alert(1)</script>',
                               '"><img src=x onerror=alert(1)>',
                               "'><svg onload=alert(1)>"],
            "sqli":           ["' OR '1'='1' --",
                               "' OR 1=1--",
                               "admin'--",
                               "' UNION SELECT NULL--"],
            "ssti":           ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "{{config}}"],
            "os":             ["; id", "| id", "; whoami", "&& id"],
            "path_traversal": ["../../etc/passwd",
                               "....//....//etc/passwd",
                               "%2e%2e%2fetc%2fpasswd"],
            "ssrf":           ["http://169.254.169.254/latest/meta-data/",
                               "http://127.0.0.1/",
                               "http://[::1]/"],
            "open_redirect":  ["https://evil.com",
                               "//evil.com",
                               "/\\evil.com"],
            "header_injection": ["foo\r\nSet-Cookie: evil=1",
                                 "foo\r\nX-Injected: bar"],
            "csrf":           ["(check if form has no CSRF token field)"],
        }

        checks_section = ""
        for c in self.checks:
            desc = _CHECK_DESCRIPTIONS.get(c, c)
            payloads = _PAYLOADS.get(c, [])
            payload_str = (
                "\n      Try: " + " | ".join(payloads[:3])
                if payloads and payloads[0] != "(check if form has no CSRF token field)"
                else ""
            )
            checks_section += f"  - {desc}{payload_str}\n"

        auth_section = ""
        if self.login_url and self.auth_user and self.auth_pass:
            auth_section = (
                f"\n## Step 0: Authentication\n"
                f"Before testing, log in at: {self.login_url}\n"
                f"Username: {self.auth_user}\n"
                f"Password: {self.auth_pass}\n"
                f"Confirm you are logged in, then proceed to test authenticated pages.\n"
            )

        # BUG-1 fix: format block uses newlines, matching _VULN_BLOCK_RE exactly.
        report_format = (
            "VULNERABILITY FOUND:\n"
            "Type: <xss|sqli|ssti|os|path_traversal|ssrf|open_redirect|csrf|header_injection>\n"
            "Severity: <critical|high|medium|low>\n"
            "URL: <exact URL of the vulnerable page>\n"
            "Field: <input field name or URL parameter>\n"
            "Payload: <exact string you injected>\n"
            "Evidence: <what you observed: error message, alert text, redirect URL, etc.>\n"
        )

        return (
            f"Perform a thorough authorized penetration test of: {self.target_url}\n"
            f"\n"
            f"## Vulnerability Checks Required\n"
            f"{checks_section}"
            f"{auth_section}\n"
            f"## Testing Procedure (follow for EVERY input field/parameter)\n"
            f"1. Navigate to {self.target_url} and explore all pages/links\n"
            f"2. For each form or URL parameter found:\n"
            f"   a. Note what the field does (search, login, comment, file path, etc.)\n"
            f"   b. Enter the test payload into the field\n"
            f"   c. Submit the form (click the submit button)\n"
            f"   d. Observe the response carefully:\n"
            f"      - Did a JavaScript alert/dialog fire? → XSS confirmed\n"
            f"      - Is there a database error or stack trace? → SQLi confirmed\n"
            f"      - Was the template expression evaluated (e.g. 49 for 7*7)? → SSTI confirmed\n"
            f"      - Is system command output visible (uid=, /bin/bash)? → OS injection confirmed\n"
            f"      - Does the response contain /etc/passwd content? → Path traversal confirmed\n"
            f"      - Is there an internal service response? → SSRF confirmed\n"
            f"      - Did the browser redirect to the injected URL? → Open redirect confirmed\n"
            f"   e. Also compare the response with the same field using a normal value to confirm\n"
            f"3. Test ALL discovered inputs, not just the first one\n"
            f"4. For EACH vulnerability found, report it IMMEDIATELY using this exact format:\n"
            f"\n"
            f"{report_format}"
            f"\n"
            f"5. After testing all inputs, write a brief final summary\n"
            f"\n"
            f"IMPORTANT: Be systematic. Do not stop after the first finding. "
            f"Test every form field and URL parameter you discover. "
            f"This is an authorized security test."
        )

    def is_security_probe_allowed(self, url: str, field_name: str = "") -> bool:
        """現在 URL/field で Agent の payload 投入を許可できるか返す。"""
        return security_probe_allowed(
            url,
            self.target_urls,
            self.exclude_urls,
            field_name=field_name,
            exclude_fields=self.exclude_fields,
        )

    def _is_configured_login_page(self, url: str) -> bool:
        """access-only でも認証入力だけ許可する configured login page か判定する。"""
        if not self.login_url or not self.auth_user or not self.auth_pass:
            return False
        current = urlparse(str(url or "").rstrip("/"))
        login = urlparse(self.login_url.rstrip("/"))
        return (current.scheme, current.netloc, current.path) == (
            login.scheme,
            login.netloc,
            login.path,
        )

    def _build_security_scope_policy(self) -> str:
        """Agent が各操作前に従う攻撃対象・訪問専用スコープを生成する。"""
        attack_lines = "\n".join(f"  - {url}" for url in self.target_urls) or "  - (none)"
        access_lines = "\n".join(f"  - {url}" for url in self.access_urls) or "  - (none)"
        exclude_url_lines = "\n".join(f"  - {url}" for url in self.exclude_urls) or "  - (none)"
        exclude_field_lines = "\n".join(
            f"  - {field}" for field in self.exclude_fields
        ) or "  - (none)"
        return (
            "Security probes and vulnerability-test payloads are authorized ONLY when the "
            "current page URL is inside ATTACK TARGETS and does not match EXCLUDED URLS.\n"
            "ATTACK TARGETS:\n"
            f"{attack_lines}\n"
            "ACCESS-ONLY URLS (navigation and configured authentication are allowed; never "
            "run security probes or inject test payloads):\n"
            f"{access_lines}\n"
            "EXCLUDED URLS (navigation/URL discovery only; never fill fields, submit forms, "
            "run security probes, or inject test payloads):\n"
            f"{exclude_url_lines}\n"
            "EXCLUDED FIELDS (never inject security-test payloads):\n"
            f"{exclude_field_lines}\n"
            "Pages outside all listed attack targets may be visited for URL discovery only. "
            "Before every fill/type/submit action used as a security test, verify the current "
            "URL and field against this policy. If it is not authorized, skip the probe and "
            "continue harmless navigation."
        )

    def _build_recon_task(self) -> str:
        """URL 発見を優先しつつ、探索中の脆弱性仮説も報告するタスクを生成する。"""
        auth_section = ""
        if self.login_url and self.auth_user and self.auth_pass:
            auth_section = (
                f"\n## Step 0: Authentication\n"
                f"Log in at: {self.login_url}\n"
                f"Username: {self.auth_user}\n"
                f"Password: {self.auth_pass}\n"
                f"Confirm login succeeded before proceeding.\n"
            )

        checks_section = "\n".join(
            f"  - {_CHECK_DESCRIPTIONS.get(check, check)}"
            for check in self.checks
        )

        return (
            f"You are a web crawler performing site reconnaissance on: {self.target_url}\n"
            f"\n"
            f"## Objective\n"
            f"Explore the entire website to discover all reachable pages and URL patterns.\n"
            f"URL discovery is the primary objective. Do not perform an exhaustive payload sweep.\n"
            f"{auth_section}"
            f"\n"
            f"## Instructions\n"
            f"1. Start at {self.target_url}\n"
            f"2. Click links and navigate menus for discovery. Submit harmless dummy data only "
            f"inside ATTACK TARGETS; the configured login form is the only access-only exception.\n"
            f"3. For each unique page you reach, output EXACTLY this line:\n"
            f"   PAGE_FOUND: <full URL>\n"
            f"4. While exploring, if an input or response suggests one of the checks below, "
            f"you may use a targeted probe to investigate it:\n"
            f"{checks_section}\n"
            f"5. Report every vulnerability you find using the exact VULNERABILITY FOUND "
            f"format required by the system message. Keep reporting PAGE_FOUND lines too.\n"
            f"6. Continue until you have explored all reachable pages or reached the step limit\n"
            f"7. After exploring, write a brief summary of the site structure and findings\n"
            f"\n"
            f"IMPORTANT: Output PAGE_FOUND: <url> for EVERY unique page you visit.\n"
            f"Reconnaissance remains the priority; a targeted security check must not stop site mapping."
        )

    async def _on_step(self, state, output, step_num: int) -> None:
        """各ステップ実行時のコールバック。"""
        self._step_count = step_num

        # browser-use の new-step callback は model action の実行前に呼ばれる。
        # 対象外/access-only/exclude 上では入力・JS・upload 等を action 列から除去し、
        # prompt 指示を外した場合にも payload 投入を実行時に止める。外部 IdP 等の
        # configured login page だけは認証情報の入力を許可する。
        current_url = str(getattr(state, "url", "") or "")
        try:
            planned_actions = (
                output.action if isinstance(output.action, list) else [output.action]
            ) if getattr(output, "action", None) else []
            allow_mutation = self.is_security_probe_allowed(current_url)
            allowed_auth_values = (
                (self.auth_user, self.auth_pass)
                if not allow_mutation and self._is_configured_login_page(current_url)
                else ()
            )
            filtered_actions, blocked_count = filter_probe_actions(
                planned_actions,
                allow_mutation=allow_mutation,
                allowed_auth_values=allowed_auth_values,
            )
            if blocked_count:
                output.action = filtered_actions
                console.print(
                    f"  [yellow][Agent Scope] {current_url or '(URL不明)'} で "
                    f"probe 操作を {blocked_count} 件ブロックしました[/yellow]"
                )
                if self.monitor:
                    try:
                        await self.monitor.emit_status(
                            f"Agent scope: 対象外ページの probe 操作を "
                            f"{blocked_count} 件ブロック",
                            "running",
                        )
                    except Exception:
                        pass
        except Exception:
            # action 形式が想定外でも callback 自体で Agent を停止させない。
            pass

        # ステップ内容を取得
        action_desc = ""
        try:
            if hasattr(output, "action") and output.action:
                actions = output.action if isinstance(output.action, list) else [output.action]
                action_desc = " / ".join(
                    str(a)[:60] for a in actions[:2]
                )
        except Exception:
            pass

        # about:blank 検出: エージェントが誤って空白ページに遷移した場合に警告
        try:
            current_url = str(getattr(state, "url", "") or "")
            if current_url in ("about:blank", "chrome://newtab/", ""):
                console.print(
                    f"  [bold yellow][Agent Step {step_num}] ⚠️  about:blank 検出 — "
                    f"エージェントは navigate アクションで {self.target_url} に戻ってください[/bold yellow]"
                )
                if self.monitor:
                    try:
                        await self.monitor.emit_status(
                            f"⚠️ about:blank 検出 (Step {step_num}) — エージェントが再ナビゲートします",
                            "running",
                        )
                    except Exception:
                        pass
        except Exception:
            pass

        # 現在の URL を memory に追記 (recon_mode)
        if self.recon_mode:
            try:
                if hasattr(state, "url") and state.url:
                    url_val = str(state.url)
                    if url_val.startswith("http") and url_val not in self._memory.visited_urls:
                        self._memory.visited_urls.append(url_val)
            except Exception:
                pass

        console.print(
            f"  [dim magenta][Agent Step {step_num}][/dim magenta] {action_desc[:80]}"
        )
        if self.monitor:
            try:
                await self.monitor.emit_status(
                    f"Agent Step {step_num}: {action_desc[:60]}", "running"
                )
            except Exception:
                pass
