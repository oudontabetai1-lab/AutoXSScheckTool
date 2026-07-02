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
import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING

from rich.console import Console
from rich.rule import Rule

if TYPE_CHECKING:
    from wscan.monitor import MonitorServer

console = Console()

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

## Your Capabilities
You can control a real web browser. Use it to:
- Navigate to URLs
- Click buttons and links
- Fill in form fields with test payloads
- Read page content and HTTP responses
- Take screenshots to document findings

## Testing Methodology
For EACH form or URL parameter you discover:
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

Be thorough but efficient. Test all discovered inputs. Do not stop after finding one vulnerability."""


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

    def to_dict(self) -> dict:
        return {
            "check_type": self.check_type,
            "severity": self.severity,
            "url": self.url,
            "field_name": self.field_name,
            "payload": self.payload,
            "evidence": self.evidence,
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
        api_key = llm_endpoint.resolve_api_key()
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
    recon_mode      : True にすると脆弱性テストをせず URL 偵察のみ行う
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
    ):
        # Ensure URLs carry a scheme — CDP rejects scheme-less URLs with error -32000,
        # and browser_use's SecurityWatchdog raises ValueError parsing them.
        def _normalize_url(u: str) -> str:
            u = u.rstrip("/")
            if u and not re.match(r'^https?://', u, re.IGNORECASE):
                u = 'http://' + u
            return u

        self.target_url = _normalize_url(target_url)
        self.llm_provider = llm_provider
        self.llm_model = llm_model
        self.ollama_url = ollama_url
        self.checks = checks or ["xss", "sqli", "ssti", "os", "path_traversal", "ssrf"]
        self.headless = headless
        self.auth_user = auth_user
        self.auth_pass = auth_pass
        self.login_url = _normalize_url(login_url) if login_url else login_url
        self.max_steps = max_steps
        self.monitor = monitor
        self.recon_mode = recon_mode
        self.llm_base_url = llm_base_url
        self._step_count = 0
        self._memory = AgentMemory()
        self._session_nonce = secrets.token_urlsafe(16)

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

        try:
            from browser_use import Agent, Browser

            # browser_use ≥ 0.2 uses BrowserConfig; older versions accept direct kwargs.
            # BrowserConfig's disable_security properly disables SecurityWatchdog,
            # while the legacy Browser(disable_security=True) only affects Playwright flags.
            try:
                from browser_use import BrowserConfig
                browser = Browser(config=BrowserConfig(
                    headless=self.headless,
                    disable_security=True,
                ))
            except (ImportError, TypeError):
                browser = Browser(
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

            system_prompt = _SECURITY_SYSTEM_PROMPT.replace(
                "{SESSION_NONCE}", self._session_nonce
            )
            agent = Agent(
                task=task,
                llm=llm,
                browser=browser,
                override_system_message=system_prompt,
                max_failures=5,
                use_vision=True,
                use_thinking=True,
                enable_planning=True,
                directly_open_url=False,           # 自動 URL 抽出を無効化 (複数 URL 問題を回避)
                initial_actions=initial_actions,   # 最初のページへ確実に遷移
                register_new_step_callback=self._on_step,
            )

            console.print("[dim]エージェント起動中...[/dim]")
            if self.monitor:
                await self.monitor.emit_status(
                    f"Agent Browser: {self.target_url} をスキャン中", "running"
                )

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

            # BrowserSession は close() を持たない — stop() が正しい
            await browser.stop()

        except ImportError:
            result.error = "browser-use がインストールされていません。pip install browser-use を実行してください。"
            console.print(f"[red]{result.error}[/red]")
            return result
        except Exception as exc:
            result.error = str(exc)
            console.print(f"[red]エージェントスキャンエラー: {exc}[/red]")

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

    def _build_recon_task(self) -> str:
        """偵察専用タスク文字列を生成する。脆弱性テストは行わず URL 発見に特化。"""
        auth_section = ""
        if self.login_url and self.auth_user and self.auth_pass:
            auth_section = (
                f"\n## Step 0: Authentication\n"
                f"Log in at: {self.login_url}\n"
                f"Username: {self.auth_user}\n"
                f"Password: {self.auth_pass}\n"
                f"Confirm login succeeded before proceeding.\n"
            )

        return (
            f"You are a web crawler performing site reconnaissance on: {self.target_url}\n"
            f"\n"
            f"## Objective\n"
            f"Explore the entire website to discover all reachable pages and URL patterns.\n"
            f"Do NOT inject payloads or test for vulnerabilities.\n"
            f"{auth_section}"
            f"\n"
            f"## Instructions\n"
            f"1. Start at {self.target_url}\n"
            f"2. Click every link, navigate every menu, submit forms with harmless dummy data\n"
            f"3. For each unique page you reach, output EXACTLY this line:\n"
            f"   PAGE_FOUND: <full URL>\n"
            f"4. Continue until you have explored all reachable pages or reached the step limit\n"
            f"5. After exploring, write a brief summary of the site structure\n"
            f"\n"
            f"IMPORTANT: Output PAGE_FOUND: <url> for EVERY unique page you visit.\n"
            f"This is site mapping, not penetration testing."
        )

    async def _on_step(self, state, output, step_num: int) -> None:
        """各ステップ実行時のコールバック。"""
        self._step_count = step_num

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
