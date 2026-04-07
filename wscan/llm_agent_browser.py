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

_SECURITY_SYSTEM_PROMPT = """You are an expert web application penetration tester conducting an authorized security assessment.

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
When you discover a vulnerability, state clearly:
```
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


# ── LLM ファクトリ ──────────────────────────────────────────────────────────

def _build_llm(provider: str, model: str, ollama_url: str = "http://localhost:11434"):
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

    elif provider == "openai":
        from browser_use.llm import ChatOpenAI
        import os
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY 環境変数が設定されていません。")
        return ChatOpenAI(model=model or "gpt-4o-mini", api_key=api_key)

    elif provider == "ollama":
        from browser_use.llm import ChatOllama
        # ollama_url は "http://localhost:11434" 形式
        host = ollama_url.rstrip("/")
        return ChatOllama(model=model or "llama3", host=host)

    else:
        raise RuntimeError(
            f"エージェントモードは provider='{provider}' に対応していません。"
            f" claude / openai / ollama を指定してください。"
        )


# ── ファインディング抽出 ────────────────────────────────────────────────────

_VULN_BLOCK_RE = re.compile(
    r"VULNERABILITY FOUND:\s*"
    r"Type:\s*(?P<type>[^\n]+)\n"
    r"Severity:\s*(?P<severity>[^\n]+)\n"
    r"URL:\s*(?P<url>[^\n]+)\n"
    r"Field:\s*(?P<field>[^\n]+)\n"
    r"Payload:\s*(?P<payload>[^\n]+)\n"
    r"Evidence:\s*(?P<evidence>(?:.+\n?)+?)(?=\nVULNERABILITY FOUND:|$)",
    re.IGNORECASE,
)

def _parse_findings_from_text(text: str) -> list[AgentFinding]:
    """エージェントの出力テキストから VULNERABILITY FOUND ブロックを解析する。"""
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

    for m in _VULN_BLOCK_RE.finditer(text):
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
    ):
        self.target_url = target_url.rstrip("/")
        self.llm_provider = llm_provider
        self.llm_model = llm_model
        self.ollama_url = ollama_url
        self.checks = checks or ["xss", "sqli", "ssti", "os", "path_traversal", "ssrf"]
        self.headless = headless
        self.auth_user = auth_user
        self.auth_pass = auth_pass
        self.login_url = login_url
        self.max_steps = max_steps
        self.monitor = monitor
        self._step_count = 0

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
            llm = _build_llm(self.llm_provider, self.llm_model, self.ollama_url)
        except RuntimeError as e:
            console.print(f"[red]LLM初期化エラー: {e}[/red]")
            return AgentScanResult(target_url=self.target_url, error=str(e))

        task = self._build_task()
        result = AgentScanResult(target_url=self.target_url)

        try:
            from browser_use import Agent, Browser

            browser = Browser(
                headless=self.headless,
                disable_security=True,
            )

            agent = Agent(
                task=task,
                llm=llm,
                browser=browser,
                override_system_message=_SECURITY_SYSTEM_PROMPT,
                max_failures=5,
                use_vision=True,
                use_thinking=True,
                enable_planning=True,
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

            result.findings = _parse_findings_from_text(all_text)

            # エラーがあればログに記録
            errors = history.errors()
            if errors:
                console.print(
                    f"  [yellow]エージェントエラー {len(errors)} 件:[/yellow]"
                )
                for err in errors[:3]:
                    console.print(f"    [dim]{str(err)[:120]}[/dim]")

            await browser.close()

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
