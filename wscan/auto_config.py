"""
Auto-Config Wizard (LLM-driven scan configuration)
====================================================
LLM 設定が完了した後、スキャン対象の説明・禁止事項・必須検査項目を
ユーザーからヒアリングし、LLM に最適な設定を生成させます。
生成された設定はレビュー・編集後にスキャンエンジンへ反映されます。
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich import box as rbox

console = Console()

# ── 利用可能なチェック一覧 ──────────────────────────────────────────
_ALL_CHECKS = [
    "sqli", "xss", "dom_xss", "os", "ssti", "path_traversal",
    "csrf", "header_injection", "mail_header", "open_redirect",
    "clickjacking", "session", "privesc",
]

# ── LLM へのシステムプロンプト ─────────────────────────────────────
_SYSTEM_PROMPT = """\
あなたはWebセキュリティスキャナー「WScan」の設定アシスタントです。
ユーザーから以下の情報を受け取り、最適なスキャン設定をJSON形式で返してください。

利用可能なチェック一覧:
  sqli           - SQLインジェクション
  xss            - 反射型・格納型XSS
  dom_xss        - DOM-based XSS (Playwrightでシンクフック)
  os             - OSコマンドインジェクション
  ssti           - サーバーサイドテンプレートインジェクション
  path_traversal - パストラバーサル
  csrf           - CSRF
  header_injection - HTTPヘッダーインジェクション
  mail_header    - メールヘッダーインジェクション
  open_redirect  - オープンリダイレクト
  clickjacking   - クリックジャッキング
  session        - セッション管理の問題
  privesc        - 権限昇格・未認証アクセス

必ず以下のJSON形式のみ返してください（コードブロック不要）:
{
  "checks": ["sqli", "xss", ...],
  "depth": 2,
  "headless": false,
  "skip_registration": true,
  "exclude_urls": [],
  "exclude_fields": [],
  "max_forms": 50,
  "timeout": 30,
  "notes": "設定の根拠・注意事項",
  "warnings": "禁止事項に関する警告（守るべき点）",
  "prohibited_reminder": "禁止事項の再確認メッセージ"
}
"""


@dataclass
class WizardResult:
    """Auto-config wizard が生成した設定。"""
    checks: list[str] = field(default_factory=lambda: ["sqli", "xss", "os"])
    depth: int = 2
    headless: bool = False
    skip_registration: bool = True
    exclude_urls: list[str] = field(default_factory=list)
    exclude_fields: list[str] = field(default_factory=list)
    max_forms: int = 50
    timeout: int = 30
    notes: str = ""
    warnings: str = ""
    prohibited_reminder: str = ""


def _ask(prompt: str, default: str = "") -> str:
    """標準入力からユーザー入力を取得。Ctrl+C / EOF は空文字列で返す。"""
    hint = f" [{default}]" if default else ""
    try:
        val = input(f"{prompt}{hint}: ").strip()
        return val if val else default
    except (KeyboardInterrupt, EOFError):
        return default


def _ask_multiline(prompt: str) -> str:
    """複数行入力 (空行で終了)。"""
    console.print(f"  [dim]{prompt} (空行で完了)[/dim]")
    lines: list[str] = []
    while True:
        try:
            line = input("    > ").strip()
        except (KeyboardInterrupt, EOFError):
            break
        if not line:
            break
        lines.append(line)
    return "\n".join(lines)


# ── LLM 呼び出し ───────────────────────────────────────────────────

async def _call_llm(payload_gen, prompt: str) -> Optional[str]:
    """PayloadGenerator のバックエンドを使ってテキストを生成する。"""
    provider = payload_gen.provider
    try:
        if provider == "claude":
            client = payload_gen._get_anthropic_client()
            if not client:
                return None
            import asyncio as _aio
            loop = _aio.get_event_loop()
            model = getattr(payload_gen, "claude_model", "claude-haiku-4-5-20251001")
            response = await loop.run_in_executor(
                None,
                lambda: client.messages.create(
                    model=model,
                    max_tokens=1200,
                    system=_SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt}],
                ),
            )
            return response.content[0].text

        elif provider == "openai":
            import os, httpx
            api_key = os.environ.get("OPENAI_API_KEY", "")
            if not api_key:
                return None
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {api_key}"},
                    json={
                        "model": payload_gen.openai_model,
                        "messages": [
                            {"role": "system", "content": _SYSTEM_PROMPT},
                            {"role": "user",   "content": prompt},
                        ],
                        "max_tokens": 1200,
                    },
                )
                if resp.status_code == 200:
                    return resp.json()["choices"][0]["message"]["content"]

        elif provider == "gemini":
            import os, httpx
            api_key = os.environ.get("GEMINI_API_KEY", "")
            if not api_key:
                return None
            url = (
                f"https://generativelanguage.googleapis.com/v1beta/models/"
                f"{payload_gen.gemini_model}:generateContent?key={api_key}"
            )
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(url, json={
                    "contents": [{"parts": [{"text": _SYSTEM_PROMPT + "\n\n" + prompt}]}]
                })
                if resp.status_code == 200:
                    return resp.json()["candidates"][0]["content"]["parts"][0]["text"]

        else:
            # Ollama
            import httpx
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    f"{payload_gen.ollama_url}/api/generate",
                    json={
                        "model": payload_gen.ollama_model,
                        "prompt": _SYSTEM_PROMPT + "\n\n" + prompt,
                        "stream": False,
                        "options": {"num_predict": 1200, "temperature": 0.3},
                    },
                )
                if resp.status_code == 200:
                    return resp.json().get("response", "")
    except Exception as e:
        console.print(f"  [yellow][AutoConfig] LLM エラー: {e}[/yellow]")
    return None


def _parse_llm_response(text: str) -> Optional[dict]:
    """LLM レスポンスから JSON を抽出してパース。"""
    # コードブロック除去
    text = re.sub(r"```(?:json)?", "", text).strip()
    # JSON 配列/オブジェクト抽出
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group())
    except json.JSONDecodeError:
        return None


def _build_result(data: dict) -> WizardResult:
    """LLM が返した dict を WizardResult に変換。"""
    checks = [c for c in data.get("checks", ["sqli", "xss", "os"]) if c in _ALL_CHECKS]
    if not checks:
        checks = ["sqli", "xss", "os"]
    return WizardResult(
        checks=checks,
        depth=max(1, min(5, int(data.get("depth", 2)))),
        headless=bool(data.get("headless", False)),
        skip_registration=bool(data.get("skip_registration", True)),
        exclude_urls=list(data.get("exclude_urls", [])),
        exclude_fields=list(data.get("exclude_fields", [])),
        max_forms=max(1, min(200, int(data.get("max_forms", 50)))),
        timeout=max(5, min(120, int(data.get("timeout", 30)))),
        notes=str(data.get("notes", "")),
        warnings=str(data.get("warnings", "")),
        prohibited_reminder=str(data.get("prohibited_reminder", "")),
    )


# ── 結果表示 ────────────────────────────────────────────────────────

def _print_result(result: WizardResult) -> None:
    """生成された設定を見やすく表示。"""
    console.print(Rule("[bold cyan] 生成された設定 [/bold cyan]", style="cyan"))

    t = Table(show_header=False, box=rbox.SIMPLE, padding=(0, 2))
    t.add_column("項目",  style="bold cyan", no_wrap=True)
    t.add_column("値",    style="white")

    t.add_row("検査項目 (checks)",    " ".join(result.checks))
    t.add_row("クロール深度 (depth)", str(result.depth))
    t.add_row("ヘッドレス",           "はい" if result.headless else "いいえ")
    t.add_row("登録フォームスキップ",  "はい" if result.skip_registration else "いいえ")
    t.add_row("最大フォーム数",        str(result.max_forms))
    t.add_row("タイムアウト (秒)",     str(result.timeout))
    if result.exclude_urls:
        t.add_row("除外URL",           "\n".join(result.exclude_urls))
    if result.exclude_fields:
        t.add_row("除外フィールド",    "\n".join(result.exclude_fields))
    console.print(t)

    if result.notes:
        console.print(Panel(
            result.notes, title="[cyan]📝 設定の根拠", border_style="cyan", padding=(0, 2)
        ))
    if result.warnings:
        console.print(Panel(
            result.warnings, title="[yellow]⚠️  注意事項", border_style="yellow", padding=(0, 2)
        ))
    if result.prohibited_reminder:
        console.print(Panel(
            result.prohibited_reminder,
            title="[red]🚫 禁止事項リマインダー", border_style="red", padding=(0, 2)
        ))


# ── 対話的編集 ──────────────────────────────────────────────────────

def _interactive_edit(result: WizardResult) -> WizardResult:
    """ユーザーが設定を手動で調整できる対話エディタ。"""
    console.print(Rule("[bold yellow] 設定の確認・編集 [/bold yellow]", style="yellow"))
    console.print("  [dim]各項目を確認し、変更する場合は新しい値を入力してください。[/dim]")
    console.print("  [dim]変更不要なら Enter をそのまま押してください。[/dim]\n")

    # ── checks ──────────────────────────────────────────────────
    console.print(f"  利用可能: [dim]{' '.join(_ALL_CHECKS)}[/dim]")
    raw = _ask("  検査項目 (スペース区切り)", " ".join(result.checks))
    new_checks = [c for c in raw.split() if c in _ALL_CHECKS]
    if new_checks:
        result.checks = new_checks

    # ── depth ───────────────────────────────────────────────────
    raw = _ask("  クロール深度 (1〜5)", str(result.depth))
    if raw.isdigit():
        result.depth = max(1, min(5, int(raw)))

    # ── headless ────────────────────────────────────────────────
    raw = _ask("  ヘッドレスモード (y/n)", "y" if result.headless else "n")
    result.headless = raw.lower().startswith("y")

    # ── skip_registration ───────────────────────────────────────
    raw = _ask("  登録フォームをスキップ (y/n)", "y" if result.skip_registration else "n")
    result.skip_registration = raw.lower().startswith("y")

    # ── max_forms ───────────────────────────────────────────────
    raw = _ask("  最大フォーム数", str(result.max_forms))
    if raw.isdigit():
        result.max_forms = max(1, min(200, int(raw)))

    # ── timeout ─────────────────────────────────────────────────
    raw = _ask("  タイムアウト (秒)", str(result.timeout))
    if raw.isdigit():
        result.timeout = max(5, min(120, int(raw)))

    # ── exclude_urls ────────────────────────────────────────────
    cur = " ".join(result.exclude_urls)
    raw = _ask("  除外URL (スペース区切り, 空=変更なし)", cur)
    if raw:
        result.exclude_urls = raw.split()

    # ── exclude_fields ──────────────────────────────────────────
    cur = " ".join(result.exclude_fields)
    raw = _ask("  除外フィールド名 (スペース区切り, 空=変更なし)", cur)
    if raw:
        result.exclude_fields = raw.split()

    return result


# ── メインエントリポイント ───────────────────────────────────────────

async def run_wizard(payload_gen) -> Optional[WizardResult]:
    """
    スキャン設定自動生成ウィザードを実行し、確定した WizardResult を返す。
    ユーザーがキャンセルした場合は None を返す。

    Parameters
    ----------
    payload_gen : PayloadGenerator
        LLM 呼び出しに使うペイロードジェネレーター (プロバイダー設定を保持)。
    """
    console.print(Rule("[bold magenta] 🤖 スキャン設定自動生成ウィザード [/bold magenta]", style="magenta"))
    console.print(
        "  LLM があなたの要件に基づいて最適なスキャン設定を生成します。\n"
        "  Ctrl+C でキャンセルしてデフォルト設定で続行できます。\n"
    )

    # ── LLM の疎通確認 ──────────────────────────────────────────
    if not await payload_gen._check_llm_available():
        console.print(
            "  [yellow]⚠ LLM が利用できないため Auto-Config をスキップします。"
            " デフォルト設定で続行します。[/yellow]"
        )
        return None

    # ── ヒアリング ───────────────────────────────────────────────
    console.print("  [bold]▌ ステップ 1/3 — スキャン対象の説明[/bold]")
    target_desc = _ask_multiline(
        "対象システムを説明してください (例: ログイン機能と管理画面を持つECサイト)"
    )
    if not target_desc:
        target_desc = "一般的なWebアプリケーション"

    console.print("\n  [bold]▌ ステップ 2/3 — 禁止事項[/bold]")
    console.print(
        "  [dim]スキャン中に行ってはいけない操作を記載してください。[/dim]\n"
        "  [dim]例: アカウント新規登録の実行、データの削除、メール送信[/dim]"
    )
    prohibited = _ask_multiline("禁止事項 (空欄=特になし)")

    console.print("\n  [bold]▌ ステップ 3/3 — 必須検査項目[/bold]")
    console.print(
        f"  [dim]利用可能: {' '.join(_ALL_CHECKS)}[/dim]\n"
        "  [dim]例: XSS と SQLi は必ず実施、認証関連の検査を重点的に[/dim]"
    )
    required = _ask_multiline("必須検査項目・重点事項 (空欄=LLMに任せる)")

    # ── LLM へ送信 ──────────────────────────────────────────────
    console.print("\n  [dim cyan]LLM に設定を生成させています...[/dim cyan]")

    user_prompt = f"""以下の条件でWebセキュリティスキャン設定を生成してください。

【スキャン対象の説明】
{target_desc}

【禁止事項】
{prohibited if prohibited else "特になし"}

【必須検査項目・重点事項】
{required if required else "LLM の判断に任せる"}

上記を踏まえて最適な設定JSONを返してください。
禁止事項が含まれる場合は warnings と prohibited_reminder に必ず明記してください。"""

    llm_text = await _call_llm(payload_gen, user_prompt)

    if not llm_text:
        console.print(
            "  [yellow]⚠ LLM から応答がありませんでした。デフォルト設定で続行します。[/yellow]"
        )
        return None

    data = _parse_llm_response(llm_text)
    if not data:
        console.print(
            "  [yellow]⚠ LLM 応答のパースに失敗しました。デフォルト設定で続行します。[/yellow]"
        )
        console.print(f"  [dim]Raw response: {llm_text[:300]}[/dim]")
        return None

    result = _build_result(data)

    # ── 生成結果の表示 ───────────────────────────────────────────
    console.print()
    _print_result(result)

    # ── レビュー・編集 ───────────────────────────────────────────
    console.print()
    action = _ask(
        "  この設定で続行しますか? ([y]=そのまま続行 / [e]=編集 / [n]=キャンセル)",
        "y",
    ).lower()

    if action.startswith("n"):
        console.print("  [yellow]Auto-Config をキャンセルしました。デフォルト設定で続行します。[/yellow]")
        return None

    if action.startswith("e"):
        result = _interactive_edit(result)
        console.print()
        _print_result(result)
        console.print()
        confirm = _ask("  この設定で続行しますか? (y/n)", "y").lower()
        if not confirm.startswith("y"):
            console.print("  [yellow]キャンセルしました。デフォルト設定で続行します。[/yellow]")
            return None

    console.print("  [green]✔ Auto-Config 設定を適用しました。[/green]\n")
    return result


async def generate_from_description(payload_gen, description: str) -> Optional[dict]:
    """
    Web向けAPI: 自然言語の説明文から設定 dict を生成する（対話なし）。
    dashboard.html の AI設定生成ボタンから呼ばれる。

    Parameters
    ----------
    payload_gen : PayloadGenerator  LLM 呼び出しに使うペイロードジェネレーター。
    description : str               ユーザーが入力した自然言語の要求文。

    Returns
    -------
    dict or None
        設定 dict。LLM が利用不可またはパース失敗の場合は None。
    """
    if not await payload_gen._check_llm_available():
        return None

    user_prompt = (
        "以下の要望に基づいてWebセキュリティスキャン設定を生成してください。\n\n"
        f"【要望】\n{description}\n\n"
        "要望から検査項目・深さ・ヘッドレス・除外URLなどを判断して最適な設定JSONを返してください。\n"
        "ユーザーが特定の技術スタック（Django / Rails / PHP / React 等）や\n"
        "特定の検査項目を言及した場合は、それを優先してください。\n"
        "禁止事項・注意事項がある場合は warnings フィールドに必ず記載してください。"
    )

    llm_text = await _call_llm(payload_gen, user_prompt)
    if not llm_text:
        return None

    data = _parse_llm_response(llm_text)
    if not data:
        return None

    result = _build_result(data)
    return {
        "checks":            result.checks,
        "depth":             result.depth,
        "headless":          result.headless,
        "skip_registration": result.skip_registration,
        "exclude_urls":      result.exclude_urls,
        "exclude_fields":    result.exclude_fields,
        "max_forms":         result.max_forms,
        "timeout":           result.timeout,
        "notes":             result.notes,
        "warnings":          result.warnings,
    }


def apply_to_args(result: WizardResult, args) -> None:
    """
    WizardResult の値を argparse.Namespace に上書き適用する。
    CLI フラグで明示的に指定された値よりも Auto-Config を優先するが、
    URLなどスキャン固有の値は変更しない。
    """
    args.checks         = result.checks
    args.depth          = result.depth
    args.headless       = result.headless
    args.include_registration = not result.skip_registration
    args.max_forms      = result.max_forms
    args.timeout        = result.timeout
    # exclude_* は追記 (CLI 指定分は保持)
    current_excl_urls   = list(getattr(args, "exclude_urls_resolved", []))
    args.exclude_urls_resolved = current_excl_urls + [
        u for u in result.exclude_urls if u not in current_excl_urls
    ]
    current_excl_fields = list(getattr(args, "exclude", []))
    args.exclude = current_excl_fields + [
        f for f in result.exclude_fields if f not in current_excl_fields
    ]
