#!/usr/bin/env python3
"""
WScan CUI Launcher
インタラクティブに設定を入力してスキャンを開始します。
ダブルクリック / launcher.bat から起動できます。
"""
import argparse
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# ── カラー出力 (rich が使えれば使う) ──────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    _console = Console()

    def _print(msg: str = ""):
        _console.print(msg)

    def _panel(title: str, content: str, style: str = "cyan"):
        _console.print(Panel(content, title=f"[bold]{title}[/bold]", border_style=style))

    def _ok(msg: str):
        _console.print(f"    [green]✔[/green] {msg}")

    def _warn(msg: str):
        _console.print(f"    [yellow]⚠[/yellow]  {msg}")

    def _err(msg: str):
        _console.print(f"    [red]✘[/red] {msg}")

    def _header(msg: str):
        _console.print(f"\n  [bold cyan]── {msg} {'─' * max(0, 36 - len(msg))}[/bold cyan]")

    def _item(key: str, val: str):
        _console.print(f"    [dim]{key:<16}[/dim] [white]{val}[/white]")

    _USE_RICH = True

except ImportError:
    _USE_RICH = False

    def _print(msg: str = ""):
        print(msg)

    def _panel(title: str, content: str, style: str = ""):
        print(f"\n  {'=' * 44}")
        print(f"    {title}")
        print(f"  {'=' * 44}")
        print(content)

    def _ok(msg: str):
        print(f"    [OK] {msg}")

    def _warn(msg: str):
        print(f"    [!]  {msg}")

    def _err(msg: str):
        print(f"    [ERR] {msg}")

    def _header(msg: str):
        print(f"\n  ── {msg} {'─' * max(0, 36 - len(msg))}")

    def _item(key: str, val: str):
        print(f"    {key:<16} {val}")


# ── 定数 ────────────────────────────────────────────────────────────

_ALL_CHECKS = {
    "sqli":             "SQL インジェクション               (IPA 1.1)",
    "os":               "OS コマンドインジェクション         (IPA 1.2)",
    "path_traversal":   "ディレクトリトラバーサル            (IPA 1.3)",
    "session":          "セッション管理の不備                (IPA 1.4)",
    "xss":              "クロスサイトスクリプティング         (IPA 1.5)",
    "csrf":             "CSRF                               (IPA 1.6)",
    "header_injection": "HTTP ヘッダインジェクション         (IPA 1.7)",
    "mail_header":      "メールヘッダインジェクション        (IPA 1.8)",
    "clickjacking":     "クリックジャッキング               (IPA 1.9)",
    "open_redirect":    "オープンリダイレクト               (IPA 1.11)",
    "ssti":             "サーバーサイドテンプレートインジェクション",
}

_DEFAULT_CHECKS = ["sqli", "xss", "os"]

_LLM_INFO = {
    "none":   "LLM不使用  (デフォルトペイロードのみ)",
    "ollama": "Ollama     (ローカル実行 / 要: ollama起動済み)",
    "claude": "Claude API (要: ANTHROPIC_API_KEY)",
    "openai": "OpenAI API (要: OPENAI_API_KEY)",
    "gemini": "Gemini API (要: GEMINI_API_KEY)",
}

_DEFAULT_MODELS = {
    "ollama": "gemma3:4b",
    "openai": "gpt-4o-mini",
    "gemini": "gemini-2.0-flash",
    "claude": "claude-haiku-4-5-20251001",
}


# ── 入力ユーティリティ ────────────────────────────────────────────

def _ask(prompt_text: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        val = input(f"  > {prompt_text}{suffix}: ").strip()
    except (KeyboardInterrupt, EOFError):
        _print()
        _print("  中断しました。")
        sys.exit(0)
    return val if val else default


def _choose(prompt_text: str, options: list[str], default: str = "") -> str:
    """番号選択メニュー。戻り値は options の要素。"""
    for i, opt in enumerate(options, 1):
        marker = " ◀" if opt == default else ""
        _print(f"    [{i}] {opt}{marker}")
    while True:
        raw = _ask(prompt_text, str(options.index(default) + 1) if default in options else "1")
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1]
        # ラベル直接入力も受け付ける
        if raw in options:
            return raw
        _err(f"1〜{len(options)} または選択肢を直接入力してください。")


# ── セクション: 対象 URL ─────────────────────────────────────────

def _section_url() -> str:
    _header("対象 URL")
    while True:
        url = _ask("URL (例: http://localhost:5000)")
        if url.startswith(("http://", "https://")):
            return url
        if url:
            _err("http:// または https:// から始めてください。")
        else:
            _err("URL を入力してください。")


# ── セクション: 検査項目 ─────────────────────────────────────────

def _section_checks() -> list[str]:
    _header("検査項目")
    _print("  番号をスペース区切りで入力（例: 1 2 3）、または all で全項目、Enter でデフォルト")
    keys = list(_ALL_CHECKS.keys())
    for i, k in enumerate(keys, 1):
        mark = "●" if k in _DEFAULT_CHECKS else "○"
        _print(f"    [{i:>2}] {mark} {k:<18} {_ALL_CHECKS[k]}")

    raw = _ask(f"選択 (デフォルト: {' '.join(_DEFAULT_CHECKS)})", "")
    if not raw:
        return list(_DEFAULT_CHECKS)
    if raw.strip().lower() == "all":
        _ok("全 11 項目を選択しました")
        return keys

    selected = []
    for token in raw.split():
        if token.isdigit() and 1 <= int(token) <= len(keys):
            selected.append(keys[int(token) - 1])
        elif token in keys:
            selected.append(token)

    if not selected:
        _warn("無効な入力です。デフォルト (sqli xss os) を使用します。")
        return list(_DEFAULT_CHECKS)
    _ok(f"選択: {', '.join(selected)}")
    return selected


# ── セクション: LLM ──────────────────────────────────────────────

def _section_llm() -> tuple[str, str, str, str]:
    """(provider, ollama_model, openai_model, gemini_model) を返す。"""
    _header("LLM ペイロード生成")
    providers = list(_LLM_INFO.keys())
    for i, p in enumerate(providers, 1):
        _print(f"    [{i}] {p:<8}  {_LLM_INFO[p]}")

    provider = _choose("プロバイダー番号", providers, "none")
    _ok(f"プロバイダー: {provider}")

    ollama_model = _DEFAULT_MODELS["ollama"]
    openai_model = _DEFAULT_MODELS["openai"]
    gemini_model = _DEFAULT_MODELS["gemini"]

    if provider == "ollama":
        _print("  ─ Ollama モデルの例 ─")
        _print("    gemma3:4b    → M4 MacBook Air 16GB に最適 (速い)")
        _print("    qwen2.5:7b   → セキュリティ知識豊富")
        _print("    llama3.2:3b  → 超軽量・超高速")
        _print("    qwen2.5:14b  → 24GB モデル向け高精度")
        ollama_model = _ask("Ollama モデル名", ollama_model)

    elif provider == "openai":
        _print("  ─ OpenAI モデルの例 ─")
        _print("    gpt-4o-mini  → 高速・低コスト (推奨)")
        _print("    gpt-4o       → 最高精度")
        openai_model = _ask("OpenAI モデル名", openai_model)
        _section_api_key("OPENAI_API_KEY", "sk-...")

    elif provider == "gemini":
        _print("  ─ Gemini モデルの例 ─")
        _print("    gemini-2.0-flash  → 高速・低コスト (推奨)")
        _print("    gemini-1.5-pro    → 最高精度")
        gemini_model = _ask("Gemini モデル名", gemini_model)
        _section_api_key("GEMINI_API_KEY", "AIza...")

    elif provider == "claude":
        _item("モデル", _DEFAULT_MODELS["claude"])
        _section_api_key("ANTHROPIC_API_KEY", "sk-ant-...")

    return provider, ollama_model, openai_model, gemini_model


def _section_api_key(env_name: str, placeholder: str):
    """環境変数が未設定なら入力を促す。入力値は os.environ に設定。"""
    if os.environ.get(env_name):
        _ok(f"{env_name} は環境変数から取得済みです")
        return
    _warn(f"{env_name} が設定されていません")
    key = _ask(f"{env_name} (このセッションのみ有効、Enter でスキップ)", "")
    if key:
        os.environ[env_name] = key
        _ok(f"{env_name} をセットしました")
    else:
        _warn("APIキー未設定 → LLM は無効化されます")


# ── セクション: クロール深度 ─────────────────────────────────────

def _section_depth() -> int:
    _header("クロール深度")
    _print("  リンクを何階層まで辿るか (深いほど時間がかかります / 推奨: 2)")
    while True:
        d = _ask("深度 (1〜5)", "2")
        try:
            return max(1, min(5, int(d)))
        except ValueError:
            _err("1〜5 の数値を入力してください。")


# ── セクション: 認証情報 ─────────────────────────────────────────

def _section_auth() -> tuple[str, str]:
    _header("ログイン認証情報 (省略可)")
    _print("  ログインフォームに自動入力するアカウント情報を設定します")
    auth_user = _ask("ユーザー名 / メールアドレス", "")
    auth_pass = _ask("パスワード", "") if auth_user else ""
    return auth_user, auth_pass


# ── セクション: Cookie ────────────────────────────────────────────

def _section_cookie() -> str:
    _header("Cookie の事前付与 (省略可)")
    _print("  スキャン開始前にブラウザへセットする Cookie")
    _print("  例: session=abc123; token=xyz789")
    return _ask("Cookie", "")


# ── セクション: 除外パラメータ ───────────────────────────────────

def _section_exclude() -> list[str]:
    _header("除外パラメータ (省略可)")
    _print("  テストをスキップするフィールド名 (スペース区切り)")
    _print("  例: csrf_token __token session_id")
    raw = _ask("除外パラメータ", "")
    return [e for e in raw.split() if e]


# ── セクション: 詳細設定 ────────────────────────────────────────

def _section_advanced(provider: str = "ollama") -> dict:
    _header("詳細設定")
    use_adv = _ask("詳細設定を変更しますか? (y/N)", "n").lower()
    # interactive_plan: LLM が none の時はデフォルト ON
    default_interactive = provider == "none"
    defaults = {
        "headless": False,
        "no_monitor": False,
        "no_planner": False,
        "interactive_plan": default_interactive,
        "ctf": False,
        "ctf_flag_format": "",
        "ctf_llm_override": None,
        "port": 8765,
        "timeout": 30,
        "max_forms": 50,
    }
    if use_adv not in ("y", "yes"):
        if default_interactive:
            _ok("LLM なし → 手動プラン編集モード: 有効 (デフォルト)")
        _ok("その他はデフォルト値を使用します")
        return defaults

    # ブラウザ表示
    h = _ask("ブラウザを非表示にしますか? (y/N)", "n").lower()
    defaults["headless"] = h in ("y", "yes")

    # ダッシュボード
    m = _ask("リアルタイムダッシュボードを無効にしますか? (y/N)", "n").lower()
    defaults["no_monitor"] = m in ("y", "yes")

    # AI プランナー
    p = _ask("AI アタックプランナーを無効にしますか? (y/N)", "n").lower()
    defaults["no_planner"] = p in ("y", "yes")

    # 手動プラン編集
    if not defaults["no_planner"]:
        default_ip = "Y" if default_interactive else "n"
        ip = _ask(
            "巡回後に攻撃プランを手動で確認・編集しますか? "
            "(LLM=none の場合は推奨)",
            default_ip,
        ).lower()
        defaults["interactive_plan"] = ip in ("y", "yes")
        if defaults["interactive_plan"]:
            _ok("手動プラン編集モード: 有効 (各フィールドのリスク・検査・ペイロードを編集できます)")

    # CTF モード
    ctf = _ask("CTF モードを有効にしますか? (y/N)", "n").lower()
    defaults["ctf"] = ctf in ("y", "yes")

    if defaults["ctf"]:
        _header("CTF モード設定")
        _print("  フラグ形式の例:")
        _print("    1. FLAG{...}  / CTF{...}   (汎用 — デフォルト)")
        _print("    2. HTB{...}                (Hack The Box)")
        _print("    3. picoCTF{...}            (picoCTF)")
        _print("    4. DUCTF{...}              (DownUnder CTF)")
        _print("    5. カスタム正規表現        (例: [A-Z0-9]{4}\\{[^}]+\\})")
        _print()
        _print("    デフォルト: FLAG|CTF の形式を自動検出。カスタム正規表現も可")
        flag_fmt = _ask(
            "フラグ形式 (例: HTB{[^}]+} / 空白=デフォルト自動検出)",
            "",
        )
        defaults["ctf_flag_format"] = flag_fmt
        if flag_fmt:
            _ok(f"フラグパターン: {flag_fmt}")
        else:
            _ok("フラグパターン: デフォルト自動検出 (FLAG/CTF/HTB 等)")

        _print()
        _print("  CTF モードでの LLM 使用:")
        _print("  ・LLM を使うとペイロードが強化されますが、外部 API / Ollama が必要です")
        _print(f"  ・現在の LLM 設定: [{provider}]")
        ctf_llm_change = _ask(
            "CTF モード用に LLM を変更しますか? (y/N)", "n"
        ).lower()
        if ctf_llm_change in ("y", "yes"):
            _print("  CTF 用 LLM を選択:")
            providers_list = list(_LLM_INFO.keys())
            for i, p in enumerate(providers_list, 1):
                marker = " ◀ (現在)" if p == provider else ""
                _print(f"    [{i}] {p:<8}  {_LLM_INFO[p]}{marker}")
            new_provider = _choose("プロバイダー番号", providers_list, provider)
            defaults["ctf_llm_override"] = new_provider
            _ok(f"CTF LLM: {new_provider}")
        else:
            defaults["ctf_llm_override"] = None

    # ポート番号
    while True:
        port_raw = _ask("ダッシュボードポート", "8765")
        try:
            defaults["port"] = int(port_raw)
            break
        except ValueError:
            _err("数値を入力してください。")

    # タイムアウト
    while True:
        to_raw = _ask("タイムアウト (秒)", "30")
        try:
            defaults["timeout"] = int(to_raw)
            break
        except ValueError:
            _err("数値を入力してください。")

    # 最大フォーム数
    while True:
        mf_raw = _ask("1ページあたりの最大フォーム数", "50")
        try:
            defaults["max_forms"] = int(mf_raw)
            break
        except ValueError:
            _err("数値を入力してください。")

    return defaults


# ── 設定サマリー表示 ─────────────────────────────────────────────

def _show_summary(
    url, checks, provider, ollama_model, openai_model, gemini_model,
    depth, auth_user, auth_pass, cookie, exclude, adv,
):
    _print()
    if _USE_RICH:
        t = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
        t.add_column("key",   style="dim",   no_wrap=True)
        t.add_column("value", style="white")

        t.add_row("対象 URL",   url)
        t.add_row("検査項目",   " / ".join(c.upper() for c in checks))

        model_str = {
            "ollama": ollama_model,
            "openai": openai_model,
            "gemini": gemini_model,
            "claude": _DEFAULT_MODELS["claude"],
            "none":   "—",
        }.get(provider, provider)
        t.add_row("LLM",        f"{provider}  ({model_str})")

        t.add_row("クロール深度", str(depth))
        t.add_row("ブラウザ",    "非表示" if adv["headless"] else "表示")
        t.add_row("ダッシュボード", "無効" if adv["no_monitor"] else f"有効 (port {adv['port']})")
        t.add_row("AI プランナー", "無効" if adv["no_planner"] else "有効")
        ip_label = "有効 (手動編集あり)" if adv.get("interactive_plan") else "無効 (自動確定)"
        t.add_row("手動プラン編集", ip_label)
        if adv["ctf"]:
            ctf_label = "有効"
            if adv.get("ctf_flag_format"):
                ctf_label += f"  (パターン: {adv['ctf_flag_format']})"
            if adv.get("ctf_llm_override"):
                ctf_label += f"  LLM→{adv['ctf_llm_override']}"
            t.add_row("CTF モード", ctf_label)
        else:
            t.add_row("CTF モード", "無効")
        if auth_user:
            t.add_row("認証",   f"{auth_user} / {'*' * len(auth_pass)}")
        if cookie:
            t.add_row("Cookie", cookie[:60] + ("..." if len(cookie) > 60 else ""))
        if exclude:
            t.add_row("除外パラメータ", " ".join(exclude))
        _console.print(Panel(t, title="[bold cyan]設定確認[/bold cyan]", border_style="cyan"))
    else:
        print()
        print("  " + "─" * 44)
        print("  設定確認")
        print("  " + "─" * 44)
        print(f"    URL      : {url}")
        print(f"    検査     : {' / '.join(c.upper() for c in checks)}")
        print(f"    LLM      : {provider}")
        print(f"    深度     : {depth}")
        if auth_user:
            print(f"    認証     : {auth_user} / {'*' * len(auth_pass)}")
        if cookie:
            print(f"    Cookie   : {cookie[:60]}")
        if exclude:
            print(f"    除外     : {' '.join(exclude)}")
        print(f"    ブラウザ : {'非表示' if adv['headless'] else '表示'}")
        print("  " + "─" * 44)


# ── メイン ───────────────────────────────────────────────────────

def main():
    if _USE_RICH:
        _console.print(Panel.fit(
            "[bold cyan]WScan  -  Web Security Scanner[/bold cyan]\n"
            "[dim]インタラクティブランチャー[/dim]",
            border_style="cyan",
        ))
    else:
        print()
        print("  " + "=" * 44)
        print("    WScan  -  Web Security Scanner")
        print("  " + "=" * 44)

    # ── 各セクションで設定を収集 ────────────────────────────────
    url = _section_url()
    checks = _section_checks()
    provider, ollama_model, openai_model, gemini_model = _section_llm()
    depth = _section_depth()
    auth_user, auth_pass = _section_auth()
    cookie = _section_cookie()
    exclude = _section_exclude()
    adv = _section_advanced(provider=provider)

    # ── 設定確認 ────────────────────────────────────────────────
    _show_summary(
        url, checks, provider, ollama_model, openai_model, gemini_model,
        depth, auth_user, auth_pass, cookie, exclude, adv,
    )

    _print()
    try:
        ok = input("  スキャンを開始しますか? [Y/n]: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        _print()
        _print("  中断しました。")
        sys.exit(0)

    if ok in ("n", "no"):
        _print("  キャンセルしました。")
        sys.exit(0)

    _print()

    # ── スキャン実行 ─────────────────────────────────────────────
    # CTF モードで LLM オーバーライドが指定されていれば適用
    effective_provider = adv.get("ctf_llm_override") or provider

    args = argparse.Namespace(
        url=url,
        checks=checks,
        depth=depth,
        headless=adv["headless"],
        no_monitor=adv["no_monitor"],
        no_planner=adv["no_planner"],
        interactive_plan=adv.get("interactive_plan", False),
        llm=effective_provider,
        ollama_model=ollama_model,
        openai_model=openai_model,
        gemini_model=gemini_model,
        payloads=None,
        output=None,
        port=adv["port"],
        timeout=adv["timeout"],
        max_forms=adv["max_forms"],
        exclude=exclude,
        exclude_file=None,
        ctf=adv["ctf"],
        ctf_flag_format=adv.get("ctf_flag_format", ""),
        cookie=cookie,
        auth_user=auth_user,
        auth_pass=auth_pass,
    )

    from main import run_scan
    try:
        asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        _print()
        _print("  スキャンを中断しました。")


if __name__ == "__main__":
    main()
