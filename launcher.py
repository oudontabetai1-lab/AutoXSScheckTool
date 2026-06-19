#!/usr/bin/env python3
"""
WScan CUI Launcher
ダブルクリック / launcher.bat から起動できます。

既定では引数なし起動でダッシュボード(serve)を自動で開きます（実運用はほぼ
ブラウザ UI のため）。起動時に公開範囲（この端末のみ=localhost / LAN 公開）を
対話で選べます。bind 先は安全側の localhost(127.0.0.1) が既定、ポートは環境変数
WSCAN_PORT（既定 8765）。LAN 公開を選ぶと別端末からアクセスでき、無認証で晒さない
よう認証トークンの入力を促します。WSCAN_HOST を環境変数で明示した場合はプロンプトを
出さずそれを尊重します（併せて WSCAN_AUTH_TOKEN の設定を推奨）。
scan / agent モードを対話的に選ぶには `python launcher.py menu`（または
環境変数 WSCAN_LAUNCHER_MENU=1）でモード選択メニューを表示します。
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
    # "mail_header" (IPA 1.8) は無効化済み。確証に OOB メール受信が必要で
    # 黒box では実用的に検知できないため、選択肢として提示しない
    # (wscan/scanners/__init__.py 参照)。
    "clickjacking":     "クリックジャッキング               (IPA 1.9)",
    "open_redirect":    "オープンリダイレクト               (IPA 1.11)",
    "ssti":             "サーバーサイドテンプレートインジェクション",
    "dom_xss":          "DOM ベース XSS",
    "stored_xss":       "蓄積型 XSS (二次攻撃)",
    "privesc":          "権限昇格",
    "cors":             "CORS 設定不備",
    "info_disclosure":  "情報漏えい",
    "host_header":      "Host ヘッダ攻撃",
    "security_headers": "セキュリティヘッダ不備",
    "nosql":            "NoSQL インジェクション",
    "deserialization":  "デシリアライゼーション脆弱性",
    "request_smuggling":"HTTP リクエストスマグリング",
    "ssrf":             "SSRF (サーバーサイドリクエストフォージェリ)",
    "graphql":          "GraphQL インジェクション",
    "jwt":              "JWT 脆弱性",
    "cms":              "CMS 固有脆弱性 (WordPress/Drupal 等)",
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


def _prompt_bind() -> tuple[str, str, bool]:
    """ダッシュボードの公開範囲(bind 先)と認証トークンを対話で決める。

    WSCAN_HOST が環境変数で明示されていればプロンプトを出さずに尊重する
    （バッチ／上級者の明示指定を優先）。それ以外は localhost 限定か LAN 公開かを
    選ばせ、LAN 公開時は無認証で晒さないよう認証トークンを促す。
    戻り値は (host, auth_token, insecure)。insecure は「LAN 公開かつトークン空」を
    対話で明示選択したときだけ True。run_serve のグローバル公開ガードは LAN IP を
    8.8.8.8 プローブで解決するため、オフライン／デフォルトルート無しのラボ網では
    プライベート bind でも判定不能で起動中止になる。意図した無認証 LAN 公開を
    尊重するため、この明示選択時のみガードを上書きする。
    """
    env_host = os.environ.get("WSCAN_HOST", "").strip()
    env_token = os.environ.get("WSCAN_AUTH_TOKEN", "")
    if env_host:
        return env_host, env_token, False

    _header("公開範囲")
    _print("    この端末だけで使うか、同一 LAN の別端末からもアクセスできるようにするか選びます。")
    choice = _choose(
        "公開範囲",
        ["この端末のみ (localhost)", "LAN に公開 (別端末からアクセス可)"],
        default="この端末のみ (localhost)",
    )
    if choice.startswith("この端末"):
        return "127.0.0.1", env_token, False

    # LAN 公開 — 同一ネットワークの誰でもスキャナを操作できてしまうため、
    # 無認証で晒さないよう認証トークンを促す（空ならその旨を警告して続行）。
    _warn("LAN に公開します。同一ネットワークの誰でもダッシュボードにアクセスできます。")
    token = env_token or _ask("認証トークン (推奨。空=無認証で公開)").strip()
    if not token:
        _warn("無認証のまま公開します。社内・検証ネットワークに限定してください。")
    # トークン空 = 利用者が無認証 LAN 公開を意図的に選んだケース。オフライン
    # ラボ網でガードに弾かれないよう insecure を立てて意図を尊重する。
    return "0.0.0.0", token, not token


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


def _section_additional_urls() -> tuple[list[str], list[str]]:
    """追加の検査対象 URL とアクセス専用 URL を収集する。"""
    _header("追加 URL 設定 (省略可)")
    _print()
    _print("  ① 追加の検査対象 URL  ─ ペイロードを挿入する URL")
    _print("    用途例: ログイン URL が別ドメインかつ検査対象の場合")
    _print("    スペース区切りで複数入力できます")
    raw_target = _ask("追加の攻撃対象 URL (空白=なし)", "")
    target_urls: list[str] = []
    for u in raw_target.split():
        if u.startswith(("http://", "https://")):
            target_urls.append(u)
        elif u:
            _warn(f"http:// / https:// 以外のため無視: {u}")
    if target_urls:
        _ok(f"攻撃対象 URL: {len(target_urls)} 件 追加")

    _print()
    _print("  ② アクセス専用 URL  ─ 巡回するがペイロードは挿入しない URL")
    _print("    用途例: Cognito 等の外部認証 IDP は巡回したいが攻撃はしたくない場合")
    _print("    スペース区切りで複数入力できます")
    raw_access = _ask("アクセス専用 URL (空白=なし)", "")
    access_urls: list[str] = []
    for u in raw_access.split():
        if u.startswith(("http://", "https://")):
            access_urls.append(u)
        elif u:
            _warn(f"http:// / https:// 以外のため無視: {u}")
    if access_urls:
        _ok(f"アクセス専用 URL: {len(access_urls)} 件 追加")

    return target_urls, access_urls


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
        _ok("全 24 項目を選択しました")
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
    _print("  何階層まで検査するか (1=このページのみ, 2=リンク先1階層まで / 推奨: 2)")
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


# ── セクション: カスタムペイロード ──────────────────────────────

def _section_payloads() -> str:
    """カスタムペイロード YAML ファイルのパスを返す。空文字=デフォルト使用。"""
    _header("カスタムペイロード (省略可)")
    _print("  デフォルト以外のペイロードを使用する場合は YAML ファイルを指定します")
    _print("  フォーマット: config/default_payloads.yaml を参照")
    _print("  例: /path/to/my_payloads.yaml")
    raw = _ask("ペイロードファイルパス (空白=デフォルト使用)", "")
    if not raw:
        return ""
    if not os.path.isfile(raw):
        _warn(f"ファイルが見つかりません: {raw}  (無視してデフォルトを使用)")
        return ""
    _ok(f"ペイロードファイル: {raw}")
    return raw


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
        "exclude_urls_file": "",
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

    # 手動プラン作成 / 編集
    # AIプランナー有効時: AIが生成したプランを編集
    # AIプランナー無効時: ヒューリスティック分析を起点に手動で1から作成
    default_ip = "Y" if (default_interactive or defaults["no_planner"]) else "n"
    if defaults["no_planner"]:
        ip_label = (
            "手動プラン作成モードを有効にしますか? "
            "(ヒューリスティック分析を起点にフィールドごとに設定)"
        )
    else:
        ip_label = (
            "巡回後に攻撃プランを手動で確認・編集しますか? "
            "(AIプランに追加で修正を加えられます)"
        )
    ip = _ask(ip_label, default_ip).lower()
    defaults["interactive_plan"] = ip in ("y", "yes")
    if defaults["interactive_plan"]:
        if defaults["no_planner"]:
            _ok("手動プラン作成モード: 有効 (ヒューリスティック分析 → 各フィールドを手動設定)")
        else:
            _ok("手動プラン編集モード: 有効 (AIプランを確認・変更できます)")

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

    # 除外 URL ファイル
    excl_urls_file = _ask(
        "除外 URL リストファイル (1行1URL / 空白=なし)",
        "",
    )
    if excl_urls_file and not __import__("os").path.isfile(excl_urls_file):
        _warn(f"ファイルが見つかりません: {excl_urls_file}  (無視します)")
        excl_urls_file = ""
    defaults["exclude_urls_file"] = excl_urls_file
    if excl_urls_file:
        _ok(f"除外 URL リスト: {excl_urls_file}")

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
    target_urls: list[str] | None = None,
    access_urls: list[str] | None = None,
    payloads_file: str = "",
):
    _print()
    if _USE_RICH:
        t = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
        t.add_column("key",   style="dim",   no_wrap=True)
        t.add_column("value", style="white")

        t.add_row("対象 URL",   url)
        if target_urls:
            t.add_row("攻撃対象 URL",  "\n".join(target_urls))
        if access_urls:
            t.add_row("アクセス専用 URL", "\n".join(access_urls))
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
        if payloads_file:
            t.add_row("カスタムペイロード", payloads_file)
        if adv.get("exclude_urls_file"):
            t.add_row("除外 URL ファイル", adv["exclude_urls_file"])
        _console.print(Panel(t, title="[bold cyan]設定確認[/bold cyan]", border_style="cyan"))
    else:
        print()
        print("  " + "─" * 44)
        print("  設定確認")
        print("  " + "─" * 44)
        print(f"    URL      : {url}")
        if target_urls:
            print(f"    攻撃URL  : {' | '.join(target_urls)}")
        if access_urls:
            print(f"    専用URL  : {' | '.join(access_urls)}")
        print(f"    検査     : {' / '.join(c.upper() for c in checks)}")
        print(f"    LLM      : {provider}")
        print(f"    深度     : {depth}")
        if auth_user:
            print(f"    認証     : {auth_user} / {'*' * len(auth_pass)}")
        if cookie:
            print(f"    Cookie   : {cookie[:60]}")
        if exclude:
            print(f"    除外     : {' '.join(exclude)}")
        if payloads_file:
            print(f"    ペイロード: {payloads_file}")
        print(f"    ブラウザ : {'非表示' if adv['headless'] else '表示'}")
        print("  " + "─" * 44)


# ── Agent Browser モード ─────────────────────────────────────────

_AGENT_CHECKS = {
    "xss":            "クロスサイトスクリプティング",
    "sqli":           "SQL インジェクション",
    "ssti":           "サーバーサイドテンプレートインジェクション",
    "os":             "OS コマンドインジェクション",
    "path_traversal": "ディレクトリトラバーサル",
    "ssrf":           "サーバーサイドリクエストフォージェリ",
    "open_redirect":  "オープンリダイレクト",
    "csrf":           "CSRF",
    "header_injection": "HTTP ヘッダインジェクション",
}

_AGENT_DEFAULT_CHECKS = ["xss", "sqli", "ssti", "os", "path_traversal", "ssrf"]

_AGENT_LLM_INFO = {
    "claude": "Claude API (要: ANTHROPIC_API_KEY) — 推奨",
    "openai": "OpenAI API (要: OPENAI_API_KEY)",
    "ollama": "Ollama     (ローカル実行 / 要: ollama起動済み)",
}

_AGENT_DEFAULT_MODELS = {
    "claude": "claude-sonnet-4-5-20250929",
    "openai": "gpt-4o-mini",
    "ollama": "llama3",
}


def _section_agent_checks() -> list[str]:
    _header("検査項目 (Agent)")
    _print("  番号をスペース区切りで入力、または all で全項目、Enter でデフォルト")
    keys = list(_AGENT_CHECKS.keys())
    for i, k in enumerate(keys, 1):
        mark = "●" if k in _AGENT_DEFAULT_CHECKS else "○"
        _print(f"    [{i:>2}] {mark} {k:<18} {_AGENT_CHECKS[k]}")

    raw = _ask(f"選択 (デフォルト: {' '.join(_AGENT_DEFAULT_CHECKS)})", "")
    if not raw:
        return list(_AGENT_DEFAULT_CHECKS)
    if raw.strip().lower() == "all":
        _ok("全項目を選択しました")
        return keys

    selected = []
    for token in raw.split():
        if token.isdigit() and 1 <= int(token) <= len(keys):
            selected.append(keys[int(token) - 1])
        elif token in keys:
            selected.append(token)

    if not selected:
        _warn("無効な入力です。デフォルトを使用します。")
        return list(_AGENT_DEFAULT_CHECKS)
    _ok(f"選択: {', '.join(selected)}")
    return selected


def _section_agent_mode() -> argparse.Namespace:
    """Agent Browser モードの設定を収集して Namespace を返す。"""
    url = _section_url()

    _header("LLM プロバイダー (Agent Browser)")
    _print("  ※ Gemini は browser-use 非対応のため除外しています")
    providers = list(_AGENT_LLM_INFO.keys())
    for i, p in enumerate(providers, 1):
        _print(f"    [{i}] {p:<8}  {_AGENT_LLM_INFO[p]}")
    provider = _choose("プロバイダー番号", providers, "claude")
    _ok(f"プロバイダー: {provider}")

    default_model = _AGENT_DEFAULT_MODELS[provider]
    _print(f"  デフォルトモデル: {default_model}")
    model = _ask("モデル名 (空白=デフォルト)", "")
    if not model:
        model = ""  # run_agent 側でデフォルト適用
        _ok(f"モデル: {default_model} (デフォルト)")
    else:
        _ok(f"モデル: {model}")

    if provider in ("claude", "openai", "ollama"):
        env_map = {
            "claude": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
        }
        env_key = env_map.get(provider)
        if env_key:
            _section_api_key(env_key, "sk-..." if provider == "openai" else "sk-ant-...")

    checks = _section_agent_checks()

    _header("最大ステップ数")
    _print("  LLM エージェントが実行できる最大操作ステップ数 (推奨: 50〜100)")
    while True:
        raw = _ask("最大ステップ数", "50")
        try:
            max_steps = max(5, min(500, int(raw)))
            break
        except ValueError:
            _err("数値を入力してください。")

    _header("ログイン認証情報 (省略可)")
    _print("  ログインが必要なサイトの場合、エージェントが自動的にログインします")
    login_url = _ask("ログイン URL (省略可)", "")
    if login_url:
        auth_user = _ask("ユーザー名", "")
        auth_pass = _ask("パスワード", "") if auth_user else ""
    else:
        auth_user = ""
        auth_pass = ""

    _header("その他の設定")
    port_raw = _ask("ダッシュボードポート", "8765")
    try:
        port = int(port_raw)
    except ValueError:
        port = 8765

    show_browser = _ask("ブラウザを表示しますか? (y/N)", "n").lower()

    _print()
    if _USE_RICH:
        from rich.table import Table
        from rich import box as _box
        t = Table(show_header=False, box=_box.SIMPLE, padding=(0, 1))
        t.add_column("key",   style="dim",   no_wrap=True)
        t.add_column("value", style="white")
        t.add_row("対象 URL",     url)
        t.add_row("LLM",          f"{provider}  ({model or _AGENT_DEFAULT_MODELS[provider]})")
        t.add_row("検査項目",     " / ".join(c.upper() for c in checks))
        t.add_row("最大ステップ", str(max_steps))
        t.add_row("ブラウザ",     "表示" if show_browser in ("y", "yes") else "非表示")
        if login_url:
            t.add_row("ログイン URL", login_url)
        if auth_user:
            t.add_row("認証",         f"{auth_user} / {'*' * len(auth_pass)}")
        _console.print(Panel(t, title="[bold magenta]Agent Browser 設定確認[/bold magenta]", border_style="magenta"))
    else:
        print()
        print(f"    URL      : {url}")
        print(f"    LLM      : {provider}")
        print(f"    検査     : {' / '.join(c.upper() for c in checks)}")
        print(f"    ステップ : {max_steps}")

    _print()
    try:
        ok = input("  Agent Browser スキャンを開始しますか? [Y/n]: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        _print()
        _print("  中断しました。")
        sys.exit(0)
    if ok in ("n", "no"):
        _print("  キャンセルしました。")
        sys.exit(0)

    return argparse.Namespace(
        url=url,
        llm=provider,
        model=model,
        ollama_url="http://localhost:11434",
        checks=checks,
        max_steps=max_steps,
        headless=show_browser not in ("y", "yes"),
        no_headless=show_browser in ("y", "yes"),
        auth_user=auth_user,
        auth_pass=auth_pass,
        login_url=login_url,
        output=None,
        port=port,
        no_monitor=False,
        no_open_report=False,
    )


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

    # ── 既定: ダッシュボード(serve)を自動起動 ───────────────────────
    # 実運用はほぼ serve（ブラウザ UI）なので、引数なし起動では即ダッシュボードを開く。
    # scan / agent も使いたいときは `python launcher.py menu`（または
    # 環境変数 WSCAN_LAUNCHER_MENU=1）でモード選択メニューを表示する。
    argv = [a.lower() for a in sys.argv[1:]]
    show_menu = ("menu" in argv) or os.environ.get(
        "WSCAN_LAUNCHER_MENU", ""
    ).strip().lower() in ("1", "true", "yes", "on")

    def _launch_serve(port: int, host: str = "127.0.0.1", auth_token: str = "",
                      insecure: bool = False) -> None:
        if host in ("127.0.0.1", "localhost", "::1"):
            _ok(f"http://localhost:{port} でダッシュボードを起動します")
        else:
            _ok(f"http://localhost:{port} （別端末からは http://<このPCのIP>:{port}）"
                f"でダッシュボードを起動します")
        _print()
        # host / auth_token は呼び出し側(_prompt_bind)で決定して渡す。WSCAN_HOST が
        # 明示されていればそれを、無ければ対話選択の結果(既定 localhost)を渡す。
        # auth_token を省くと run_serve がトークン無しにフォールバックし、設定済みでも
        # 未認証になるため明示的に渡す。
        #
        # bind 先はローカルツールとして安全側に倒し、既定で localhost(127.0.0.1)。
        # ダブルクリック起動が無認証のままスキャナ制御画面を LAN へ晒さないため、
        # LAN 公開は対話で明示選択したときのみ（その際は認証トークンを促す）。
        # サーバ常駐は `python main.py serve` を使う（config の host を尊重）。
        from main import run_serve
        serve_args = argparse.Namespace(
            port=port,
            host=host,
            auth_token=auth_token,
            # 無認証 LAN 公開を対話で明示選択したときのみ True（run_serve の
            # グローバル公開ガードをオフライン網でも越えて意図を尊重するため）。
            insecure=insecure,
            # ランチャーはダッシュボードを開くのが目的なので必ずブラウザを開く
            # （run_serve 既定は loopback bind 時のみ開く）。
            open_browser=True,
        )
        try:
            asyncio.run(run_serve(serve_args))
        except KeyboardInterrupt:
            _print()
            _print("  ダッシュボードを停止しました。")

    if not show_menu:
        # ポートは環境変数 WSCAN_PORT（既定 8765）。プロンプトせず即起動。
        try:
            port = int(os.environ.get("WSCAN_PORT", "8765") or "8765")
        except ValueError:
            port = 8765
        _header("ダッシュボードを起動")
        _print("    [dim]scan / agent を使うには `python launcher.py menu`[/dim]"
               if _USE_RICH else
               "    scan / agent を使うには `python launcher.py menu`")
        host, auth_token, insecure = _prompt_bind()
        _launch_serve(port, host, auth_token, insecure)
        return

    # ── モード選択（menu 指定時のみ） ────────────────────────────────
    _header("起動モードを選択")
    _print("    [1] 通常スキャン        — クロール → AI プランナー → ペイロード自動攻撃")
    _print("    [2] Agent Browser スキャン — LLM がブラウザを直接操作して自律的に探索")
    _print("    [3] ダッシュボードを開く   — ブラウザ UI から設定・スキャン起動 (serve)")
    _print()
    mode_options = ["scan", "agent", "serve"]
    mode = _choose("モード番号", mode_options, "serve")

    # ── serve モード ─────────────────────────────────────────────
    if mode == "serve":
        _header("ダッシュボードポート")
        port_raw = _ask("ポート番号", "8765")
        try:
            port = int(port_raw)
        except ValueError:
            port = 8765
        host, auth_token, insecure = _prompt_bind()
        _launch_serve(port, host, auth_token, insecure)
        return

    # ── Agent Browser モード ─────────────────────────────────────
    if mode == "agent":
        agent_args = _section_agent_mode()
        from main import run_agent
        try:
            asyncio.run(run_agent(agent_args))
        except KeyboardInterrupt:
            _print()
            _print("  スキャンを中断しました。")
        return

    # ── 通常スキャン (scan) ─────────────────────────────────────
    url = _section_url()
    additional_target_urls, access_urls = _section_additional_urls()
    checks = _section_checks()
    provider, ollama_model, openai_model, gemini_model = _section_llm()
    depth = _section_depth()
    auth_user, auth_pass = _section_auth()
    cookie = _section_cookie()
    exclude = _section_exclude()
    payloads_file = _section_payloads()
    adv = _section_advanced(provider=provider)

    # ── 設定確認 ────────────────────────────────────────────────
    _show_summary(
        url, checks, provider, ollama_model, openai_model, gemini_model,
        depth, auth_user, auth_pass, cookie, exclude, adv,
        target_urls=additional_target_urls,
        access_urls=access_urls,
        payloads_file=payloads_file,
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
        claude_model=_DEFAULT_MODELS["claude"],
        payloads=payloads_file or None,
        output=None,
        port=adv["port"],
        timeout=adv["timeout"],
        max_forms=adv["max_forms"],
        exclude=exclude,
        exclude_file=None,
        exclude_urls_file=adv.get("exclude_urls_file", "") or None,
        ctf=adv["ctf"],
        ctf_flag_format=adv.get("ctf_flag_format", ""),
        cookie=cookie,
        auth_user=auth_user,
        auth_pass=auth_pass,
        # 複数 URL スコープ
        target_urls=additional_target_urls,
        access_urls=access_urls,
        target_urls_file="",
        access_urls_file="",
        # 追加フィールド（run_scan が getattr で参照するもの）
        login_url="",
        login_user_field="username",
        login_pass_field="password",
        login_success="",
        proxy="",
        no_open_report=False,
        include_registration=False,
        dom_xss=False,
        auto_config=False,
        no_auto_config=True,
        learning_file="",
        concurrency=1,
        flows=[],
        cookie_file="",
        low_priv_cookies="",
        low_priv_cookie_file="",
        no_ai_analysis=False,
        no_waf_detection=False,
        no_payload_learning=False,
        no_sitemap_crawl=False,
        enable_llm_web_browsing=False,
    )

    from main import run_scan
    try:
        asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        _print()
        _print("  スキャンを中断しました。")


if __name__ == "__main__":
    main()
