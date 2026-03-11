#!/usr/bin/env python3
"""
WScan CUI Launcher
インタラクティブに設定を入力してスキャンを開始します。
"""
import asyncio
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


def ask(prompt_text: str, default: str = "") -> str:
    """プロンプトを表示して入力を受け取る。空Enterでデフォルト値を返す。"""
    suffix = f" [{default}]" if default else ""
    try:
        val = input(f"  {prompt_text}{suffix}: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n\n  中断しました。")
        sys.exit(0)
    return val if val else default


def section(title: str):
    print(f"\n  ── {title} {'─' * max(0, 36 - len(title))}")


def main():
    print()
    print("  " + "=" * 44)
    print("    WScan  -  Web Security Scanner")
    print("  " + "=" * 44)

    # ── 対象URL ──────────────────────────────────────────
    section("対象URL")
    while True:
        url = ask("URL (例: http://localhost:5000)")
        if url.startswith(("http://", "https://")):
            break
        if url:
            print("    ※ http:// または https:// から始めてください。")
        else:
            print("    ※ URLを入力してください。")

    # ── 検査項目 ──────────────────────────────────────────
    section("検査項目")
    print("    sqli  = SQL インジェクション")
    print("    xss   = クロスサイトスクリプティング")
    print("    os    = OS コマンドインジェクション")
    checks_input = ask("実施する検査 (スペース区切り)", "sqli xss os")
    checks = [c for c in checks_input.split() if c in ("sqli", "xss", "os")]
    if not checks:
        checks = ["sqli", "xss", "os"]

    # ── クロール深度 ───────────────────────────────────────
    section("クロール深度")
    print("    リンクを何階層まで辿るか (深いほど時間がかかります)")
    while True:
        d = ask("深度", "2")
        try:
            depth = max(1, min(5, int(d)))
            break
        except ValueError:
            print("    ※ 1〜5 の数値を入力してください。")

    # ── 除外パラメータ ─────────────────────────────────────
    section("除外パラメータ (省略可)")
    print("    テストをスキップするパラメータ名をスペース区切りで入力")
    print("    例: csrf_token __token session_id")
    exclude_input = ask("除外パラメータ", "")
    exclude = [e for e in exclude_input.split() if e]

    # ── CTF モード ────────────────────────────────────────
    section("CTF モード")
    print("    CTFモードを有効にすると以下が追加されます:")
    print("      - SSTI (サーバーサイドテンプレートインジェクション) 検査")
    print("      - スキャン速度の向上 (スリープ時間を半減)")
    ctf_input = ask("CTFモードを有効にしますか? (y=有効 / n=無効)", "n").lower()
    ctf_mode = ctf_input in ("y", "yes")

    # ── 認証情報 ──────────────────────────────────────────
    section("ログイン認証情報 (省略可)")
    print("    ログインフォームのフィールドに自動入力する認証情報を設定します")
    print("    ユーザー名フィールド: username / email / login 等")
    print("    パスワードフィールド: type=password の全フィールド")
    auth_user = ask("ユーザー名/メールアドレス", "")
    auth_pass = ask("パスワード", "")

    # ── Cookie ────────────────────────────────────────────
    section("Cookie の事前付与 (省略可)")
    print("    スキャン開始前にブラウザにセットするCookieを入力します")
    print("    例: session=abc123; token=xyz789")
    cookie = ask("Cookie", "")

    # ── LLM ───────────────────────────────────────────────
    section("LLM ペイロード生成")
    print("    none   = デフォルトペイロードのみ使用 (推奨)")
    print("    ollama = Ollama でペイロード自動生成 (要: ローカル起動済み)")
    print("    claude = Claude API (要: ANTHROPIC_API_KEY 環境変数)")
    llm = ask("LLM", "none")
    if llm not in ("none", "ollama", "claude"):
        llm = "none"

    # ── ヘッドレス ─────────────────────────────────────────
    section("ブラウザ表示")
    h = ask("ブラウザを非表示にしますか? (y=非表示 / n=表示)", "n").lower()
    headless = h in ("y", "yes")

    # ── 設定確認 ───────────────────────────────────────────
    print()
    print("  " + "─" * 44)
    print("  設定確認")
    print("  " + "─" * 44)
    print(f"    対象: {url}")
    print(f"    検査: {' / '.join(c.upper() for c in checks)}{' + SSTI' if ctf_mode else ''}")
    print(f"    深度: {depth}")
    print(f"    LLM : {llm}")
    print(f"    CTF : {'有効' if ctf_mode else '無効'}")
    if auth_user:
        print(f"    認証: {auth_user} / {'*' * len(auth_pass)}")
    if cookie:
        print(f"    Cookie: {cookie[:60]}{'...' if len(cookie) > 60 else ''}")
    if exclude:
        print(f"    除外: {' '.join(exclude)}")
    print(f"    表示: {'非表示 (ヘッドレス)' if headless else '表示'}")
    print("  " + "─" * 44)
    print()

    try:
        ok = input("  スキャンを開始しますか? [Y/n]: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print("\n  中断しました。")
        sys.exit(0)

    if ok in ("n", "no"):
        print("  キャンセルしました。")
        sys.exit(0)

    print()

    # ── スキャン実行 ───────────────────────────────────────
    args = argparse.Namespace(
        url=url,
        checks=checks,
        depth=depth,
        headless=headless,
        no_monitor=False,
        llm=llm,
        ollama_model="llama3",
        payloads=None,
        output=None,
        port=8765,
        timeout=30,
        max_forms=50,
        exclude=exclude,
        exclude_file=None,
        ctf=ctf_mode,
        cookie=cookie,
        auth_user=auth_user,
        auth_pass=auth_pass,
    )

    from main import run_scan
    try:
        asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        print("\n  スキャンを中断しました。")


if __name__ == "__main__":
    main()
