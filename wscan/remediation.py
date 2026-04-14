"""
LLM Remediation Generator
==========================
検出された脆弱性に対して、LLM を使った修正ガイダンスを生成する。
LLM が利用できない場合は静的テンプレートにフォールバックする。

使い方:
    from wscan.remediation import generate_fix
    fix_text = await generate_fix(finding, engine.payload_gen)
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from wscan.scanners.base import Finding
    from wscan.payload_gen import PayloadGenerator


# ── 静的修正ガイダンス (LLM なし時のフォールバック) ──────────────────────────

_STATIC_FIX: dict[str, str] = {
    "sqli": (
        "**SQLインジェクション対策**\n"
        "1. プリペアドステートメント（パラメータ化クエリ）を使用し、動的SQL文字列の連結を排除してください。\n"
        "2. ORM（Hibernate, SQLAlchemy, Django ORM 等）を活用してください。\n"
        "3. 入力値の型チェック・範囲検証を行ってください。\n"
        "4. データベースアカウントに最小権限を付与してください。\n"
        "例 (Python): `cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))`"
    ),
    "xss": (
        "**クロスサイト・スクリプティング (XSS) 対策**\n"
        "1. ユーザー入力を HTML に出力する際、必ず HTML エスケープ (`htmlspecialchars`, `escape()` 等) を適用してください。\n"
        "2. `Content-Security-Policy` ヘッダを設定し、スクリプト実行元を制限してください。\n"
        "3. テンプレートエンジンの自動エスケープ機能を有効にしてください。\n"
        "4. `innerHTML` の使用を避け、`textContent` を使用してください。"
    ),
    "dom_xss": (
        "**DOM-based XSS 対策**\n"
        "1. `document.write()`, `innerHTML`, `eval()` 等の危険な DOM API への直接的なユーザー入力を避けてください。\n"
        "2. `textContent`, `setAttribute()` 等の安全な代替 API を使用してください。\n"
        "3. DOMPurify 等のサニタイズライブラリを使用してください。\n"
        "4. `Content-Security-Policy` の `script-src` 制限を設定してください。"
    ),
    "stored_xss": (
        "**蓄積型 XSS 対策**\n"
        "1. データベースへの保存前にサニタイズ、出力時に HTML エスケープの二段階で保護してください。\n"
        "2. リッチテキストエディタには許可リスト方式のサニタイザー (DOMPurify 等) を使用してください。\n"
        "3. `Content-Security-Policy` ヘッダを設定してください。"
    ),
    "os": (
        "**OSコマンド・インジェクション対策**\n"
        "1. ユーザー入力を OS コマンドに渡すことを避けてください。\n"
        "2. どうしても必要な場合はホワイトリスト検証を行い、シェル呼び出し (`shell=True`) を使わないでください。\n"
        "3. Python: `subprocess.run(['cmd', arg], shell=False)` のようにリスト形式で引数を渡してください。\n"
        "4. コマンド実行が必要な機能は、既存のライブラリ関数で置き換えることを検討してください。"
    ),
    "ssti": (
        "**サーバーサイド・テンプレート・インジェクション (SSTI) 対策**\n"
        "1. ユーザー入力をテンプレート文字列として直接扱わないでください。\n"
        "2. テンプレートエンジンの sandbox モードを使用してください (Jinja2: `SandboxedEnvironment`)。\n"
        "3. テンプレートファイルはホワイトリストで管理し、ユーザーが指定できないようにしてください。"
    ),
    "path_traversal": (
        "**パス・トラバーサル対策**\n"
        "1. ファイルパスの正規化 (`os.path.realpath()`) 後、許可ベースディレクトリ内に収まるか検証してください。\n"
        "2. ファイル名にはホワイトリスト形式の検証 (英数字・ドット・ハイフンのみ) を適用してください。\n"
        "3. ユーザー入力から `../`, `..\\` を除去するだけでなく、デコード後の値も検証してください。"
    ),
    "open_redirect": (
        "**オープンリダイレクト対策**\n"
        "1. リダイレクト先 URL をユーザー入力から取得しないでください。\n"
        "2. どうしても必要な場合はリダイレクト先 URL をホワイトリストで管理してください。\n"
        "3. 相対パスのみ許可し、外部 URL への直接リダイレクトを拒否してください。"
    ),
    "csrf": (
        "**CSRF 対策**\n"
        "1. 状態変更操作に CSRF トークン（ランダムな秘密値）を要求してください。\n"
        "2. `SameSite=Strict` または `SameSite=Lax` Cookie 属性を設定してください。\n"
        "3. `Origin` / `Referer` ヘッダの検証を追加してください。\n"
        "4. フレームワークの CSRF 保護機能（Django CSRF middleware 等）を有効にしてください。"
    ),
    "cors": (
        "**CORS 設定対策**\n"
        "1. `Access-Control-Allow-Origin: *` を本番環境で使用しないでください。\n"
        "2. 許可するオリジンをホワイトリストで管理し、動的に検証してください。\n"
        "3. `Access-Control-Allow-Credentials: true` は信頼できるオリジンにのみ設定してください。"
    ),
    "header_injection": (
        "**HTTPヘッダ・インジェクション対策**\n"
        "1. HTTP レスポンスヘッダに含める値からユーザー入力をサニタイズしてください。\n"
        "2. 改行文字 (`\\r`, `\\n`, `%0d`, `%0a`) を除去または拒否してください。\n"
        "3. フレームワークのヘッダ設定 API を使用し、生の文字列結合を避けてください。"
    ),
    "clickjacking": (
        "**クリックジャッキング対策**\n"
        "1. `X-Frame-Options: DENY` または `X-Frame-Options: SAMEORIGIN` ヘッダを設定してください。\n"
        "2. `Content-Security-Policy: frame-ancestors 'none'` または `frame-ancestors 'self'` を設定してください。"
    ),
    "session": (
        "**セッション管理対策**\n"
        "1. ログイン後にセッション ID を再生成してください (セッション固定攻撃対策)。\n"
        "2. Cookie に `HttpOnly`, `Secure`, `SameSite=Lax` 属性を設定してください。\n"
        "3. セッションタイムアウト（30分程度）を設定してください。\n"
        "4. 暗号学的に安全な乱数でセッション ID を生成してください（長さ128bit以上）。"
    ),
    "privesc_unauth": (
        "**認可制御対策 (未認証アクセス)**\n"
        "1. すべての保護エンドポイントで認証チェックを行ってください。\n"
        "2. 認可ミドルウェア/デコレータを一元管理してください。\n"
        "3. デフォルトで拒否し、明示的に許可する設計 (Deny-by-Default) を採用してください。"
    ),
    "privesc_vertical": (
        "**認可制御対策 (垂直権限昇格)**\n"
        "1. 管理者機能には管理者ロールチェックを実装してください。\n"
        "2. ロールベースアクセス制御 (RBAC) を一元実装してください。\n"
        "3. 機能ごとに必要なロールを明示的に定義し、コードレビューで確認してください。"
    ),
    "privesc_horizontal": (
        "**認可制御対策 (水平権限昇格 / IDOR)**\n"
        "1. ユーザーが操作するリソースの所有者確認を毎回行ってください。\n"
        "2. URL/パラメータの ID を直接使用せず、セッションのユーザー ID と照合してください。\n"
        "3. 間接オブジェクト参照 (UUID の使用等) を検討してください。"
    ),
    "info_disclosure": (
        "**情報漏洩対策**\n"
        "1. 本番環境でデバッグモード (`DEBUG=True`) を無効にしてください。\n"
        "2. エラーページに詳細なスタックトレースやパス情報を表示しないでください。\n"
        "3. 汎用エラーページを使用してください。\n"
        "4. `.env`, `backup`, `config.bak` 等の機密ファイルをウェブルートから除外してください。"
    ),
    "security_headers": (
        "**セキュリティヘッダ対策**\n"
        "1. `Content-Security-Policy` を設定してください。\n"
        "2. `X-Frame-Options: DENY` を設定してください。\n"
        "3. `X-Content-Type-Options: nosniff` を設定してください。\n"
        "4. `Strict-Transport-Security` (HSTS) を HTTPS サイトに設定してください。\n"
        "5. `Referrer-Policy` を設定してください。"
    ),
    "nosql": (
        "**NoSQLインジェクション対策**\n"
        "1. ユーザー入力を MongoDB クエリオブジェクトに直接渡さないでください。\n"
        "2. 入力の型チェックを行い、オブジェクト型を拒否してください。\n"
        "3. Mongoose では `$where` 演算子の使用を避けてください。\n"
        "4. ODM のパラメータバインディング機能を使用してください。"
    ),
    "deserialization": (
        "**デシリアライゼーション対策**\n"
        "1. 信頼できないデータをデシリアライズしないでください。\n"
        "2. JSON 等の安全なデータ形式を使用してください。\n"
        "3. デシリアライズ前に署名/整合性チェックを行ってください。\n"
        "4. Java: `ObjectInputStream` を安全なサブクラスに置き換えてください。"
    ),
    "request_smuggling": (
        "**HTTPリクエストスマグリング対策**\n"
        "1. フロントエンドとバックエンドで HTTP バージョンと `Transfer-Encoding` の扱いを統一してください。\n"
        "2. HTTP/2 エンドツーエンドを使用してください。\n"
        "3. リバースプロキシのアップデートと適切な設定確認を行ってください。"
    ),
    "ssrf": (
        "**SSRF 対策**\n"
        "1. ユーザーが指定した URL への直接リクエストを避けてください。\n"
        "2. どうしても必要な場合は許可 URL リスト (ホワイトリスト) を使用してください。\n"
        "3. 内部ネットワーク IP (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1) をブロックしてください。\n"
        "4. DNS リバインディング攻撃対策として DNS 解決後の IP も検証してください。"
    ),
    "graphql_introspection": (
        "**GraphQL イントロスペクション対策**\n"
        "1. 本番環境でイントロスペクションを無効にしてください。\n"
        "2. `__schema`, `__type` クエリを拒否するミドルウェアを設定してください。"
    ),
    "graphql_injection": (
        "**GraphQL インジェクション対策**\n"
        "1. GraphQL リゾルバでパラメータ化クエリを使用してください。\n"
        "2. 入力値のバリデーションとサニタイズを実装してください。\n"
        "3. クエリ深度・複雑度の制限を設定してください。"
    ),
    "jwt": (
        "**JWT 対策**\n"
        "1. `alg: none` を明示的に拒否してください。\n"
        "2. 強い秘密鍵 (256bit 以上のランダム値) を使用してください。\n"
        "3. `exp` (有効期限) クレームを必ず設定・検証してください。\n"
        "4. JWT ペイロードに機密情報を含めないでください。\n"
        "5. `kid` ヘッダを使う場合は安全な鍵参照のみ許可してください。"
    ),
    "cms": (
        "**CMS セキュリティ対策**\n"
        "1. CMS 本体・プラグイン・テーマを常に最新版に更新してください。\n"
        "2. 未使用プラグインを削除してください。\n"
        "3. デフォルトの管理画面 URL を変更してください。\n"
        "4. バックアップファイル (`config.php.bak` 等) をウェブルートに置かないでください。\n"
        "5. XML-RPC が不要な場合は無効にしてください (WordPress)。"
    ),
}


async def generate_fix(finding: "Finding", payload_gen: "PayloadGenerator") -> str:
    """
    Finding の脆弱性に対する修正ガイダンスを生成する。

    LLM が利用可能な場合: Claude / OpenAI / Ollama で動的生成。
    利用不可の場合: 静的テンプレートを返す。

    Parameters
    ----------
    finding     : Finding オブジェクト
    payload_gen : PayloadGenerator (LLM 設定を参照)

    Returns
    -------
    修正ガイダンス文字列 (Markdown 形式)
    """
    check_type = finding.check_type
    static = _get_static(check_type)

    # LLM が無効な場合は静的テンプレートをそのまま返す
    if payload_gen.provider == "none":
        return static

    # LLM プロンプト構築
    prompt = (
        f"You are a web security expert. A vulnerability has been found:\n"
        f"- Type: {check_type}\n"
        f"- URL: {finding.url}\n"
        f"- Field: {finding.field_name}\n"
        f"- Payload: {finding.payload}\n"
        f"- Evidence: {finding.evidence}\n\n"
        f"Provide a concise remediation guide (max 150 words) in Japanese. "
        f"Include:\n"
        f"1. Root cause\n"
        f"2. Concrete fix with code example if applicable\n"
        f"3. Prevention measures\n"
        f"Reply only with the remediation text, no preamble."
    )

    try:
        result = await payload_gen._call_llm(prompt)
        # _call_llm returns list[str] for payloads; for remediation we need raw text
        # So we use the internal methods directly
        llm_text = await _call_llm_raw(payload_gen, prompt)
        if llm_text and len(llm_text) > 20:
            return llm_text
    except Exception:
        pass

    return static


async def _call_llm_raw(payload_gen: "PayloadGenerator", prompt: str) -> str | None:
    """LLM を呼び出して生テキストを返す (JSON パース不要)。"""
    provider = payload_gen.provider

    if provider == "claude":
        client = payload_gen._get_anthropic_client()
        if not client:
            return None
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: client.messages.create(
                    model=payload_gen.claude_model,
                    max_tokens=400,
                    messages=[{"role": "user", "content": prompt}],
                ),
            )
            return response.content[0].text if response.content else None
        except Exception:
            return None

    if provider == "openai":
        import os
        import httpx
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            return None
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {api_key}"},
                    json={
                        "model": payload_gen.openai_model,
                        "messages": [{"role": "user", "content": prompt}],
                        "max_tokens": 400,
                        "temperature": 0.3,
                    },
                )
                if resp.status_code == 200:
                    return resp.json()["choices"][0]["message"]["content"]
        except Exception:
            return None

    if provider == "ollama":
        import httpx
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    f"{payload_gen.ollama_url}/api/generate",
                    json={
                        "model": payload_gen.ollama_model,
                        "prompt": prompt,
                        "stream": False,
                        "options": {"temperature": 0.3, "num_predict": 400},
                    },
                )
                if resp.status_code == 200:
                    return resp.json().get("response", "")
        except Exception:
            return None

    return None


def _get_static(check_type: str) -> str:
    """静的修正ガイダンスを返す。完全一致なければ prefix フォールバック。"""
    if check_type in _STATIC_FIX:
        return _STATIC_FIX[check_type]
    base = check_type.split("_")[0]
    return _STATIC_FIX.get(base, f"**{check_type} 対策**\n脆弱性の詳細を確認し、入力値の検証・出力のエスケープ・最小権限原則を適用してください。")
