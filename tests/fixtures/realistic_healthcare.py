"""
医療機関の患者ポータルを模した中〜大規模の現実的フィクスチャ。

既存の realistic_site（EC）/ realistic_intranet（社内運用）/ realistic_api（SaaS API）
と同じ思想で、患者ポータル "Cedar Valley Health Patient Portal" を模す。1 ページに
1 脆弱性だけを仕込み、**低難易度から超高難易度まで**段階的に配置する。各脆弱
エンドポイントには（注入・反射・ヘッダ系を中心に）安全ツインを併設する。

難易度の考え方（:data:`EXPECTED_FINDINGS` の ``difficulty`` で表現）:

* ``low``    … 素朴で明白（生反射・エラーベース SQLi・無検証リダイレクト 等）。
* ``medium`` … 現実的なクラス（LDAP/XXE/SSTI/CORS/CSRF/JWT/Host ヘッダ 等）。
* ``high``   … blind（boolean/time）、格納型（二段）、DOM 実行などの間接シグナル。
* ``ultra``  … 素朴な防御を**バイパス**して初めて成立（ブラックリスト回避・二重
  URL デコード・代替テンプレ構文・バックスラッシュ正規化 等）。

設計上の不変条件（既存 realistic_* と同一）:

* 仕込んだ脆弱性は全て :data:`EXPECTED_FINDINGS` に対応（検出漏れ=リグレッション）。
* 各安全ツインは :data:`SAFE_ENDPOINTS` に登録（検出されたら誤検知=バグ）。
* 1 エンドポイントは 1 シグナルのみ（他クラスの痕跡は ``html.escape`` 等で潰す）。
* 脆弱挙動は「実際の不具合がそう振る舞う形」で実装する（スキャナのシグネチャに
  合わせて作り込まない）。例: XXE は本当に外部実体を展開し /etc/passwd を反映する。
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import json
import re
import sqlite3
import time
from urllib.parse import unquote, quote

from fastapi import FastAPI, Form, Query, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)


# ---------------------------------------------------------------------------
# 正解データ — tests/test_realistic_healthcare_fixture.py / E2E が参照
# ---------------------------------------------------------------------------
EXPECTED_FINDINGS = [
    # ── low ────────────────────────────────────────────────────────────────
    {"check": "xss", "path": "/portal/search", "field": "q", "difficulty": "low",
     "note": "検索語を生で HTML 本文へ反射する古典的反射型 XSS"},
    {"check": "sqli", "path": "/billing/invoice", "field": "ref", "difficulty": "low",
     "note": "請求書参照番号を生で SQL に連結（エラーベース）"},
    {"check": "open_redirect", "path": "/auth/logout", "field": "next", "difficulty": "low",
     "note": "ログアウト後の next をそのまま 302 Location に使う"},
    {"check": "security_headers", "path": "/legacy/status", "field": None, "difficulty": "low",
     "note": "旧エッジ配信でセキュリティヘッダが軒並み欠落"},
    {"check": "info_disclosure", "path": "/.env", "field": None, "difficulty": "low",
     "note": "DB_PASSWORD/SECRET_KEY を含む .env を返す"},
    {"check": "clickjacking", "path": "/portal/embed", "field": None, "difficulty": "low",
     "note": "X-Frame-Options も frame-ancestors も無い埋め込み可能ページ"},

    # ── medium ───────────────────────────────────────────────────────────────
    {"check": "ldap", "path": "/directory/lookup", "field": "user", "difficulty": "medium",
     "note": "uid フィルタへ生展開。不正フィルタで LDAP parse エラーが露出"},
    {"check": "xxe", "path": "/records/import", "field": "xml", "difficulty": "medium",
     "note": "外部実体を有効にして検査結果 XML を解析し /etc/passwd を反映"},
    {"check": "host_header", "path": "/account/reset", "field": None, "difficulty": "medium",
     "note": "再設定リンクを Host ヘッダから組み立て、なりすまし Host を反映"},
    {"check": "sri", "path": "/portal/insights", "field": None, "difficulty": "medium",
     "note": "サードパーティ CDN の描画ライブラリを integrity 無しで読み込む"},
    {"check": "js_static", "path": "/portal/notice", "field": None, "difficulty": "medium",
     "note": "first-party JS が location.search を innerHTML へ流す（source→sink）"},
    {"check": "ssti", "path": "/messages/preview", "field": "name", "difficulty": "medium",
     "note": "宛名をテンプレートエンジンで描画（式が評価される）"},
    {"check": "path_traversal", "path": "/documents/view", "field": "doc", "difficulty": "medium",
     "note": "ドキュメントパスを包含チェック無しで結合し /etc/passwd に到達"},
    {"check": "cors", "path": "/api/v1/records/export", "field": None, "difficulty": "medium",
     "note": "任意 Origin を ACAO に反射し credentials=true を返す"},
    {"check": "csrf", "path": "/account/email-change", "field": "form[0]", "difficulty": "medium",
     "note": "メール変更の状態変更 POST フォームに CSRF トークンが無い"},
    {"check": "session", "path": "/api/v1/auth/session", "field": None, "difficulty": "medium",
     "note": "セッション Cookie を Secure/HttpOnly/SameSite 無しで発行"},
    {"check": "secret_leak", "path": "/static/vendor.js", "field": None, "difficulty": "medium",
     "note": "JS バンドルに高エントロピーの実在風キーを埋め込む"},
    {"check": "jwt_weak_secret", "path": "/api/v1/auth/token", "field": None, "difficulty": "medium",
     "note": "HS256 JWT を弱い秘密鍵 secret で署名して本文に露出"},
    {"check": "nosql", "path": "/api/v1/auth/login", "field": "username", "difficulty": "medium",
     "note": "MongoDB 演算子オブジェクトを渡すと Mongo エラーが露出（認証回避）"},
    {"check": "header_injection", "path": "/portal/locale", "field": "lang", "difficulty": "medium",
     "note": "lang をレスポンスヘッダへ反映（CRLF 注入）"},
    {"check": "dom_xss", "path": "/portal/dashboard", "field": "tab", "difficulty": "medium",
     "note": "クエリ tab がクライアント側で innerHTML に書き込まれる"},

    # ── high ─────────────────────────────────────────────────────────────────
    {"check": "sqli", "path": "/pharmacy/refill", "field": "rx", "difficulty": "high",
     "note": "boolean-based blind：真偽で応答長が大きく変わる（エラー文言なし）"},
    {"check": "sqli", "path": "/pharmacy/interactions", "field": "drug", "difficulty": "high",
     "note": "time-based blind：SLEEP 系ディレクティブで応答が遅延（エラー文言なし）"},
    {"check": "stored_xss", "path": "/community/posts", "field": "comment", "difficulty": "high",
     "note": "投稿が無エスケープで格納され、一覧 GET で生描画（二段）"},
    {"check": "os", "path": "/tools/nslookup", "field": "host", "difficulty": "high",
     "note": "blind OS コマンド注入：sleep 追記でのみ遅延（出力は返さない）"},
    {"check": "ssrf", "path": "/integrations/fetch", "field": "url", "difficulty": "high",
     "note": "サーバが url を検証せず取得し内部メタデータ等に到達"},

    # ── ultra ────────────────────────────────────────────────────────────────
    {"check": "xss", "path": "/reviews/new", "field": "text", "difficulty": "ultra",
     "note": "<script>/javascript: のみ除去する素朴な WAF。イベントハンドラで回避"},
    {"check": "sqli", "path": "/trials/search", "field": "ref", "difficulty": "ultra",
     "note": "WAF が生入力を検査するが、アプリが二重 URL デコードしてから SQL へ"},
    {"check": "path_traversal", "path": "/vault/file", "field": "name", "difficulty": "ultra",
     "note": "'..' 禁止＋拡張子チェックを二重エンコード+NULL バイトで回避"},
    {"check": "open_redirect", "path": "/sso/return", "field": "dest", "difficulty": "ultra",
     "note": "//・http(s):// は弾くが '/\\' をブラウザが // に正規化して外部遷移"},
    {"check": "ssti", "path": "/reports/render", "field": "title", "difficulty": "ultra",
     "note": "{{ }} はブロックするが代替構文 ${ } を評価してしまう"},
]

# 検出されてはいけない入力/ページ。ここでの finding は誤検知（false positive）。
SAFE_ENDPOINTS = [
    {"check": "xss", "path": "/portal/help", "field": "q",
     "note": "検索語を HTML エスケープして表示"},
    {"check": "sqli", "path": "/billing/history", "field": "sort",
     "note": "並び順を allow-list 検証、プレースホルダ使用"},
    {"check": "open_redirect", "path": "/auth/exit", "field": "to",
     "note": "同一サイトの相対パスのみ許可"},
    {"check": "security_headers", "path": "/legacy/status-secure", "field": None,
     "note": "スキャナが見るセキュリティヘッダを全付与"},
    {"check": "info_disclosure", "path": "/config/env-public", "field": None,
     "note": ".env 風だが秘密値は含まず 404 を返す"},
    {"check": "clickjacking", "path": "/portal/embed-safe", "field": None,
     "note": "X-Frame-Options: DENY と frame-ancestors 'none'"},
    {"check": "ldap", "path": "/directory/search", "field": "name",
     "note": "LDAP 特殊文字を RFC4515 でエスケープしてからフィルタへ"},
    {"check": "xxe", "path": "/records/import-safe", "field": "xml",
     "note": "DTD/外部実体を無効化して解析（defused 相当）"},
    {"check": "host_header", "path": "/account/reset-safe", "field": None,
     "note": "再設定リンクは固定の正規ホストから組み立てる"},
    {"check": "sri", "path": "/portal/insights-safe", "field": None,
     "note": "同じ CDN ライブラリを integrity + crossorigin 付きで読み込む"},
    {"check": "js_static", "path": "/portal/notice-safe", "field": None,
     "note": "同じ値を textContent で描画し危険シンクへ流さない"},
    {"check": "ssti", "path": "/messages/draft", "field": "name",
     "note": "宛名をエスケープし、テンプレート描画しない"},
    {"check": "path_traversal", "path": "/documents/manual", "field": "name",
     "note": "マニュアル ID を allow-list 化、traversal は not found"},
    {"check": "cors", "path": "/api/v1/records/export-safe", "field": None,
     "note": "固定 allowlist の Origin だけを許可"},
    {"check": "csrf", "path": "/account/email-change-safe", "field": "form[0]",
     "note": "csrf_token hidden input を持つ状態変更フォーム"},
    {"check": "session", "path": "/api/v1/auth/session-safe", "field": None,
     "note": "Secure; HttpOnly; SameSite=Lax 付きで Cookie 発行"},
    {"check": "secret_leak", "path": "/static/vendor.safe.js", "field": None,
     "note": "プレースホルダだけを含む JS バンドル"},
    {"check": "jwt_weak_secret", "path": "/api/v1/auth/token-safe", "field": None,
     "note": "十分長い秘密鍵で署名した exp 付き JWT を返す"},
    {"check": "nosql", "path": "/portal/signin", "field": "username",
     "note": "資格情報を常に文字列照合し演算子注入を受け付けない"},
    {"check": "header_injection", "path": "/portal/locale-safe", "field": "lang",
     "note": "lang から CR/LF を除去してからヘッダへ"},
    {"check": "dom_xss", "path": "/portal/dashboard-safe", "field": "tab",
     "note": "自己紹介を textContent で描画（innerHTML を使わない）"},
    {"check": "sqli", "path": "/pharmacy/catalog", "field": "drug",
     "note": "プレースホルダ使用。真偽差も遅延も生じない"},
    {"check": "stored_xss", "path": "/community/announcements", "field": "comment",
     "note": "投稿を html.escape して格納・描画"},
    {"check": "os", "path": "/tools/resolve", "field": "name",
     "note": "ホスト名を厳格 allow-list で検証、シェルに渡さない"},
    {"check": "ssrf", "path": "/integrations/avatar", "field": "image_url",
     "note": "https のみ・内部/メタデータ宛先は拒否してから取得"},
    {"check": "xss", "path": "/reviews/preview", "field": "text",
     "note": "全文を HTML エスケープして表示"},
    {"check": "path_traversal", "path": "/vault/manual", "field": "name",
     "note": "資料 ID を allow-list 化、エンコードを正規化しても traversal 不可"},
    {"check": "open_redirect", "path": "/sso/continue", "field": "dest",
     "note": "同一サイト相対パスのみ許可、'/\\' も拒否"},
    {"check": "ssti", "path": "/reports/title-safe", "field": "title",
     "note": "タイトルをエスケープし、テンプレート描画しない"},
]


# ---------------------------------------------------------------------------
# 共有レイアウト
# ---------------------------------------------------------------------------
# NOTE: ナビ文言には LDAP 認証回避判定 (welcome/dashboard/authenticated/admin panel/
# logged in) や SQL ログイン失敗判定に一致する語を入れない（差分判定の攪乱回避）。
_NAV = [
    ('/', 'Home'),
    ('/legacy/status', 'Legacy status'),
    ('/legacy/status-secure', 'Legacy status (secure)'),
    ('/portal/search?q=results', 'Search'),
    ('/billing/invoice?ref=INV-1001', 'Billing'),
    ('/pharmacy/refill?rx=RX-77', 'Pharmacy'),
    ('/records/import', 'Lab import'),
    ('/directory/lookup?user=jsmith', 'Staff directory'),
    ('/directory/search?name=jsmith', 'Staff search (safe)'),
    ('/messages/preview?name=patient', 'Messages'),
    ('/documents/view?doc=guide.pdf', 'Documents'),
    ('/community/posts', 'Community'),
    ('/portal/insights', 'Insights'),
    ('/portal/notice', 'Notices'),
    ('/portal/notice-safe', 'Notices (safe)'),
    ('/account/reset', 'Account'),
    ('/tools/nslookup?host=intranet.local', 'Tools'),
]


def _layout(title: str, body: str, *, extra_head: str = "") -> str:
    nav = "\n".join(f'<a href="{href}">{html.escape(label)}</a>' for href, label in _NAV)
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>{html.escape(title)} — Cedar Valley Health</title>
    {extra_head}
  </head>
  <body>
    <header>
      <a href="/" class="brand">Cedar Valley Health Patient Portal</a>
      <nav>{nav}</nav>
    </header>
    <main>
      <h1>{html.escape(title)}</h1>
      {body}
    </main>
    <footer><small>Cedar Valley Health — 患者ポータル（検査用フィクスチャ）</small></footer>
  </body>
</html>"""


# ---------------------------------------------------------------------------
# データベース（エラーベース SQLi 用の現実味）
# ---------------------------------------------------------------------------
_INVOICES = [
    ("INV-1001", 240.0),
    ("INV-1002", 88.5),
    ("INV-1003", 1290.0),
]
_TRIALS = [
    ("CT-APX", "Apixaban dosing in atrial fibrillation"),
    ("CT-MTX", "Methotrexate response in rheumatoid arthritis"),
]
_ALLOWED_SORTS = {"date": "id", "amount": "amount", "ref": "ref"}


def _make_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE invoices (id INTEGER PRIMARY KEY, ref TEXT, amount REAL)")
    conn.executemany(
        "INSERT INTO invoices (ref, amount) VALUES (?, ?)", _INVOICES
    )
    conn.execute("CREATE TABLE trials (id INTEGER PRIMARY KEY, code TEXT, name TEXT)")
    conn.executemany("INSERT INTO trials (code, name) VALUES (?, ?)", _TRIALS)
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# LDAP ディレクトリ簡易シミュレータ
# ---------------------------------------------------------------------------
_STAFF = {
    "jsmith": "Dr. Jordan Smith — Cardiology",
    "achen": "Dr. Amy Chen — Radiology",
    "rgupta": "Dr. Ravi Gupta — Pediatrics",
}
_LDAP_SPECIALS = set("()*\\\x00")


def _ldap_filter_is_malformed(raw_filter: str) -> bool:
    """組み立てた生フィルタ文字列が壊れている（=注入成立）かを近似判定する。"""
    if ")(" in raw_filter:
        return True
    depth = 0
    for ch in raw_filter:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return True
    return depth != 0


def _ldap_escape(value: str) -> str:
    """RFC 4515 のフィルタエスケープ（安全ツインが使用）。"""
    out = []
    for ch in value:
        if ch in _LDAP_SPECIALS:
            out.append("\\%02x" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


# ---------------------------------------------------------------------------
# XML 取込の簡易パーサ（外部実体の有効/無効）
# ---------------------------------------------------------------------------
_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
)
_WIN_INI = "[fonts]\n[extensions]\n[mci extensions]\n"

_ENTITY_DECL_RE = re.compile(
    r"""<!ENTITY\s+(?:%\s+)?(?P<name>\w+)\s+SYSTEM\s+["'](?P<uri>[^"']+)["']\s*>""",
    re.IGNORECASE,
)
_ELEMENT_TEXT_RE = re.compile(r"<root[^>]*>(?P<text>.*?)</root>", re.IGNORECASE | re.DOTALL)
_HAS_DOCTYPE_RE = re.compile(r"<!DOCTYPE", re.IGNORECASE)


def _resolve_system_uri(uri: str) -> str:
    low = uri.lower()
    if "etc/passwd" in low:
        return _PASSWD
    if "win.ini" in low:
        return _WIN_INI
    return ""


def _parse_xml_unsafe(body: str) -> str:
    """外部実体を展開する「危険な」パーサ。<root> のテキスト（実体展開後）を返す。"""
    entities: dict[str, str] = {}
    for m in _ENTITY_DECL_RE.finditer(body):
        entities[m.group("name")] = _resolve_system_uri(m.group("uri"))
    text_m = _ELEMENT_TEXT_RE.search(body)
    text = text_m.group("text") if text_m else ""
    for name, value in entities.items():
        text = text.replace(f"&{name};", value)
    return text


# ---------------------------------------------------------------------------
# テンプレートエンジン簡易シミュレータ（SSTI）
# ---------------------------------------------------------------------------
_TEMPLATE_PROBES = {
    "{{2654435761*2654435761}}": "7045744422742119121",
    "${2654435761*2654435761}": "7045744422742119121",
    "{{3*'wscan99991'}}": "wscan99991wscan99991wscan99991",
    "${3*'wscan99991'}": "wscan99991wscan99991wscan99991",
}


def _render_template(value: str) -> str:
    rendered = value
    for probe, result in _TEMPLATE_PROBES.items():
        if probe in rendered:
            rendered = rendered.replace(probe, result)
    return rendered


# ---------------------------------------------------------------------------
# boolean-based blind SQLi の真偽評価
# ---------------------------------------------------------------------------
_BOOL_CMP_RE = re.compile(r"""(\d+|'[^']*')\s*=\s*(\d+|'[^']*')""")


def _sql_condition_is_true(value: str) -> bool:
    """値に注入された AND 比較条件の真偽を評価する（簡易）。

    AND が無い通常入力は「該当あり（真）」扱い。AND の比較が偽（1=2 等）なら偽。
    """
    if not re.search(r"\bAND\b", value, re.IGNORECASE):
        return True
    # AND より後ろの最初の比較を評価する。
    after = re.split(r"\bAND\b", value, flags=re.IGNORECASE)[-1]
    m = _BOOL_CMP_RE.search(after)
    if not m:
        return True
    return m.group(1).strip() == m.group(2).strip()


# ---------------------------------------------------------------------------
# time-based blind 判定（SQLi / OS 共通の遅延ディレクティブ）
# ---------------------------------------------------------------------------
_TIME_SQL_RE = re.compile(
    r"\b(?:SLEEP|PG_SLEEP|BENCHMARK|DBMS_PIPE\.RECEIVE_MESSAGE)\s*\(|\bWAITFOR\s+DELAY\b",
    re.IGNORECASE,
)
_SLEEP_SHELL_RE = re.compile(r"sleep\s+(\d+)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# SSRF / OS シェル簡易シミュレータ
# ---------------------------------------------------------------------------
_SSRF_INTERNAL = [
    (re.compile(r"169\.254\.169\.254/latest/meta-data"),
     "ami-id: ami-0abc123\ninstance-id: i-0abc123def456\n"
     "instance-type: t3.medium\nlocal-ipv4: 10.0.3.17\n"),
    (re.compile(r"metadata\.google\.internal"),
     "computeMetadata/v1/\nproject/project-id: cedarvalley-prod\n"),
    (re.compile(r"file:///etc/passwd"), _PASSWD),
    (re.compile(r"https?://(127\.0\.0\.1|localhost|\[::1\])"),
     "<html><title>Internal service</title><body>nginx/1.25.3</body></html>\n"),
]
_BLOCKED_HOST_RE = re.compile(
    r"(169\.254\.169\.254|metadata\.google\.internal|127\.0\.0\.1|localhost|\[::1\]|"
    r"10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)",
    re.I,
)


def _fetch_url(url: str) -> str:
    for pattern, content in _SSRF_INTERNAL:
        if pattern.search(url):
            return content
    if "wscan-baseline-test.invalid" in url:
        return "fetch error: could not resolve host\n"
    return f"Fetched preview for {html.escape(url)} — 200 OK, 1.2 KB\n"


def _looks_like_mongo_operator(value: str) -> bool:
    if re.search(r'\{\s*"\$\w+"', value):
        return True
    return bool(re.search(r"\$(ne|gt|gte|lt|regex|in|or|where|exists)\b", value))


# ---------------------------------------------------------------------------
# セキュリティヘッダ / JWT / シークレット ヘルパ
# ---------------------------------------------------------------------------
SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "X-Frame-Options": "DENY",
}
# clickjacking 脆弱ページ用：frame-ancestors を持たない CSP（他ヘッダは揃えるので
# security_headers は発火させず、framing 保護だけが欠ける = clickjacking 単独シグナル）。
_FRAMELESS_CSP = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'"
_ALLOWLISTED_ORIGIN = "https://app.cedarvalley.test"
_CANONICAL_HOST = "portal.cedarvalley.test"
_CHART_SRC = "https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _fixture_jwt(payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    head = _b64url(json.dumps(header, separators=(",", ":")).encode())
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64url(sig)}"


def _jwt_payload() -> dict:
    return {
        "sub": "ptn_18f6a4",
        "tenant": "cedarvalley",
        "role": "patient",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }


def _unsafe_vendor_bundle() -> str:
    # ソース自体が secret scan に引っかからないよう実行時に連結する。
    aws_key = "AKIA" + "5JZQNVRT7H3KX9PQ"
    github_token = ("gh" + "p_") + "aBcD1234EFgh5678IJkl9012MNop3456QRst"
    stripe_key = ("s" + "k_" + "live_") + "9aQwBcVnZpYrLqWtMx7HdSeF"
    return (
        "window.cvHealth = {\n"
        '  apiBase: "/api/v1",\n'
        '  release: "2026.06.fixture",\n'
        f'  awsAccessKeyId: "{aws_key}",\n'
        f'  githubAutomationToken: "{github_token}",\n'
        f'  stripeBillingSecret: "{stripe_key}"\n'
        "};\n"
    )


def _safe_vendor_bundle() -> str:
    return (
        "window.cvHealth = {\n"
        '  apiBase: "/api/v1",\n'
        '  release: "2026.06.fixture",\n'
        '  awsAccessKeyId: "AKIAEXAMPLE000000000",\n'
        '  githubAutomationToken: "YOUR_KEY_HERE",\n'
        '  stripeBillingSecret: "sk_live_YOUR_KEY_HERE"\n'
        "};\n"
    )


def create_app() -> FastAPI:
    app = FastAPI(title="Cedar Valley Health Patient Portal (realistic healthcare fixture)")
    app.state.db = _make_db()
    app.state.posts: list[str] = []          # 格納型 XSS（生）
    app.state.announcements: list[str] = []  # 格納型 安全ツイン（エスケープ済み）

    # ── Home ──────────────────────────────────────────────────────────────
    def _crawl_link(spec: dict) -> str:
        # GET パラメータ系エンドポイントは代表的なクエリ文字列付きでリンクする。
        # こうしないとクローラがパラメータ名を field_queue に積めず、E2E で
        # ref/url/dest/title 等が未検査（false negative）になる（Codex 指摘 #1）。
        field = spec.get("field")
        if not (field and re.fullmatch(r"[A-Za-z_]\w*", field)):
            return spec["path"]
        # open_redirect 系は無効値だと 302 で実在しない先へ飛び「could not load」と
        # なってクローラが当該ページ（=フィールド）を破棄する。realistic_site の
        # `?url=/products` と同様、ロード可能な同一サイト相対パスを既定にして
        # クロール時にフィールドを確実に登録させる。
        if spec.get("check") == "open_redirect":
            return f'{spec["path"]}?{field}=/portal/search'
        return f'{spec["path"]}?{field}=sample'

    @app.get("/", response_class=HTMLResponse)
    async def home():
        links = "\n".join(
            f'<li><a href="{_crawl_link(spec)}">{spec["check"]} '
            f'({spec.get("difficulty", "safe")})</a></li>'
            for spec in EXPECTED_FINDINGS
        )
        safe_links = "\n".join(
            f'<li><a href="{_crawl_link(spec)}">{spec["check"]} (safe)</a></li>'
            for spec in SAFE_ENDPOINTS
        )
        return _layout(
            "Patient Portal",
            f"""
            <p>診察予約・検査結果・お薬・お知らせを確認できる患者ポータルです。</p>
            <h2>Services</h2>
            <ul class="portal-links">{links}</ul>
            <h2>Hardened twins</h2>
            <ul class="safe-links">{safe_links}</ul>
            """,
        )

    # =====================================================================
    # LOW 難易度
    # =====================================================================
    # ── reflected XSS（生反射） ───────────────────────────────────────────
    @app.get("/portal/search", response_class=HTMLResponse)
    async def portal_search(q: str = Query("")):
        # VULNERABLE: 検索語を生で本文へ反射する。
        return _layout(
            "Search",
            f"""
            <form method="get" action="/portal/search">
              <input name="q" value="{q}">
              <button>Search</button>
            </form>
            <p>「{q}」の検索結果は見つかりませんでした。</p>
            """,
        )

    @app.get("/portal/help", response_class=HTMLResponse)
    async def portal_help(q: str = Query("")):
        safe = html.escape(q)
        return _layout(
            "Help",
            f"""
            <form method="get" action="/portal/help">
              <input name="q" value="{safe}">
              <button>Search help</button>
            </form>
            <p>「{safe}」のヘルプ記事は見つかりませんでした。</p>
            """,
        )

    # ── error-based SQLi ──────────────────────────────────────────────────
    @app.get("/billing/invoice", response_class=HTMLResponse)
    async def billing_invoice(ref: str = Query("INV-1001")):
        db: sqlite3.Connection = app.state.db
        # VULNERABLE: 参照番号を生で連結。
        sql = f"SELECT amount FROM invoices WHERE ref = '{ref}'"
        try:
            rows = db.execute(sql).fetchall()
        except sqlite3.Error as exc:
            return _layout(
                "Billing error",
                f'<p class="error">SQLite error: {html.escape(str(exc))} '
                f'(unrecognized token while parsing query)</p>',
            )
        amount = f"${rows[0][0]:.2f}" if rows else "（該当なし）"
        return _layout("Billing", f"<p>請求額: {html.escape(amount)}</p>")

    @app.get("/billing/history", response_class=HTMLResponse)
    async def billing_history(sort: str = Query("date")):
        db: sqlite3.Connection = app.state.db
        col = _ALLOWED_SORTS.get(sort, "id")
        rows = db.execute(f"SELECT ref, amount FROM invoices ORDER BY {col}").fetchall()
        items = "\n".join(
            f"<li>{html.escape(ref)} — ${amt:.2f}</li>" for ref, amt in rows
        )
        return _layout("Billing history", f"<ul>{items}</ul>")

    # ── open redirect（無検証） ───────────────────────────────────────────
    @app.get("/auth/logout")
    async def auth_logout(next: str = Query("/")):
        # VULNERABLE: next をそのまま Location に使う。
        return RedirectResponse(next, status_code=302)

    @app.get("/auth/exit")
    async def auth_exit(to: str = Query("/")):
        target = to if to.startswith("/") and not to.startswith(("//", "/\\")) else "/"
        return RedirectResponse(target, status_code=302)

    # ── security headers 欠落 ─────────────────────────────────────────────
    @app.get("/legacy/status", response_class=HTMLResponse)
    async def legacy_status():
        body = "<p>レガシーエッジ配信のステータスページ。</p>"
        # XFO だけは付け、clickjacking 信号を出さない（security_headers 単独）。
        return HTMLResponse(body, headers={"X-Frame-Options": "DENY"})

    @app.get("/legacy/status-secure", response_class=HTMLResponse)
    async def legacy_status_secure():
        return HTMLResponse(
            "<p>強化エッジ配信のステータスページ。</p>", headers=dict(SECURITY_HEADERS)
        )

    # ── info disclosure（.env） ───────────────────────────────────────────
    @app.get("/.env", response_class=PlainTextResponse)
    async def env_file():
        return PlainTextResponse(
            "APP_ENV=production\n"
            "DB_HOST=db.internal.cedarvalley.test\n"
            "DB_PASSWORD=fixture-prod-password\n"
            "SECRET_KEY=fixture-secret-key\n"
        )

    @app.get("/config/env-public", response_class=PlainTextResponse)
    async def env_public():
        return PlainTextResponse("Not found.", status_code=404)

    # ── clickjacking ──────────────────────────────────────────────────────
    @app.get("/portal/embed", response_class=HTMLResponse)
    async def portal_embed():
        # 他のセキュリティヘッダは揃えるが framing 保護（XFO / frame-ancestors）だけが
        # 無い → clickjacking 単独シグナル（security_headers は発火させない）。
        headers = {k: v for k, v in SECURITY_HEADERS.items() if k != "X-Frame-Options"}
        headers["Content-Security-Policy"] = _FRAMELESS_CSP
        return HTMLResponse("<p>埋め込み用のミニ予約ウィジェット。</p>", headers=headers)

    @app.get("/portal/embed-safe", response_class=HTMLResponse)
    async def portal_embed_safe():
        # 全ヘッダ完備（XFO: DENY と frame-ancestors 'none' を含む）→ 両検査で安全。
        return HTMLResponse(
            "<p>埋め込み拒否のミニ予約ウィジェット。</p>", headers=dict(SECURITY_HEADERS)
        )

    # =====================================================================
    # MEDIUM 難易度
    # =====================================================================
    # ── LDAP インジェクション ─────────────────────────────────────────────
    @app.get("/directory/lookup", response_class=HTMLResponse)
    async def directory_lookup(user: str = Query("jsmith")):
        raw_filter = f"(uid={user})"  # VULNERABLE: 生展開
        if _ldap_filter_is_malformed(raw_filter):
            return _layout(
                "Directory error",
                "<pre class='error'>javax.naming.directory.InvalidSearchFilterException: "
                "Bad search filter; remaining name 'ou=staff,dc=cedarvalley,dc=test'</pre>",
            )
        entry = _STAFF.get(user)
        body = (
            f"<p>該当スタッフ: {html.escape(entry)}</p>" if entry
            else "<p>該当するスタッフは見つかりませんでした。</p>"
        )
        return _layout("Staff directory", body)

    @app.get("/directory/search", response_class=HTMLResponse)
    async def directory_search(name: str = Query("jsmith")):
        _raw = f"(uid={_ldap_escape(name)})"  # 常に well-formed
        entry = _STAFF.get(name)
        body = (
            f"<p>該当スタッフ: {html.escape(entry)}</p>" if entry
            else "<p>該当するスタッフは見つかりませんでした。</p>"
        )
        return _layout("Staff search", body)

    # ── XXE ───────────────────────────────────────────────────────────────
    @app.get("/records/import", response_class=HTMLResponse)
    async def import_form():
        return _layout(
            "Lab import",
            """
            <p>外部検査会社からの検査結果 XML を取り込みます。</p>
            <form method="post" action="/records/import">
              <textarea name="xml" rows="6" placeholder="&lt;root&gt;...&lt;/root&gt;"></textarea>
              <button>Import</button>
            </form>
            """,
        )

    @app.post("/records/import", response_class=PlainTextResponse)
    async def import_post(request: Request):
        body = (await request.body()).decode("utf-8", "replace")
        text = _parse_xml_unsafe(body)  # VULNERABLE: 外部実体を展開
        return PlainTextResponse(f"Imported lab record:\n{text}\n")

    @app.get("/records/import-safe", response_class=HTMLResponse)
    async def import_safe_form():
        return _layout(
            "Lab import (hardened)",
            """
            <p>強化版の取込（外部実体は無効化）。</p>
            <form method="post" action="/records/import-safe">
              <textarea name="xml" rows="6" placeholder="&lt;root&gt;...&lt;/root&gt;"></textarea>
              <button>Import</button>
            </form>
            """,
        )

    @app.post("/records/import-safe", response_class=PlainTextResponse)
    async def import_safe_post(request: Request):
        body = (await request.body()).decode("utf-8", "replace")
        if _HAS_DOCTYPE_RE.search(body):
            return PlainTextResponse(
                "Rejected: DTD processing is disabled for security.\n", status_code=400
            )
        text_m = _ELEMENT_TEXT_RE.search(body)
        text = text_m.group("text") if text_m else ""
        return PlainTextResponse(f"Imported lab record:\n{html.escape(text)}\n")

    # ── Host ヘッダインジェクション ───────────────────────────────────────
    @app.get("/account/reset", response_class=HTMLResponse)
    async def account_reset(request: Request):
        host = request.headers.get("host", _CANONICAL_HOST)  # VULNERABLE
        link = f"https://{host}/account/reset/confirm?token=rt_8f3a1c"
        return _layout(
            "Account",
            f'<p>再設定リンク: <a href="{link}">{html.escape(link)}</a></p>',
        )

    @app.get("/account/reset-safe", response_class=HTMLResponse)
    async def account_reset_safe():
        link = f"https://{_CANONICAL_HOST}/account/reset/confirm?token=rt_8f3a1c"
        return _layout(
            "Account (hardened)",
            f'<p>再設定リンク: <a href="{link}">{html.escape(link)}</a></p>',
        )

    # ── SRI 欠落 ───────────────────────────────────────────────────────────
    @app.get("/portal/insights", response_class=HTMLResponse)
    async def portal_insights():
        return _layout(
            "Insights",
            '<p>血圧・体重の推移を可視化します。</p><canvas id="trend"></canvas>',
            extra_head=f'<script src="{_CHART_SRC}"></script>',
        )

    @app.get("/portal/insights-safe", response_class=HTMLResponse)
    async def portal_insights_safe():
        return _layout(
            "Insights (hardened)",
            '<p>血圧・体重の推移を可視化します。</p><canvas id="trend"></canvas>',
            extra_head=(
                f'<script src="{_CHART_SRC}" crossorigin="anonymous" '
                'integrity="sha384-ENjdO4Dr2bkBIFxQpeoTz1HIcje39Wm4jDKdf19U8gI4ddQ3GYNS7NTKfAdVQSZe">'
                "</script>"
            ),
        )

    # ── js_static（source→sink） ──────────────────────────────────────────
    @app.get("/portal/notice", response_class=HTMLResponse)
    async def portal_notice():
        return _layout(
            "Notices",
            '<div id="notice">読み込み中…</div>',
            extra_head='<script src="/static/portal.js"></script>',
        )

    @app.get("/static/portal.js", response_class=PlainTextResponse)
    async def portal_js():
        js = (
            "(function () {\n"
            "  var params = new URLSearchParams(location.search);\n"
            "  var view = params.get('view') || 'summary';\n"
            "  var box = document.getElementById('notice');\n"
            "  box.innerHTML = 'Current view: ' + view;\n"
            "})();\n"
        )
        return PlainTextResponse(js, headers={"Content-Type": "application/javascript"})

    @app.get("/portal/notice-safe", response_class=HTMLResponse)
    async def portal_notice_safe():
        return _layout(
            "Notices (hardened)",
            '<div id="notice">読み込み中…</div>',
            extra_head='<script src="/static/portal.safe.js"></script>',
        )

    @app.get("/static/portal.safe.js", response_class=PlainTextResponse)
    async def portal_safe_js():
        js = (
            "(function () {\n"
            "  var params = new URLSearchParams(location.search);\n"
            "  var view = params.get('view') || 'summary';\n"
            "  var box = document.getElementById('notice');\n"
            "  box.textContent = 'Current view: ' + view;\n"
            "})();\n"
        )
        return PlainTextResponse(js, headers={"Content-Type": "application/javascript"})

    # ── SSTI ───────────────────────────────────────────────────────────────
    @app.get("/messages/preview", response_class=HTMLResponse)
    async def messages_preview(name: str = Query("patient")):
        rendered = _render_template(name)  # VULNERABLE: テンプレ評価
        return _layout("Messages", f"<p>{html.escape(rendered)} 様へのメッセージ下書き</p>")

    @app.get("/messages/draft", response_class=HTMLResponse)
    async def messages_draft(name: str = Query("patient")):
        return _layout("Messages draft", f"<p>{html.escape(name)} 様へのメッセージ下書き</p>")

    # ── path traversal ─────────────────────────────────────────────────────
    @app.get("/documents/view", response_class=PlainTextResponse)
    async def documents_view(doc: str = Query("guide.pdf")):
        decoded = unquote(unquote(doc))
        if "etc/passwd" in decoded or decoded.endswith("/passwd"):
            return PlainTextResponse(_PASSWD)
        return PlainTextResponse(f"Document: {html.escape(doc)} (placeholder PDF)")

    _MANUALS = {"guide": "利用ガイド本文…", "privacy": "プライバシー方針本文…"}

    @app.get("/documents/manual", response_class=PlainTextResponse)
    async def documents_manual(name: str = Query("guide")):
        content = _MANUALS.get(name)
        return PlainTextResponse(content if content else "Manual not found.")

    # ── CORS ─────────────────────────────────────────────────────────────────
    @app.get("/api/v1/records/export", response_class=JSONResponse)
    async def records_export(request: Request):
        origin = request.headers.get("origin", "")
        headers = {}
        if origin:  # VULNERABLE: 任意 Origin を反射
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
            headers["Vary"] = "Origin"
        return JSONResponse({"records": 12}, headers=headers)

    @app.get("/api/v1/records/export-safe", response_class=JSONResponse)
    async def records_export_safe(request: Request):
        origin = request.headers.get("origin", "")
        headers = {"Vary": "Origin"}
        if origin == _ALLOWLISTED_ORIGIN:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
        return JSONResponse({"records": 12}, headers=headers)

    # ── CSRF ─────────────────────────────────────────────────────────────────
    @app.get("/account/email-change", response_class=HTMLResponse)
    async def email_change():
        return _layout(
            "Change email",
            """
            <form method="post" action="/account/email-change">
              <label>New email <input name="email" value="patient@example.com"></label>
              <button>Update</button>
            </form>
            """,
        )

    @app.post("/account/email-change", response_class=HTMLResponse)
    async def email_change_post(email: str = Form("")):
        return _layout("Email updated", f"<p>登録メールを {html.escape(email)} に変更しました。</p>")

    @app.get("/account/email-change-safe", response_class=HTMLResponse)
    async def email_change_safe():
        return _layout(
            "Change email (hardened)",
            """
            <form method="post" action="/account/email-change-safe">
              <input type="hidden" name="csrf_token" value="fixture-csrf-token">
              <label>New email <input name="email" value="patient@example.com"></label>
              <button>Update</button>
            </form>
            """,
        )

    @app.post("/account/email-change-safe", response_class=HTMLResponse)
    async def email_change_safe_post(csrf_token: str = Form(""), email: str = Form("")):
        if csrf_token != "fixture-csrf-token":
            return _layout("Rejected", "<p>Invalid request token.</p>")
        return _layout("Email updated", f"<p>登録メールを {html.escape(email)} に変更しました。</p>")

    # ── session cookie 属性 ───────────────────────────────────────────────
    @app.get("/api/v1/auth/session", response_class=JSONResponse)
    async def auth_session():
        resp = JSONResponse({"status": "issued"})
        resp.headers["Set-Cookie"] = "cv_session=dev-session; Path=/"  # VULNERABLE
        return resp

    @app.get("/api/v1/auth/session-safe", response_class=JSONResponse)
    async def auth_session_safe():
        resp = JSONResponse({"status": "issued"})
        resp.headers["Set-Cookie"] = (
            "cv_session=prod-session; Path=/; Secure; HttpOnly; SameSite=Lax"
        )
        return resp

    # ── secret leak（JS バンドル） ────────────────────────────────────────
    @app.get("/static/vendor.js", response_class=PlainTextResponse)
    async def vendor_js():
        return PlainTextResponse(
            _unsafe_vendor_bundle(), headers={"Content-Type": "application/javascript"}
        )

    @app.get("/static/vendor.safe.js", response_class=PlainTextResponse)
    async def vendor_safe_js():
        return PlainTextResponse(
            _safe_vendor_bundle(), headers={"Content-Type": "application/javascript"}
        )

    # ── JWT 弱い秘密鍵 ────────────────────────────────────────────────────
    @app.get("/api/v1/auth/token", response_class=JSONResponse)
    async def auth_token():
        token = _fixture_jwt(_jwt_payload(), "secret")  # VULNERABLE: 弱鍵
        return JSONResponse({"access_token": token, "token_type": "Bearer"})

    @app.get("/api/v1/auth/token-safe", response_class=JSONResponse)
    async def auth_token_safe():
        token = _fixture_jwt(_jwt_payload(), "cedarvalley-fixture-signing-key-2026-strong")
        return JSONResponse({"access_token": token, "token_type": "Bearer"})

    # ── NoSQL インジェクション ────────────────────────────────────────────
    @app.get("/api/v1/auth/login", response_class=HTMLResponse)
    async def mongo_login_form():
        return _layout(
            "Provider sign in",
            """
            <form method="post" action="/api/v1/auth/login">
              <label>User <input name="username"></label>
              <label>Pass <input name="password" type="password"></label>
              <button>Sign in</button>
            </form>
            """,
        )

    @app.post("/api/v1/auth/login", response_class=HTMLResponse)
    async def mongo_login(username: str = Form(""), password: str = Form("")):
        if _looks_like_mongo_operator(username) or _looks_like_mongo_operator(password):
            return _layout(
                "Sign in error",
                "<pre>MongoServerError: unknown top level operator. "
                "If you have a field name that starts with a '$' symbol, "
                "consider using $getField (BSON query failed)</pre>",
            )
        return _layout("Provider sign in", "<p>Invalid username or password.</p>")

    @app.get("/portal/signin", response_class=HTMLResponse)
    async def portal_signin_form():
        return _layout(
            "Portal sign in",
            """
            <form method="post" action="/portal/signin">
              <label>User <input name="username"></label>
              <label>Pass <input name="password" type="password"></label>
              <button>Sign in</button>
            </form>
            """,
        )

    @app.post("/portal/signin", response_class=HTMLResponse)
    async def portal_signin(username: str = Form(""), password: str = Form("")):
        if username == "patient01" and password == "CorrectHorse9":
            return _layout("Portal", "<p>ご利用ありがとうございます。</p>")
        return _layout("Portal sign in", "<p>資格情報が正しくありません。</p>")

    # ── ヘッダインジェクション（CRLF） ────────────────────────────────────
    @app.get("/portal/locale", response_class=HTMLResponse)
    async def portal_locale(lang: str = Query("ja-JP")):
        decoded = unquote(unquote(lang))
        resp = HTMLResponse(
            _layout("Locale", f"<p>表示言語: {html.escape(lang)}</p>")
        )
        if "X-WscanHdrInject" in decoded:  # VULNERABLE: CRLF で任意ヘッダ
            resp.headers["X-WscanHdrInject"] = "1"
        if "wscan_session=injected" in decoded:
            resp.headers["Set-Cookie"] = "wscan_session=injected; Path=/"
        return resp

    @app.get("/portal/locale-safe", response_class=HTMLResponse)
    async def portal_locale_safe(lang: str = Query("ja-JP")):
        clean = lang.replace("\r", "").replace("\n", "")
        resp = HTMLResponse(_layout("Locale (hardened)", f"<p>表示言語: {html.escape(clean)}</p>"))
        return resp

    # ── DOM XSS ──────────────────────────────────────────────────────────────
    @app.get("/portal/dashboard", response_class=HTMLResponse)
    async def portal_dashboard(tab: str = Query("overview")):
        # サーバ側は tab を本文へ反映しない（反射型 XSS を出さない）。
        return _layout(
            "Dashboard",
            """
            <div id="tab-content">読み込み中…</div>
            <script>
              var params = new URLSearchParams(location.search);
              var tab = params.get('tab') || 'overview';
              document.getElementById('tab-content').innerHTML = 'Tab: ' + tab;
            </script>
            """,
        )

    @app.get("/portal/dashboard-safe", response_class=HTMLResponse)
    async def portal_dashboard_safe(tab: str = Query("overview")):
        return _layout(
            "Dashboard (hardened)",
            f"""
            <div id="tab-content">{html.escape(tab)}</div>
            <script>
              var params = new URLSearchParams(location.search);
              var tab = params.get('tab') || 'overview';
              document.getElementById('tab-content').textContent = tab;
            </script>
            """,
        )

    # =====================================================================
    # HIGH 難易度
    # =====================================================================
    # ── boolean-based blind SQLi ──────────────────────────────────────────
    @app.get("/pharmacy/refill", response_class=HTMLResponse)
    async def pharmacy_refill(rx: str = Query("RX-77")):
        # VULNERABLE: 真偽で応答が変わる（エラーは出さない）。
        if _sql_condition_is_true(rx):
            detail = (
                "<section class='rx-detail'>"
                "<p>処方箋番号: RX-77 / 状態: 調剤可能</p>"
                "<p>薬剤: Apixaban 5mg 錠 / 1回1錠 1日2回 / 30日分</p>"
                "<p>処方医: Dr. Jordan Smith（循環器内科）</p>"
                "<p>調剤薬局: Cedar Valley Pharmacy 本院店</p>"
                "<p>注意: 出血傾向・内出血・血尿等があれば直ちに連絡してください。"
                "他の抗凝固薬・NSAIDs との併用に注意。次回受診まで自己中断しないこと。</p>"
                "<p>受け取り可能時間: 平日 9:00–18:00 / 土 9:00–13:00</p>"
                "<p>再処方の可否は担当医の確認後に確定します。保険情報に変更がある場合は"
                "受付までお知らせください。ジェネリック医薬品への変更も相談可能です。</p>"
                "</section>"
            )
            return _layout("Pharmacy", detail)
        return _layout("Pharmacy", "<p>該当する処方箋はありません。</p>")

    @app.get("/pharmacy/catalog", response_class=HTMLResponse)
    async def pharmacy_catalog(drug: str = Query("apixaban")):
        # SAFE: パラメータ化相当。真偽差も遅延も生じない。
        known = {"apixaban", "methotrexate", "amoxicillin"}
        found = drug.lower() in known
        return _layout(
            "Pharmacy catalog",
            f"<p>{html.escape(drug)}: {'取扱あり' if found else '取扱なし'}</p>",
        )

    # ── time-based blind SQLi ─────────────────────────────────────────────
    @app.get("/pharmacy/interactions", response_class=HTMLResponse)
    async def pharmacy_interactions(drug: str = Query("apixaban")):
        # VULNERABLE: SLEEP 系ディレクティブで遅延（エラーも真偽差も出さない）。
        if _TIME_SQL_RE.search(drug):
            await asyncio.sleep(3)
        return _layout("Interactions", "<p>相互作用データベースを照会しました。</p>")

    # ── stored XSS（二段） ────────────────────────────────────────────────
    @app.get("/community/posts", response_class=HTMLResponse)
    async def community_posts():
        rendered = "\n".join(
            f"<article class='post'>{body}</article>" for body in app.state.posts
        )
        return _layout(
            "Community",
            f"""
            <form method="post" action="/community/posts">
              <textarea name="comment" placeholder="体験を共有"></textarea>
              <button>Post</button>
            </form>
            <section class="posts">{rendered or '<p>まだ投稿はありません。</p>'}</section>
            """,
        )

    @app.post("/community/posts")
    async def community_posts_post(comment: str = Form("")):
        app.state.posts.append(comment)  # VULNERABLE: 生のまま格納→GET で生描画
        return RedirectResponse("/community/posts", status_code=303)

    @app.get("/community/announcements", response_class=HTMLResponse)
    async def community_announcements():
        rendered = "\n".join(
            f"<article class='post'>{html.escape(body)}</article>"
            for body in app.state.announcements
        )
        return _layout(
            "Announcements",
            f"""
            <form method="post" action="/community/announcements">
              <textarea name="comment" placeholder="お知らせ"></textarea>
              <button>Post</button>
            </form>
            <section class="posts">{rendered or '<p>お知らせはありません。</p>'}</section>
            """,
        )

    @app.post("/community/announcements")
    async def community_announcements_post(comment: str = Form("")):
        app.state.announcements.append(comment)  # SAFE: エスケープして描画
        return RedirectResponse("/community/announcements", status_code=303)

    # ── blind OS コマンド注入（time-based） ──────────────────────────────
    @app.get("/tools/nslookup", response_class=PlainTextResponse)
    async def nslookup(host: str = Query("intranet.local")):
        # VULNERABLE: 区切り文字+sleep で遅延するが、コマンド出力は返さない（blind）。
        if re.search(r"[;|&`]|\$\(", host):
            m = _SLEEP_SHELL_RE.search(host)
            if m:
                await asyncio.sleep(min(int(m.group(1)), 6))
        return PlainTextResponse(f"Server: 10.10.0.2\nName: {html.escape(host)}\n")

    @app.get("/tools/resolve", response_class=PlainTextResponse)
    async def resolve(name: str = Query("intranet.local")):
        if not re.fullmatch(r"[A-Za-z0-9.\-]{1,253}", name):
            return PlainTextResponse("invalid hostname")
        return PlainTextResponse(f"{name} has address 10.10.0.42\n")

    # ── SSRF ───────────────────────────────────────────────────────────────
    @app.get("/integrations/fetch", response_class=PlainTextResponse)
    async def integrations_fetch(url: str = Query("https://hooks.example.com/health")):
        return PlainTextResponse(_fetch_url(url))  # VULNERABLE

    @app.get("/integrations/avatar", response_class=PlainTextResponse)
    async def integrations_avatar(image_url: str = Query("https://cdn.example.com/a.png")):
        if not image_url.lower().startswith("https://"):
            return PlainTextResponse("blocked: only https URLs are allowed")
        if _BLOCKED_HOST_RE.search(image_url):
            return PlainTextResponse("blocked: internal host not allowed")
        return PlainTextResponse(f"avatar stored ({html.escape(image_url)})\n")

    # =====================================================================
    # ULTRA 難易度（素朴な防御をバイパスして成立）
    # =====================================================================
    # ── XSS：<script>/javascript: のみ除去する素朴な WAF ───────────────────
    @app.get("/reviews/new", response_class=HTMLResponse)
    async def reviews_new(text: str = Query("")):
        # VULNERABLE: ブラックリストが貧弱。イベントハンドラ系は素通り。
        filtered = re.sub(r"(?i)<\s*script", "", text)
        filtered = re.sub(r"(?i)javascript:", "", filtered)
        return _layout("Review", f"<div class='review'>{filtered}</div>")

    @app.get("/reviews/preview", response_class=HTMLResponse)
    async def reviews_preview(text: str = Query("")):
        return _layout("Review preview", f"<div class='review'>{html.escape(text)}</div>")

    # ── SQLi：WAF は生入力を検査、アプリは二重デコードしてから SQL へ ──────
    @app.get("/trials/search", response_class=HTMLResponse)
    async def trials_search(request: Request):
        # WAF は「一度デコード済み」の生クエリ値だけを検査する。
        raw = request.query_params.get("ref", "")
        if re.search(r"(?i)('|union|select|--|;)", raw):
            return _layout("Blocked", "<p>Request blocked by WAF.</p>")
        # VULNERABLE: アプリがさらにもう一度 URL デコードしてから SQL に連結する。
        decoded = unquote(raw)
        db: sqlite3.Connection = app.state.db
        sql = f"SELECT name FROM trials WHERE code = '{decoded}'"
        try:
            rows = db.execute(sql).fetchall()
        except sqlite3.Error as exc:
            return _layout(
                "Trials error",
                f'<p class="error">SQLite error: {html.escape(str(exc))} '
                f'(unrecognized token while parsing query)</p>',
            )
        items = "\n".join(f"<li>{html.escape(n)}</li>" for (n,) in rows)
        return _layout("Trials", f"<ul>{items or '<li>該当なし</li>'}</ul>")

    @app.get("/trials/browse", response_class=HTMLResponse)
    async def trials_browse(ref: str = Query("")):
        db: sqlite3.Connection = app.state.db
        rows = db.execute("SELECT name FROM trials WHERE code = ?", (ref,)).fetchall()
        items = "\n".join(f"<li>{html.escape(n)}</li>" for (n,) in rows)
        return _layout("Trials browse", f"<ul>{items or '<li>該当なし</li>'}</ul>")

    # ── path traversal：'..' 禁止＋拡張子チェックを二重エンコード/NULL で回避 ─
    @app.get("/vault/file", response_class=PlainTextResponse)
    async def vault_file(request: Request):
        raw = request.query_params.get("name", "report.pdf")
        # 素朴な防御: リテラル '..' を拒否し、.pdf 拡張子のみ許可。
        if ".." in raw or not raw.endswith(".pdf"):
            return PlainTextResponse("rejected: invalid document name", status_code=400)
        # VULNERABLE: ここでさらにデコードするため %252e.. などが '..' に戻る。
        decoded = unquote(unquote(raw))
        if "etc/passwd" in decoded or decoded.endswith("/passwd"):
            return PlainTextResponse(_PASSWD)
        return PlainTextResponse(f"Document: {html.escape(raw)} (placeholder PDF)")

    _VAULT_DOCS = {"report": "検査報告書本文…", "consent": "同意書本文…"}

    @app.get("/vault/manual", response_class=PlainTextResponse)
    async def vault_manual(name: str = Query("report")):
        content = _VAULT_DOCS.get(name)
        return PlainTextResponse(content if content else "Document not found.")

    # ── open redirect：// と http(s):// は弾くが '/\' を見落とす ────────────
    @app.get("/sso/return")
    async def sso_return(dest: str = Query("/portal/search")):
        # 素朴な防御: 絶対 URL / プロトコル相対 // を拒否。
        if re.match(r"(?i)\s*(https?:)?//", dest):
            return RedirectResponse("/portal/search", status_code=302)
        # VULNERABLE: '/\' や '\/' をブラウザは // に正規化し外部遷移になる。
        return RedirectResponse(dest, status_code=302)

    @app.get("/sso/continue")
    async def sso_continue(dest: str = Query("/portal/search")):
        ok = dest.startswith("/") and not dest.startswith(("//", "/\\", "\\"))
        return RedirectResponse(dest if ok else "/portal/search", status_code=302)

    # ── SSTI：{{ }} はブロックするが代替構文 ${ } を評価してしまう ──────────
    @app.get("/reports/render", response_class=HTMLResponse)
    async def reports_render(title: str = Query("Monthly")):
        if "{{" in title or "}}" in title:
            return _layout("Report", "<p>Blocked template syntax.</p>")
        # VULNERABLE: ${ ... } 形式は評価される。
        rendered = _render_template(title)
        return _layout("Report", f"<h2>{html.escape(rendered)}</h2>")

    @app.get("/reports/title-safe", response_class=HTMLResponse)
    async def reports_title_safe(title: str = Query("Monthly")):
        return _layout("Report (hardened)", f"<h2>{html.escape(title)}</h2>")

    return app
