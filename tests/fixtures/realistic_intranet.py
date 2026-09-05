"""
社内向けツールポータルを模した現実的フィクスチャ（注入系クラスタ用）。

``realistic_site`` がインターネット向けECサイトを模すのに対し、本フィクスチャは
社内の IT運用ポータル "Initech IT Ops Console" を模す。ネットワーク診断ツール・
外部Webhook連携・管理ログイン・ダッシュボードといった「実運用で本当にありそうな」
画面を備え、サーバサイド注入系の検査（OSコマンド注入 / SSRF / NoSQL注入 /
DOM-based XSS）を現実的な文脈で発火させる。

設計方針は ``realistic_site`` と同一：

* 仕込んだ脆弱性は全て :data:`EXPECTED_FINDINGS`（正解データ）に対応する。検出漏れ
  （false negative）はスキャナのリグレッション。
* 各脆弱エンドポイントには必ず「安全ツイン」を併設し :data:`SAFE_ENDPOINTS` に登録。
  ここでの検出は誤検知（false positive）= プログラムのバグ。
* 1エンドポイントは1脆弱性クラスのシグナルだけを出す（他クラスのシグナルは出さない／
  ``html.escape`` 等で潰す）ので正解が曖昧にならない。
"""
from __future__ import annotations

import asyncio
import html
import re

from fastapi import FastAPI, Form, Query
from fastapi.responses import HTMLResponse, PlainTextResponse


# ---------------------------------------------------------------------------
# 正解データ — tests/test_end_to_end_scan_extra.py / 単体テストが参照
# ---------------------------------------------------------------------------
EXPECTED_FINDINGS = [
    {"check": "os", "path": "/tools/ping", "field": "host",
     "note": "診断ツールが host をシェルに渡す。区切り文字+コマンドで任意実行"},
    {"check": "ssrf", "path": "/integrations/webhook-test", "field": "url",
     "note": "サーバが url を検証せず取得。内部メタデータ等に到達する"},
    {"check": "nosql", "path": "/admin/login", "field": "username",
     "note": "MongoDB 演算子オブジェクトを渡すと Mongo エラーが露出（認証回避）"},
    {"check": "dom_xss", "path": "/dashboard/widget", "field": "tab",
     "note": "クエリ tab がクライアント側で innerHTML に書き込まれる"},
]

# 検出されてはいけない入力。ここでの finding は誤検知。
SAFE_ENDPOINTS = [
    {"path": "/tools/dns-lookup", "field": "name",
     "note": "ホスト名を厳格な allow-list 正規表現で検証、シェルに渡さない"},
    {"path": "/integrations/avatar-fetch", "field": "image_url",
     "note": "https のみ・内部/メタデータ宛先は拒否してから取得"},
    {"path": "/portal/signin", "field": "username",
     "note": "資格情報を常に文字列として扱い、演算子注入を受け付けない"},
    {"path": "/dashboard/profile", "field": "bio",
     "note": "自己紹介を textContent で描画（innerHTML を使わない）"},
]


# ---------------------------------------------------------------------------
# 共有レイアウト
# ---------------------------------------------------------------------------
_NAV = [
    ('/', 'Home'),
    ('/tools/ping?host=127.0.0.1', 'Ping'),
    ('/tools/dns-lookup?name=intranet.local', 'DNS lookup'),
    ('/integrations/webhook-test?url=https://hooks.example.com/health', 'Webhook test'),
    ('/integrations/avatar-fetch?image_url=https://cdn.example.com/a.png', 'Avatar fetch'),
    ('/dashboard/widget?tab=overview', 'Dashboard'),
    ('/dashboard/profile?bio=hello', 'Profile'),
    ('/admin/login', 'Admin sign in'),
    ('/portal/signin', 'Portal sign in'),
]


def _layout(title: str, body: str, *, extra_head: str = "") -> str:
    nav = "\n".join(f'<a href="{href}">{label}</a>' for href, label in _NAV)
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>{title} — Initech IT Ops Console</title>
    {extra_head}
  </head>
  <body>
    <header>
      <a href="/" class="brand">Initech IT Ops</a>
      <nav>{nav}</nav>
    </header>
    <main>
      <h1>{title}</h1>
      {body}
    </main>
    <footer><small>Initech 社内ツール — 認可された運用担当者のみ</small></footer>
  </body>
</html>"""


# ---------------------------------------------------------------------------
# OSコマンド注入のシェル簡易シミュレータ
# ---------------------------------------------------------------------------
# 実機の `ping -c1 <host>` を `os.system` で呼ぶような実装を、外部プロセスを
# 起動せずに模す。区切り文字に続く「追記コマンド」を解釈し、代表的な出力や
# 遅延を返す（OSInjectionScanner の OS_OUTPUT_PATTERNS / 時間ベース判定に一致）。
_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
)
_ID_OUTPUT = "uid=0(root) gid=0(root) groups=0(root)\n"
_UNAME_OUTPUT = "Linux ops-host01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n"
_LS_OUTPUT = "total 48\ndrwxr-xr-x 6 root root 4096 Jan  1 00:00 .\n-rw-r--r-- 1 root root  220 Jan  1 00:00 .bashrc\n"

_SLEEP_RE = re.compile(r"sleep\s+(\d+)")


async def _simulate_shell(host: str) -> str | None:
    """注入された追記コマンドを解釈して出力を返す。注入が無ければ None。"""
    # シェル区切り文字が無ければ素直なホスト名 → 注入なし
    if not re.search(r"[;|&`]|\$\(", host):
        return None

    # 時間ベース：sleep N / ping -c N （実時間を消費する）
    m = _SLEEP_RE.search(host)
    if m:
        await asyncio.sleep(min(int(m.group(1)), 6))
        return f"PING (injected delay {m.group(1)}s)\n"
    if re.search(r"ping\s+-[cn]\s*\d", host):
        await asyncio.sleep(3)
        return "PING 127.0.0.1: 3 packets transmitted\n"

    # 出力ベース：代表的コマンドの結果を返す
    if re.search(r"cat\b.*passwd|\{cat,/etc/passwd\}|/???/p?sswd".replace("?", r"\?"), host):
        return _PASSWD
    if re.search(r"\bid\b|\$\(id\)|`id`|\{id", host):
        return _ID_OUTPUT
    if re.search(r"\buname\b", host):
        return _UNAME_OUTPUT
    if re.search(r"\bls\b", host):
        return _LS_OUTPUT
    # whoami / env 等は OS_OUTPUT_PATTERNS に該当する出力を持たないので
    # 注入は成立しているが「観測可能なシグナルなし」として空文字を返す。
    return ""


# 内部 SSRF 探索 URL → 返す内部コンテンツ（SSRFScanner の検出パターンに一致）
_SSRF_INTERNAL = [
    (re.compile(r"169\.254\.169\.254/latest/meta-data"),
     "ami-id: ami-0abc123\ninstance-id: i-0abc123def456\n"
     "instance-type: t3.medium\nlocal-ipv4: 10.0.3.17\npublic-hostname: ec2-x.compute\n"),
    (re.compile(r"metadata\.google\.internal"),
     "computeMetadata/v1/\nproject/project-id: initech-prod\n"
     "instance/service-accounts/default/token\n"),
    (re.compile(r"169\.254\.169\.254/metadata/instance"),
     '{"compute":{"subscriptionId":"00000000-0000","resourceGroupName":"rg-ops",'
     '"vmId":"abcd","location":"eastus"}}\n'),
    (re.compile(r"file:///etc/passwd"), _PASSWD),
    (re.compile(r"https?://(127\.0\.0\.1|localhost|\[::1\])"),
     "<html><head><title>Internal service</title></head>"
     "<body>Server: nginx/1.25.3 — Index of /</body></html>\n"),
]


def _fetch_url(url: str) -> tuple[bool, str]:
    """サーバサイドの「URL取得」を模す。(内部到達か, 本文) を返す。"""
    for pattern, content in _SSRF_INTERNAL:
        if pattern.search(url):
            return True, content
    if "wscan-baseline-test.invalid" in url:
        return False, "fetch error: could not resolve host\n"
    # 外部URLは内部マーカーを含まない無害なプレビューを返す
    return False, f"Fetched preview for {html.escape(url)} — 200 OK, 1.2 KB\n"


# 内部宛先（SSRF安全ツインが拒否すべきホスト）
_BLOCKED_HOST_RE = re.compile(
    r"(169\.254\.169\.254|metadata\.google\.internal|127\.0\.0\.1|localhost|\[::1\]|"
    r"10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)",
    re.I,
)


def _looks_like_mongo_operator(value: str) -> bool:
    """MongoDB演算子オブジェクト/演算子文字列かを判定。"""
    if re.search(r'\{\s*"\$\w+"', value):  # {"$ne": ...} 形式
        return True
    return bool(re.search(r"\$(ne|gt|gte|lt|regex|in|or|where|exists)\b", value))


def create_app() -> FastAPI:
    app = FastAPI(title="Initech IT Ops Console (realistic intranet fixture)")

    # ── Home ──────────────────────────────────────────────────────────────
    @app.get("/", response_class=HTMLResponse)
    async def home():
        return _layout(
            "運用コンソール",
            """
            <p>社内インフラの診断・連携・管理を行うコンソールです。</p>
            <ul>
              <li><a href="/tools/ping?host=127.0.0.1">ネットワーク疎通確認 (ping)</a></li>
              <li><a href="/integrations/webhook-test?url=https://hooks.example.com/health">Webhook 疎通テスト</a></li>
              <li><a href="/dashboard/widget?tab=overview">ダッシュボード</a></li>
              <li><a href="/admin/login">管理サインイン</a></li>
            </ul>
            <p>安全ツイン（正しく検証する版）:</p>
            <ul>
              <li><a href="/tools/dns-lookup?name=intranet.local">DNS ルックアップ (allow-list)</a></li>
              <li><a href="/integrations/avatar-fetch?image_url=https://cdn.example.com/a.png">アバター取得 (SSRF 防御)</a></li>
              <li><a href="/dashboard/profile?bio=hello">プロフィール (textContent)</a></li>
              <li><a href="/portal/signin">ポータルサインイン (文字列扱い)</a></li>
            </ul>
            """,
        )

    # ── OSコマンド注入（意図的） ────────────────────────────────────────────
    @app.get("/tools/ping", response_class=PlainTextResponse)
    async def ping(host: str = Query("127.0.0.1")):
        # VULNERABLE: host をそのままシェルに連結して実行する想定。
        injected = await _simulate_shell(host)
        if injected is not None:
            # 注入が成立：ping の通常出力に追記コマンドの結果が続く
            return (
                f"PING {host} (resolving...)\n"
                f"--- {host} ping statistics ---\n"
                f"{injected}"
            )
        return (
            f"PING {host}: 56 data bytes\n"
            f"64 bytes from {host}: icmp_seq=0 ttl=64 time=0.04 ms\n"
            f"--- {host} ping statistics ---\n"
            "1 packets transmitted, 1 received, 0% packet loss\n"
        )

    # ── OS安全ツイン：ホスト名を検証してから扱う ───────────────────────────
    @app.get("/tools/dns-lookup", response_class=PlainTextResponse)
    async def dns_lookup(name: str = Query("intranet.local")):
        # SAFE: 厳格な allow-list。英数字とドット・ハイフンのみ許可。
        if not re.fullmatch(r"[A-Za-z0-9.\-]{1,253}", name):
            return "invalid hostname"
        return f"{name} has address 10.10.0.42\n"

    # ── SSRF（意図的） ──────────────────────────────────────────────────────
    @app.get("/integrations/webhook-test", response_class=PlainTextResponse)
    async def webhook_test(url: str = Query("https://hooks.example.com/health")):
        # VULNERABLE: 宛先を検証せずサーバから取得して本文を返す。
        _internal, body = _fetch_url(url)
        return body

    # ── SSRF安全ツイン：スキーム/宛先を検証してから取得 ─────────────────────
    @app.get("/integrations/avatar-fetch", response_class=PlainTextResponse)
    async def avatar_fetch(image_url: str = Query("https://cdn.example.com/a.png")):
        # SAFE: https のみ許可し、内部/メタデータ宛先を拒否してから取得。
        if not image_url.lower().startswith("https://"):
            return "blocked: only https URLs are allowed"
        if _BLOCKED_HOST_RE.search(image_url):
            return "blocked: internal host not allowed"
        return f"avatar stored (1 image fetched from {html.escape(image_url)})\n"

    # ── NoSQL注入（意図的）：管理サインイン ─────────────────────────────────
    @app.get("/admin/login", response_class=HTMLResponse)
    async def admin_login_form():
        return _layout(
            "管理サインイン",
            """
            <form method="post" action="/admin/login">
              <label>User <input name="username"></label>
              <label>Pass <input name="password" type="password"></label>
              <button>Sign in</button>
            </form>
            """,
        )

    @app.post("/admin/login", response_class=HTMLResponse)
    async def admin_login(username: str = Form(""), password: str = Form("")):
        # VULNERABLE: 値を MongoDB クエリにそのまま展開する想定。演算子オブジェクトを
        # 渡すとドライバ層の型エラーがそのまま画面に漏れる（Mongo エラー露出）。
        if _looks_like_mongo_operator(username) or _looks_like_mongo_operator(password):
            # エラー文字列のみを出す（XSS等の他シグナルは混ぜない）
            return _layout(
                "サインインエラー",
                "<pre>MongoServerError: unknown top level operator. "
                "If you have a field name that starts with a '$' symbol, "
                "consider using $getField (BSON query failed)</pre>",
            )
        return _layout("管理サインイン", "<p>Invalid username or password.</p>")

    # ── NoSQL安全ツイン：常に文字列照合 ─────────────────────────────────────
    @app.get("/portal/signin", response_class=HTMLResponse)
    async def portal_signin_form():
        return _layout(
            "ポータルサインイン",
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
        # SAFE: 入力は常に素の文字列として等値比較。演算子は普通の文字列扱いで
        # ヒットせず、エラーも応答サイズの急増も起こさない。
        if username == "alice" and password == "CorrectHorse9":
            return _layout("ポータル", "<p>ようこそ。</p>")
        return _layout("ポータルサインイン", "<p>資格情報が正しくありません。</p>")

    # ── DOM-based XSS（意図的）：クライアント側で innerHTML に書き込む ───────
    @app.get("/dashboard/widget", response_class=HTMLResponse)
    async def dashboard_widget(tab: str = Query("overview")):
        # サーバ側では tab を本文へ反映しない（反射型XSSのシグナルを出さない）。
        # クライアント JS が location のクエリを読み innerHTML に書く点が脆弱。
        return _layout(
            "ダッシュボード",
            """
            <div id="tab-content">読み込み中…</div>
            <nav class="tabs">
              <a href="?tab=overview">概要</a>
              <a href="?tab=alerts">アラート</a>
            </nav>
            <script>
              // VULNERABLE: クエリ tab を innerHTML にそのまま書き込む
              var params = new URLSearchParams(location.search);
              var tab = params.get('tab') || 'overview';
              document.getElementById('tab-content').innerHTML = 'Tab: ' + tab;
            </script>
            """,
        )

    # ── DOM安全ツイン：textContent で描画 ──────────────────────────────────
    @app.get("/dashboard/profile", response_class=HTMLResponse)
    async def dashboard_profile(bio: str = Query("hello")):
        # サーバ側でも bio はエスケープして表示し、JS は textContent を使う。
        return _layout(
            "プロフィール",
            f"""
            <div id="bio-view">{html.escape(bio)}</div>
            <script>
              // SAFE: textContent なのでマークアップは解釈されない
              var params = new URLSearchParams(location.search);
              var bio = params.get('bio') || '';
              document.getElementById('bio-view').textContent = bio;
            </script>
            """,
        )

    return app
