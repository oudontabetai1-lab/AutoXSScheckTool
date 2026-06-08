"""
Acme Cloud Console の現実寄り REST/API フィクスチャ。

既存の realistic_site.py と同じ考え方で、各脆弱エンドポイントは
1種類の検査シグナルだけを出し、対応する安全ツインを併設する。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import time

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response


# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------
EXPECTED_FINDINGS = [
    {
        "check": "security_headers",
        "path": "/console/insecure",
        "field": None,
        "note": "HSTS/CSP/XCTO/Referrer/Permissions/COOP が欠落",
    },
    {
        "check": "clickjacking",
        "path": "/console/embed",
        "field": None,
        "note": "X-Frame-Options と CSP frame-ancestors がどちらも無い",
    },
    {
        "check": "cors",
        "path": "/api/v1/reports/export",
        "field": None,
        "note": "任意 Origin を ACAO に反射し credentials=true を返す",
    },
    {
        "check": "session",
        "path": "/api/v1/session/issue",
        "field": "Cookie: acme_session",
        "note": "セッション風 Cookie を Secure/HttpOnly/SameSite 無しで発行",
    },
    {
        "check": "csrf",
        "path": "/console/billing/payment-method",
        "field": "form[0]",
        "note": "状態変更 POST フォームに CSRF トークンが無い",
    },
    {
        "check": "info_disclosure",
        "path": "/.env",
        "field": None,
        "note": "DB_PASSWORD/SECRET_KEY を含む .env を返す",
    },
    {
        "check": "info_disclosure",
        "path": "/console/debug-error",
        "field": None,
        "note": "Python Traceback を含む詳細エラーページを返す",
    },
    {
        "check": "secret_leak",
        "path": "/static/console.js",
        "field": None,
        "note": "JS バンドルに高エントロピーの実在風キーを埋め込む",
    },
    {
        "check": "jwt_weak_secret",
        "path": "/api/v1/session/bootstrap",
        "field": None,
        "note": "HS256 JWT を弱い秘密鍵 secret で署名してレスポンス本文に露出",
    },
]

SAFE_ENDPOINTS = [
    {
        "check": "security_headers",
        "path": "/console/secure",
        "field": None,
        "note": "スキャナが見るセキュリティヘッダをすべて付与",
    },
    {
        "check": "clickjacking",
        "path": "/console/embed-safe",
        "field": None,
        "note": "X-Frame-Options: DENY と CSP frame-ancestors 'none' を付与",
    },
    {
        "check": "cors",
        "path": "/api/v1/reports/export-safe",
        "field": None,
        "note": "固定 allowlist の Origin だけを許可",
    },
    {
        "check": "session",
        "path": "/api/v1/session/issue-safe",
        "field": "Cookie: acme_session",
        "note": "Secure; HttpOnly; SameSite=Lax 付きで Cookie を発行",
    },
    {
        "check": "csrf",
        "path": "/console/billing/payment-method-safe",
        "field": "form[0]",
        "note": "csrf_token hidden input を持つ状態変更フォーム",
    },
    {
        "check": "info_disclosure",
        "path": "/safe/.env",
        "field": None,
        "note": ".env は 404 で本文にも秘密値を含めない",
    },
    {
        "check": "info_disclosure",
        "path": "/console/safe-error",
        "field": None,
        "note": "汎用エラーメッセージだけを返す",
    },
    {
        "check": "secret_leak",
        "path": "/static/console.safe.js",
        "field": None,
        "note": "プレースホルダだけを含む JS バンドル",
    },
    {
        "check": "jwt_weak_secret",
        "path": "/api/v1/session/bootstrap-safe",
        "field": None,
        "note": "十分長い秘密鍵で署名した exp 付き JWT を返す",
    },
]


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
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Frame-Options": "DENY",
}

_FRAMELESS_CSP = (
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'"
)
_ALLOWLISTED_ORIGIN = "https://app.acme-cloud.test"
_CSRF_TOKEN_NAMES = {
    "csrf",
    "csrftoken",
    "csrf_token",
    "_csrf",
    "_token",
    "token",
    "authenticity_token",
    "nonce",
}

_NAV = [
    ("/", "Overview"),
    ("/console/insecure", "Header audit"),
    ("/console/secure", "Secure header twin"),
    ("/console/embed", "Embedded dashboards"),
    ("/console/embed-safe", "Protected dashboards"),
    ("/api/v1/reports/export", "Report API"),
    ("/api/v1/reports/export-safe", "Report API safe"),
    ("/api/v1/session/issue", "Session issue"),
    ("/api/v1/session/issue-safe", "Session issue safe"),
    ("/console/billing/payment-method", "Billing"),
    ("/console/billing/payment-method-safe", "Billing safe"),
    ("/console/debug-error", "Debug error"),
    ("/console/safe-error", "Safe error"),
    ("/static/console.js", "Console bundle"),
    ("/static/console.safe.js", "Safe bundle"),
    ("/api/v1/session/bootstrap", "JWT bootstrap"),
    ("/api/v1/session/bootstrap-safe", "JWT bootstrap safe"),
]


def _with_security_headers(headers: dict[str, str | None] | None = None) -> dict[str, str]:
    merged = dict(SECURITY_HEADERS)
    if headers:
        for name, value in headers.items():
            if value is None:
                merged.pop(name, None)
            else:
                merged[name] = value
    return merged


def _layout(title: str, body: str, *, headers: dict[str, str | None] | None = None) -> HTMLResponse:
    nav = "\n".join(f'<a href="{href}">{html.escape(label)}</a>' for href, label in _NAV)
    page = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>{html.escape(title)} - Acme Cloud Console</title>
    <script src="/static/console.safe.js"></script>
  </head>
  <body>
    <header>
      <a href="/" class="brand">Acme Cloud Console</a>
      <nav>{nav}</nav>
    </header>
    <main>
      <h1>{html.escape(title)}</h1>
      {body}
    </main>
    <footer><small>Acme Cloud Console tenant-admin fixture</small></footer>
  </body>
</html>"""
    return HTMLResponse(page, headers=_with_security_headers(headers))


def _json(payload: dict, *, headers: dict[str, str | None] | None = None) -> JSONResponse:
    return JSONResponse(payload, headers=_with_security_headers(headers))


def _text(
    body: str,
    *,
    status_code: int = 200,
    headers: dict[str, str | None] | None = None,
) -> PlainTextResponse:
    return PlainTextResponse(
        body,
        status_code=status_code,
        headers=_with_security_headers(headers),
    )


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
        "sub": "usr_18f6a4",
        "tenant": "acme-prod",
        "role": "analyst",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }


def _unsafe_console_bundle() -> str:
    # ソースコード自体が secret scan に引っかからないよう、値は実行時に連結する。
    aws_key = "AKIA" + "5JZQNVRT7H3KX9PQ"
    github_token = ("gh" + "p_") + "aBcD1234EFgh5678IJkl9012MNop3456QRst"
    stripe_key = ("s" + "k_" + "live_") + "9aQwBcVnZpYrLqWtMx7HdSeF"
    return f"""
window.acmeConsole = {{
  apiBase: "/api/v1",
  release: "2026.06.fixture",
  supportRegion: "us-east-1",
  awsAccessKeyId: "{aws_key}",
  githubAutomationToken: "{github_token}",
  stripeBillingSecret: "{stripe_key}"
}};
"""


def _safe_console_bundle() -> str:
    return """
window.acmeConsole = {
  apiBase: "/api/v1",
  release: "2026.06.fixture",
  supportRegion: "us-east-1",
  awsAccessKeyId: "AKIAEXAMPLE000000000",
  githubAutomationToken: "YOUR_KEY_HERE",
  stripeBillingSecret: "sk_live_YOUR_KEY_HERE"
};
"""


def create_app() -> FastAPI:
    app = FastAPI(title="Acme Cloud Console realistic API fixture")

    @app.get("/", response_class=HTMLResponse)
    async def home():
        metrics = """
        <section class="metrics">
          <article><h2>Workspaces</h2><p>42 active tenants</p></article>
          <article><h2>Deployments</h2><p>1,284 changes this week</p></article>
          <article><h2>Incidents</h2><p>0 open critical incidents</p></article>
        </section>
        <form method="post" action="/console/billing/payment-method-safe">
          <input type="hidden" name="csrf_token" value="home-token">
          <input name="card_id" value="pm_demo">
          <button>Update billing preview</button>
        </form>
        """
        return _layout("Operations Overview", metrics)

    @app.get("/console/insecure", response_class=HTMLResponse)
    async def insecure_headers():
        body = """
        <p>Legacy tenant-status view served by an old edge configuration.</p>
        <table><tr><th>Tenant</th><th>Status</th></tr><tr><td>acme-prod</td><td>green</td></tr></table>
        """
        # security_headers 専用。XFO だけは入れてクリックジャッキング信号を抑える。
        return HTMLResponse(body, headers={"X-Frame-Options": "DENY"})

    @app.get("/console/secure", response_class=HTMLResponse)
    async def secure_headers():
        return _layout(
            "Hardened Tenant Status",
            "<p>Same status data served through the hardened console edge.</p>",
        )

    @app.get("/console/embed", response_class=HTMLResponse)
    async def embeddable_dashboard():
        body = """
        <p>Partner embedding preview for deployment-health dashboards.</p>
        <iframe title="preview" src="/console/secure"></iframe>
        """
        # CSP はあるが frame-ancestors が無いので clickjacking だけが残る。
        return _layout(
            "Embed Preview",
            body,
            headers={
                "Content-Security-Policy": _FRAMELESS_CSP,
                "X-Frame-Options": None,
            },
        )

    @app.get("/console/embed-safe", response_class=HTMLResponse)
    async def embeddable_dashboard_safe():
        return _layout("Protected Embed Preview", "<p>Embedding is explicitly denied.</p>")

    @app.get("/api/v1/reports/export", response_class=JSONResponse)
    async def export_report(request: Request):
        origin = request.headers.get("origin", "")
        headers = {}
        if origin:
            # VULNERABLE: wscan の canary Origin もそのまま反射する。
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
            headers["Vary"] = "Origin"
        return _json({"report": "monthly-usage", "rows": 128}, headers=headers)

    @app.get("/api/v1/reports/export-safe", response_class=JSONResponse)
    async def export_report_safe(request: Request):
        origin = request.headers.get("origin", "")
        headers = {"Vary": "Origin"}
        if origin == _ALLOWLISTED_ORIGIN:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
        return _json({"report": "monthly-usage", "rows": 128}, headers=headers)

    @app.get("/api/v1/session/issue", response_class=JSONResponse)
    async def issue_session():
        response = _json({"status": "issued", "user": "billing-admin"})
        # VULNERABLE: Cookie 属性をあえて付けない。
        response.headers["Set-Cookie"] = "acme_session=dev-console-session; Path=/"
        return response

    @app.get("/api/v1/session/issue-safe", response_class=JSONResponse)
    async def issue_session_safe():
        response = _json({"status": "issued", "user": "billing-admin"})
        response.headers["Set-Cookie"] = (
            "acme_session=prod-console-session; Path=/; Secure; HttpOnly; SameSite=Lax"
        )
        return response

    @app.get("/console/billing/payment-method", response_class=HTMLResponse)
    async def payment_method():
        return _layout(
            "Billing Payment Method",
            """
            <form method="post" action="/console/billing/payment-method">
              <label>Payment method <input name="card_id" value="pm_live_4242"></label>
              <button>Set default</button>
            </form>
            """,
        )

    @app.post("/console/billing/payment-method", response_class=HTMLResponse)
    async def payment_method_post(card_id: str = Form("")):
        return _layout(
            "Billing Updated",
            f"<p>Default payment method changed to {html.escape(card_id)}.</p>",
        )

    @app.get("/console/billing/payment-method-safe", response_class=HTMLResponse)
    async def payment_method_safe():
        return _layout(
            "Billing Payment Method Safe",
            """
            <form method="post" action="/console/billing/payment-method-safe">
              <input type="hidden" name="csrf_token" value="fixture-csrf-token">
              <label>Payment method <input name="card_id" value="pm_live_4242"></label>
              <button>Set default</button>
            </form>
            """,
        )

    @app.post("/console/billing/payment-method-safe", response_class=HTMLResponse)
    async def payment_method_safe_post(
        csrf_token: str = Form(""),
        card_id: str = Form(""),
    ):
        if csrf_token != "fixture-csrf-token":
            return _layout("Billing Rejected", "<p>Invalid request token.</p>")
        return _layout(
            "Billing Updated",
            f"<p>Default payment method changed to {html.escape(card_id)}.</p>",
        )

    @app.get("/.env", response_class=PlainTextResponse)
    async def env_file():
        return _text(
            "APP_ENV=production\n"
            "DB_HOST=db.internal.acme-cloud.test\n"
            "DB_PASSWORD=fixture-prod-password\n"
            "SECRET_KEY=fixture-secret-key\n"
        )

    @app.get("/safe/.env", response_class=PlainTextResponse)
    async def env_file_safe():
        return _text("Not found.", status_code=404)

    @app.get("/console/debug-error", response_class=HTMLResponse)
    async def debug_error():
        body = """
        <pre>Traceback (most recent call last):
  File "/srv/acme/console/views.py", line 88, in tenant_usage
    rows = usage_repo.load_tenant("acme-prod")
RuntimeError: fixture billing warehouse timeout
</pre>
        """
        return _layout("Debug Error", body)

    @app.get("/console/safe-error", response_class=HTMLResponse)
    async def safe_error():
        return _layout(
            "Service Notice",
            "<p>We could not load usage details. Please retry later.</p>",
        )

    @app.get("/static/console.js", response_class=PlainTextResponse)
    async def console_js():
        return _text(_unsafe_console_bundle(), headers={"Content-Type": "application/javascript"})

    @app.get("/static/console.safe.js", response_class=PlainTextResponse)
    async def console_safe_js():
        return _text(_safe_console_bundle(), headers={"Content-Type": "application/javascript"})

    @app.get("/api/v1/session/bootstrap", response_class=JSONResponse)
    async def jwt_bootstrap():
        token = _fixture_jwt(_jwt_payload(), "secret")
        return _json({"access_token": token, "token_type": "Bearer"})

    @app.get("/api/v1/session/bootstrap-safe", response_class=JSONResponse)
    async def jwt_bootstrap_safe():
        token = _fixture_jwt(
            _jwt_payload(),
            "acme-console-fixture-signing-key-2026-strong",
        )
        return _json({"access_token": token, "token_type": "Bearer"})

    @app.options("/api/v1/reports/export")
    async def export_report_preflight(request: Request):
        origin = request.headers.get("origin", "")
        headers = {
            "Access-Control-Allow-Methods": "GET, OPTIONS",
            "Access-Control-Allow-Headers": "authorization, content-type",
        }
        if origin:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
        return Response(status_code=204, headers=_with_security_headers(headers))

    @app.options("/api/v1/reports/export-safe")
    async def export_report_safe_preflight(request: Request):
        origin = request.headers.get("origin", "")
        headers = {
            "Access-Control-Allow-Methods": "GET, OPTIONS",
            "Access-Control-Allow-Headers": "authorization, content-type",
            "Vary": "Origin",
        }
        if origin == _ALLOWLISTED_ORIGIN:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
        return Response(status_code=204, headers=_with_security_headers(headers))

    return app


def form_has_csrf_token(html_body: str) -> bool:
    """テスト用: CSRFScanner と同じ名前規則で token field を確認する。"""
    lowered = html_body.lower()
    return any(f'name="{name}"' in lowered or f"name='{name}'" in lowered for name in _CSRF_TOKEN_NAMES)
