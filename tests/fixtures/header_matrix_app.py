from fastapi import FastAPI
from fastapi.responses import HTMLResponse


SAFE_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def _page(title: str, body: str, headers: dict[str, str]) -> HTMLResponse:
    html = f"""
    <html>
      <head><title>{title}</title></head>
      <body>
        <h1>{title}</h1>
        <nav>
          <a href="/safe">Safe headers</a>
          <a href="/missing">Missing headers</a>
          <a href="/unsafe-csp">Unsafe CSP</a>
          <a href="/short-hsts">Short HSTS</a>
        </nav>
        <main>{body}</main>
      </body>
    </html>
    """
    return HTMLResponse(html, headers=headers)


def create_app() -> FastAPI:
    app = FastAPI(title="WScan header matrix fixture")

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return _page(
            "Header Matrix",
            "<p>Root is fully configured; linked pages exercise header edge cases.</p>",
            dict(SAFE_HEADERS),
        )

    @app.get("/safe", response_class=HTMLResponse)
    async def safe():
        return _page("Safe Headers", "<p>No security header finding expected.</p>", dict(SAFE_HEADERS))

    @app.get("/missing", response_class=HTMLResponse)
    async def missing():
        headers = dict(SAFE_HEADERS)
        headers.pop("Permissions-Policy")
        return _page("Missing Header", "<p>Exactly one missing header expected.</p>", headers)

    @app.get("/unsafe-csp", response_class=HTMLResponse)
    async def unsafe_csp():
        headers = dict(SAFE_HEADERS)
        headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'"
        return _page("Unsafe CSP", "<p>Unsafe inline CSP expected.</p>", headers)

    @app.get("/short-hsts", response_class=HTMLResponse)
    async def short_hsts():
        headers = dict(SAFE_HEADERS)
        headers["Strict-Transport-Security"] = "max-age=60"
        return _page("Short HSTS", "<p>Short HSTS max-age expected.</p>", headers)

    return app
