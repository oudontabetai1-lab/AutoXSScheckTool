from __future__ import annotations

from urllib.parse import unquote

from fastapi import FastAPI, Form, Query
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse


FLAG_HOME = "FLAG{large_fixture_public_flag}"
FLAG_SSTI = "FLAG{large_fixture_ssti_flag}"
FLAG_ADMIN = "FLAG{large_fixture_admin_panel}"
FLAG_JS_DISCOVERY = "FLAG{large_fixture_js_discovered_flag}"
FLAG_BUNDLE_DISCOVERY = "FLAG{large_fixture_bundle_discovered_flag}"


def _layout(title: str, body: str) -> str:
    nav = "\n".join(
        [
            '<a href="/">Home</a>',
            '<a href="/catalog">Catalog</a>',
            '<a href="/search?q=hello">Search</a>',
            '<a href="/support">Support</a>',
            '<a href="/tools">Tools</a>',
            '<a href="/template?name=guest">Template</a>',
            '<a href="/download?file=readme.txt">Download</a>',
            '<a href="/login">Login</a>',
            '<a href="/admin/actions">Admin Actions</a>',
            '<a href="/ctf">CTF</a>',
        ]
    )
    return f"""
    <html>
      <head>
        <title>{title}</title>
        <script src="/static/app.js"></script>
      </head>
      <body>
        <header><h1>{title}</h1><nav>{nav}</nav></header>
        <main>{body}</main>
      </body>
    </html>
    """


def create_app(page_count: int = 48) -> FastAPI:
    app = FastAPI(title="WScan large vulnerable fixture")
    app.state.tickets = []

    @app.get("/", response_class=HTMLResponse)
    async def index():
        links = "\n".join(
            f'<li><a href="/section/{i % 6}/page/{i}">Section {i % 6} page {i}</a></li>'
            for i in range(page_count)
        )
        return _layout(
            "Large Fixture Portal",
            f"""
            <p>Welcome to the large fixture. Public training flag: {FLAG_HOME}</p>
            <form method="get" action="/search">
              <input name="q" value="">
              <button>Search</button>
            </form>
            <script>
              window.largeFixtureApi = {{
                hiddenCtf: "/ctf/js-hidden?token=from-script"
              }};
            </script>
            <ul>{links}</ul>
            """,
        )

    @app.get("/catalog", response_class=HTMLResponse)
    async def catalog():
        links = "\n".join(
            f'<a href="/product/{i}?ref=homepage">Product {i}</a><br>'
            for i in range(1, page_count + 1)
        )
        return _layout("Catalog", links)

    @app.get("/section/{section}/page/{page_id}", response_class=HTMLResponse)
    async def section_page(section: int, page_id: int):
        next_id = (page_id + 1) % page_count
        return _layout(
            f"Section {section} page {page_id}",
            f"""
            <p>Repeated content page {page_id} for crawl-scale testing.</p>
            <a href="/section/{section}/page/{next_id}">Next page</a>
            <a href="/product/{page_id + 1}?ref=section">Related product</a>
            """,
        )

    @app.get("/product/{product_id}", response_class=HTMLResponse)
    async def product(product_id: int, ref: str = Query("")):
        return _layout(
            f"Product {product_id}",
            f"""
            <p>Product ref: {ref}</p>
            <form method="get" action="/product/{product_id}/review">
              <input name="comment" value="">
              <button>Preview review</button>
            </form>
            """,
        )

    @app.get("/product/{product_id}/review", response_class=HTMLResponse)
    async def product_review(product_id: int, comment: str = Query("")):
        return _layout("Review Preview", f"<article>{comment}</article>")

    @app.get("/search", response_class=HTMLResponse)
    async def search(q: str = Query("")):
        return _layout("Search", f"<p>Search result: {q}</p>")

    @app.get("/support", response_class=HTMLResponse)
    async def support_form():
        return _layout(
            "Support",
            """
            <form method="post" action="/support">
              <input name="subject" value="">
              <textarea name="message"></textarea>
              <button>Submit</button>
            </form>
            <a href="/tickets">Tickets</a>
            """,
        )

    @app.post("/support", response_class=HTMLResponse)
    async def support(subject: str = Form(""), message: str = Form("")):
        app.state.tickets.append({"subject": subject, "message": message})
        return RedirectResponse("/tickets", status_code=303)

    @app.get("/tickets", response_class=HTMLResponse)
    async def tickets():
        rendered = "\n".join(
            f"<article><h2>{ticket['subject']}</h2><p>{ticket['message']}</p></article>"
            for ticket in app.state.tickets
        )
        return _layout("Tickets", rendered or "<p>No tickets yet.</p>")

    @app.get("/tools", response_class=HTMLResponse)
    async def tools():
        return _layout(
            "Tools",
            """
            <form method="get" action="/ping">
              <input name="host" value="127.0.0.1">
              <button>Ping</button>
            </form>
            <form method="get" action="/download">
              <input name="file" value="readme.txt">
              <button>Download</button>
            </form>
            """,
        )

    @app.get("/ping", response_class=PlainTextResponse)
    async def ping(host: str = Query("")):
        if "ls -la" in host:
            return "total 8\ndrwxr-xr-x  2 wscan wscan 4096 May 11 12:00 .\n-rw-r--r--  1 wscan wscan   31 May 11 12:00 flag.txt"
        if any(token in host for token in ["; id", "| id", "&& id", "$(id)", "`id`"]):
            return "uid=1000(wscan) gid=1000(wscan) groups=1000(wscan)"
        if "cat /etc/passwd" in host:
            return "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
        return f"PING {host}: 64 bytes from {host}"

    @app.get("/download", response_class=PlainTextResponse)
    async def download(file: str = Query("")):
        decoded = unquote(unquote(file))
        if "etc/passwd" in decoded or decoded.startswith("/etc/passwd"):
            return "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin"
        if "flag" in decoded:
            return "FLAG{large_fixture_lfi_flag}"
        return f"Documentation for {file}"

    @app.get("/template", response_class=HTMLResponse)
    async def template(name: str = Query("")):
        evaluated = name
        if "{{2654435761*2654435761}}" in name:
            evaluated = name.replace("{{2654435761*2654435761}}", "7045744422742119121")
        elif "${2654435761*2654435761}" in name:
            evaluated = name.replace("${2654435761*2654435761}", "7045744422742119121")
        elif "{{3*'wscan99991'}}" in name:
            evaluated = name.replace("{{3*'wscan99991'}}", "wscan99991wscan99991wscan99991")
        if "7045744422742119121" in evaluated:
            evaluated += f" {FLAG_SSTI}"
        return _layout("Template Preview", f"<p>Hello {evaluated}</p>")

    @app.get("/login", response_class=HTMLResponse)
    async def login_form():
        return _layout(
            "Login",
            """
            <form method="post" action="/login">
              <input name="username">
              <input name="password" type="password">
              <button>Login</button>
            </form>
            """,
        )

    @app.post("/login", response_class=HTMLResponse)
    async def login(username: str = Form(""), password: str = Form("")):
        if "' OR '1'='1" in username or "' OR '1'='1" in password:
            return RedirectResponse("/admin", status_code=302)
        if username == "admin" and password == "correct-password":
            return RedirectResponse("/admin", status_code=302)
        return _layout("Login Failed", "<p>invalid login</p>")

    @app.get("/admin", response_class=HTMLResponse)
    async def admin():
        return _layout("Admin", f"<p>Admin dashboard secret. {FLAG_ADMIN}</p>")

    @app.get("/admin/actions", response_class=HTMLResponse)
    async def admin_actions():
        return _layout(
            "Admin Actions",
            """
            <form method="post" action="/admin/users/role">
              <input name="user_id" value="42">
              <input name="role" value="admin">
              <button>Change role</button>
            </form>
            """,
        )

    @app.post("/admin/users/role", response_class=HTMLResponse)
    async def admin_role_change(user_id: str = Form(""), role: str = Form("")):
        return _layout(
            "Role Changed",
            f"<p>Changed user {user_id} to {role}. {FLAG_ADMIN}</p>",
        )

    @app.get("/ctf", response_class=HTMLResponse)
    async def ctf():
        return _layout(
            "CTF Training",
            """
            <p>Find flags through crawl, injection, and file read challenges.</p>
            <a href="/ctf/public">Public flag</a>
            <a href="/template?name=guest">SSTI challenge</a>
            <a href="/download?file=flag.txt">File challenge</a>
            """,
        )

    @app.get("/ctf/public", response_class=HTMLResponse)
    async def ctf_public():
        return _layout("Public Flag", "<code>CTF{large_fixture_ctf_public}</code>")

    @app.get("/ctf/js-hidden", response_class=HTMLResponse)
    async def ctf_js_hidden(token: str = Query("")):
        if token == "from-script":
            return _layout("Script Discovered Flag", f"<code>{FLAG_JS_DISCOVERY}</code>")
        return _layout("Script Discovered Flag", "<p>missing token</p>")

    @app.get("/static/app.js", response_class=PlainTextResponse)
    async def static_app_js():
        return """
        window.largeFixtureBundle = {
          hiddenCtf: "/ctf/bundle-hidden?token=from-bundle"
        };
        """

    @app.get("/ctf/bundle-hidden", response_class=HTMLResponse)
    async def ctf_bundle_hidden(token: str = Query("")):
        if token == "from-bundle":
            return _layout("Bundle Discovered Flag", f"<code>{FLAG_BUNDLE_DISCOVERY}</code>")
        return _layout("Bundle Discovered Flag", "<p>missing token</p>")

    return app
