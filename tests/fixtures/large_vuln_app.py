from __future__ import annotations

import base64
import hashlib
import hmac
import json
from urllib.parse import unquote

from fastapi import FastAPI, File, Form, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse


FLAG_HOME = "FLAG{large_fixture_public_flag}"
FLAG_SSTI = "FLAG{large_fixture_ssti_flag}"
FLAG_ADMIN = "FLAG{large_fixture_admin_panel}"
FLAG_JS_DISCOVERY = "FLAG{large_fixture_js_discovered_flag}"
FLAG_BUNDLE_DISCOVERY = "FLAG{large_fixture_bundle_discovered_flag}"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _fixture_jwt(payload: dict, secret: str = "secret") -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    head = _b64url(json.dumps(header, separators=(",", ":")).encode())
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64url(sig)}"


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
            '<a href="/go?next=/catalog">Continue</a>',
            '<a href="/nosql-login">NoSQL Login</a>',
            '<a href="/fetch?url=http://example.test/">Fetch URL</a>',
            '<a href="/graphql-lab">GraphQL Lab</a>',
            '<a href="/jwt-lab">JWT Lab</a>',
            '<a href="/cors-reflect">CORS Reflect</a>',
            '<a href="/cors-wildcard">CORS Wildcard</a>',
            '<a href="/deserialize">Deserialize</a>',
            '<a href="/ldap-login">LDAP Login</a>',
            '<a href="/xml">XML Import</a>',
            '<a href="/upload">Upload</a>',
            '<a href="/coupon">Coupon</a>',
            '<a href="/ws-lab">WebSocket Lab</a>',
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
            <a href="/header-echo?ref=safe">Header Echo</a>
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

    @app.get("/go")
    async def go(next: str = Query("/")):
        return RedirectResponse(next, status_code=302)

    @app.get("/header-echo", response_class=PlainTextResponse)
    async def header_echo(ref: str = Query("")):
        response = PlainTextResponse(f"Header echo for {ref}")
        decoded = unquote(unquote(ref))
        if "X-WscanHdrInject" in decoded:
            response.headers["X-WscanHdrInject"] = "1"
        if "wscan_session=injected" in decoded:
            response.headers["Set-Cookie"] = "wscan_session=injected; Path=/"
        return response

    @app.get("/fetch", response_class=PlainTextResponse)
    async def fetch_url(url: str = Query("")):
        decoded = unquote(unquote(url))
        if "169.254.169.254/latest/meta-data" in decoded:
            return "instance-id\ni-1234567890abcdef0\ninstance-type\nlocal-ipv4"
        if decoded.startswith("file:///etc/passwd"):
            return "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin"
        if "127.0.0.1" in decoded or "localhost" in decoded:
            return "<html><title>Internal Admin</title><body>Server: fixture</body></html>"
        return f"Fetched public resource: {decoded}"

    @app.get("/graphql-lab", response_class=HTMLResponse)
    async def graphql_lab():
        return _layout(
            "GraphQL Lab",
            """
            <p>GraphQL endpoint for scanner regression tests.</p>
            <code>/graphql</code>
            """,
        )

    @app.post("/graphql")
    async def graphql_endpoint(request: Request):
        payload = await request.json()

        def handle(operation):
            raw = str(operation)
            if "__schema" in raw:
                return {
                    "data": {
                        "__schema": {
                            "queryType": {"name": "Query"},
                            "types": [
                                {
                                    "name": "Query",
                                    "kind": "OBJECT",
                                    "fields": [
                                        {
                                            "name": "search",
                                            "args": [
                                                {"name": "query", "type": {"name": "String", "kind": "SCALAR"}}
                                            ],
                                        },
                                        {
                                            "name": "user",
                                            "args": [
                                                {"name": "id", "type": {"name": "ID", "kind": "SCALAR"}}
                                            ],
                                        },
                                        {"name": "apiToken", "args": []},
                                    ],
                                },
                                {"name": "SecretCredential", "kind": "OBJECT", "fields": []},
                            ],
                        }
                    }
                }
            if "__typename" in raw:
                return {"data": {"__typename": "Query"}}
            if "{{7*7}}" in raw or "${7*7}" in raw:
                return {"data": {"search": "template result 49"}}
            if "UNION SELECT" in raw or "' OR 1=1" in raw:
                return {"errors": [{"message": "sqlite syntax error near injected query"}]}
            if "wscan-graphql-xss" in raw:
                return {"data": {"search": "<script>alert('wscan-graphql-xss')</script>"}}
            return {"data": {"search": raw}}

        if isinstance(payload, list):
            return [handle(item) for item in payload]
        return handle(payload)

    @app.get("/jwt-lab", response_class=HTMLResponse)
    async def jwt_lab():
        token = _fixture_jwt({
            "sub": "fixture-user",
            "role": "user",
            "api_key": "fixture-secret-api-key",
        })
        response = HTMLResponse(_layout(
            "JWT Lab",
            f"""
            <p>JWT regression page</p>
            <code>{token}</code>
            """,
        ))
        response.set_cookie("token", token, httponly=True)
        return response

    @app.get("/cors-reflect", response_class=PlainTextResponse)
    async def cors_reflect(request: Request):
        origin = request.headers.get("origin", "")
        response = PlainTextResponse("cors reflection fixture")
        if origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
        return response

    @app.get("/cors-wildcard", response_class=PlainTextResponse)
    async def cors_wildcard():
        response = PlainTextResponse("cors wildcard fixture")
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response

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

    @app.get("/nosql-login", response_class=HTMLResponse)
    async def nosql_login_form():
        return _layout(
            "NoSQL Login",
            """
            <form method="post" action="/nosql-login">
              <input name="username">
              <input name="password" type="password">
              <button>Login</button>
            </form>
            """,
        )

    @app.post("/nosql-login", response_class=HTMLResponse)
    async def nosql_login(username: str = Form(""), password: str = Form("")):
        if any(token in username for token in ['"$ne"', '"$gt"', '"$regex"', "$ne", "$gt", "$regex"]):
            records = "".join(
                f"<li>user-{i}: sensitive record {FLAG_ADMIN}</li>"
                for i in range(80)
            )
            return _layout("NoSQL Admin Results", f"<ul>{records}</ul>")
        return _layout("NoSQL Login Failed", "<p>invalid login</p>")

    @app.get("/deserialize", response_class=HTMLResponse)
    async def deserialize_form():
        return _layout(
            "Deserialize",
            """
            <form method="post" action="/deserialize">
              <input name="data">
              <button>Load</button>
            </form>
            """,
        )

    @app.post("/deserialize", response_class=PlainTextResponse)
    async def deserialize(data: str = Form("")):
        if "R:99999999" in data:
            return "PHP Warning: unserialize(): Error at offset 12 of 29 bytes"
        if data.startswith("rO0ABQ"):
            return "java.io.StreamCorruptedException: invalid stream header"
        if data.startswith("gAI="):
            return "_pickle.UnpicklingError: pickle data was truncated"
        return "Loaded safe serialized value"

    @app.get("/ldap-login", response_class=HTMLResponse)
    async def ldap_login_form():
        return _layout(
            "LDAP Login",
            """
            <form method="post" action="/ldap-login">
              <input name="username">
              <input name="password" type="password">
              <button>Login</button>
            </form>
            """,
        )

    @app.post("/ldap-login", response_class=HTMLResponse)
    async def ldap_login(username: str = Form(""), password: str = Form("")):
        if ")(invalid" in username:
            return _layout("LDAP Error", "<pre>javax.naming.NamingException: bad search filter</pre>")
        if "objectClass=*" in username or "uid=*" in username:
            return _layout("LDAP Admin Panel", f"<p>Authenticated admin panel. {FLAG_ADMIN}</p>")
        return _layout("LDAP Login Failed", "<p>invalid login</p>")

    @app.get("/xml", response_class=HTMLResponse)
    async def xml_form():
        return _layout(
            "XML Import",
            """
            <form method="post" action="/xml">
              <textarea name="xml"></textarea>
              <button>Import</button>
            </form>
            """,
        )

    @app.post("/xml", response_class=PlainTextResponse)
    async def xml_import(request: Request):
        body = (await request.body()).decode(errors="ignore")
        if 'SYSTEM "file:///etc/passwd"' in body:
            return "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin"
        if "<!ENTITY lol" in body:
            return "lollollollol entity expanded"
        return "XML import accepted"

    @app.get("/upload", response_class=HTMLResponse)
    async def upload_form():
        return _layout(
            "Upload",
            """
            <form method="post" action="/upload" enctype="multipart/form-data">
              <input name="file" type="file">
              <button>Upload</button>
            </form>
            """,
        )

    @app.post("/upload", response_class=PlainTextResponse)
    async def upload(file: UploadFile = File(...)):
        data = await file.read()
        if file.filename and file.filename.endswith((".php", ".phtml", ".jsp", ".php.jpg")):
            if b"wscan-probe-jsp" in data:
                return "uploaded and executed: wscan-probe-jsp"
            if b"wscan-probe-" in data:
                return "uploaded and executed: wscan-probe-8.2"
        return f"uploaded {file.filename}"

    @app.get("/coupon", response_class=HTMLResponse)
    async def coupon_form():
        app.state.coupon_claimed = False
        return _layout(
            "Coupon",
            """
            <form method="post" action="/coupon/apply">
              <input name="coupon" value="SAVE100">
              <button>Apply</button>
            </form>
            """,
        )

    @app.post("/coupon/apply", response_class=PlainTextResponse)
    async def coupon_apply(coupon: str = Form("")):
        if not getattr(app.state, "coupon_claimed", False):
            import asyncio

            await asyncio.sleep(0.05)
            app.state.coupon_claimed = True
            return f"success coupon accepted: {coupon}"
        return "already redeemed"

    @app.get("/ws-lab", response_class=HTMLResponse)
    async def ws_lab():
        return _layout(
            "WebSocket Lab",
            """
            <script>
              window.wsLab = new WebSocket(`ws://${location.host}/ws/echo`);
              window.wsLab.onopen = () => window.wsLab.send(JSON.stringify({message: "hello"}));
            </script>
            <p>WebSocket echo lab</p>
            """,
        )

    @app.websocket("/ws/echo")
    async def ws_echo(ws: WebSocket):
        await ws.accept()
        try:
            while True:
                raw = await ws.receive_text()
                if "{{7*7}}" in raw or "${7*7}" in raw:
                    await ws.send_text("template result: 49")
                elif "wsostest123" in raw:
                    await ws.send_text("command output: wsostest123")
                elif "UNION SELECT" in raw or "' OR '1'='1" in raw:
                    await ws.send_text("sqlite syntax error near injected query")
                else:
                    await ws.send_text(raw)
        except WebSocketDisconnect:
            return

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
