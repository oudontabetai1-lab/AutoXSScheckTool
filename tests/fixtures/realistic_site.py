"""
Realistic web-application fixture for end-to-end scanner testing.

Unlike ``large_vuln_app`` (a flat "lab" of obviously-vulnerable probe
endpoints), this fixture models the structure of a real site — a small
e-commerce / support portal ("Northwind Outfitters") with a shared layout,
navigation, product pages, search, auth, a review board, and an account
area.

The point is to exercise the *whole program* (crawl → plan → attack →
verify) the way it runs against a real target, and to make scanner bugs
easy to surface:

* Every planted vulnerability has an entry in :data:`EXPECTED_FINDINGS`
  (ground truth — the scanner MUST detect it: guards against false
  negatives / regressions that silence a scanner).
* Every safe input has an entry in :data:`SAFE_ENDPOINTS` and is written
  to be genuinely safe across *all* checks (properly escaped output,
  allow-listed parameters, parameterised queries). A finding on any of
  these is a false positive — a real bug in the program.

Each vulnerable endpoint exposes exactly ONE vulnerability class on a given
field so the ground truth stays unambiguous: only ``/search`` reflects user
input raw (the intentional reflected XSS); every other endpoint
HTML-escapes user input in the page body and leaks only its own dedicated
signal.
"""
from __future__ import annotations

import html
import sqlite3
from urllib.parse import quote, unquote

from fastapi import FastAPI, Form, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse


# ---------------------------------------------------------------------------
# Ground truth — consumed by tests/test_end_to_end_scan.py
# ---------------------------------------------------------------------------
# Each entry: the scanner check family that MUST fire, the path it lives on,
# and the input field / query-parameter name it is reachable through.
EXPECTED_FINDINGS = [
    {"check": "xss", "path": "/search", "field": "q",
     "note": "reflected, unescaped query echoed into HTML body"},
    {"check": "xss", "path": "/track", "field": "ref",
     "note": "attribute-breakout: angle brackets stripped but quote passes; "
             "onmouseover handler fires only via the active event-trigger layer"},
    {"check": "sqli", "path": "/products", "field": "category",
     "note": "error-based: raw category interpolated into SQL"},
    {"check": "sqli", "path": "/login", "field": "username",
     "note": "auth bypass: ' OR '1'='1 logs in as the first user"},
    {"check": "ssti", "path": "/greeting", "field": "name",
     "note": "name rendered through a template engine"},
    {"check": "path_traversal", "path": "/files/download", "field": "doc",
     "note": "doc path joined without containment, reaches /etc/passwd"},
    {"check": "open_redirect", "path": "/redirect", "field": "url",
     "note": "url used verbatim as 302 Location"},
    {"check": "header_injection", "path": "/locale", "field": "lang",
     "note": "lang reflected into a response header (CRLF)"},
]

# Stored XSS spans two requests (inject on POST /reviews, observe on GET
# /reviews) and depends on the chain scanner; asserted separately/optionally.
EXPECTED_STORED_XSS = {"check": "stored_xss", "path": "/reviews", "field": "comment"}

# Inputs that must NEVER produce a finding. A finding here == false positive.
SAFE_ENDPOINTS = [
    {"path": "/help", "field": "query",
     "note": "search term HTML-escaped before display"},
    {"path": "/catalog", "field": "sort",
     "note": "sort key validated against an allow-list, parameterised query"},
    {"path": "/welcome", "field": "name",
     "note": "name HTML-escaped, never template-rendered"},
    {"path": "/track/safe", "field": "ref",
     "note": "ref HTML-escaped (quotes neutralised), no attribute breakout"},
    {"path": "/account/delete", "field": "item",
     "note": "item HTML-escaped; page has its own legitimate confirm() button "
             "that the firing layer must not mis-trigger as XSS"},
    {"path": "/files/manual", "field": "name",
     "note": "manual id allow-listed, traversal returns 'not found'"},
    {"path": "/account/continue", "field": "next",
     "note": "only same-site relative paths accepted as redirect target"},
]


# ---------------------------------------------------------------------------
# Shared layout
# ---------------------------------------------------------------------------
_NAV = [
    ('/', 'Home'),
    ('/search?q=jacket', 'Search'),
    ('/help?query=returns', 'Help'),
    ('/products?category=outerwear', 'Products'),
    ('/catalog?sort=price', 'Catalog'),
    ('/greeting?name=guest', 'Greeting'),
    ('/welcome?name=guest', 'Welcome'),
    ('/track?ref=home', 'Tracking'),
    ('/account/delete?item=draft', 'Delete item'),
    ('/files/download?doc=catalog.pdf', 'Brochure'),
    ('/files/manual?name=sizing', 'Size guide'),
    ('/redirect?url=/products', 'Partner link'),
    ('/account/continue?next=/account/profile', 'Continue'),
    ('/locale?lang=en-US', 'Language'),
    ('/login', 'Sign in'),
    ('/reviews', 'Reviews'),
    ('/account/profile', 'My account'),
]


def _layout(title: str, body: str, *, extra_head: str = "") -> str:
    nav = "\n".join(f'<a href="{href}">{label}</a>' for href, label in _NAV)
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>{title} — Northwind Outfitters</title>
    {extra_head}
  </head>
  <body>
    <header>
      <a href="/" class="brand">Northwind Outfitters</a>
      <nav>{nav}</nav>
    </header>
    <main>
      <h1>{title}</h1>
      {body}
    </main>
    <footer><small>&copy; Northwind Outfitters — demo storefront</small></footer>
  </body>
</html>"""


# A tiny in-memory product catalogue, used so the SQL endpoints look real.
_PRODUCTS = [
    (1, "Trailhead Jacket", "outerwear", 189.0),
    (2, "Summit Down Parka", "outerwear", 329.0),
    (3, "Riverbank Boots", "footwear", 145.0),
    (4, "Basecamp Backpack", "bags", 99.0),
    (5, "Anorak Shell", "outerwear", 159.0),
]
_ALLOWED_SORTS = {
    "relevance": "id",
    "price": "price",
    "name": "name",
}


def _make_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute(
        "CREATE TABLE products (id INTEGER, name TEXT, category TEXT, price REAL)"
    )
    conn.executemany("INSERT INTO products VALUES (?, ?, ?, ?)", _PRODUCTS)
    conn.execute("CREATE TABLE users (id INTEGER, username TEXT, password TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'alice', 'CorrectHorse9')")
    conn.execute("INSERT INTO users VALUES (2, 'bob', 'hunter2-battery')")
    conn.commit()
    return conn


def create_app() -> FastAPI:
    app = FastAPI(title="Northwind Outfitters (realistic fixture)")
    app.state.db = _make_db()
    app.state.reviews = []  # list of stored review bodies

    # ── Home ────────────────────────────────────────────────────────────
    @app.get("/", response_class=HTMLResponse)
    async def home():
        cards = "\n".join(
            f'<article class="product"><h3>{html.escape(name)}</h3>'
            f'<p>{html.escape(category)} · ${price:.0f}</p>'
            f'<a href="/products?category={quote(category)}">More {html.escape(category)}</a>'
            f"</article>"
            for _id, name, category, price in _PRODUCTS
        )
        return _layout(
            "Welcome",
            f"""
            <p>Outdoor gear for every trail.</p>
            <form method="get" action="/search">
              <input name="q" placeholder="Search products" value="">
              <button>Search</button>
            </form>
            <section class="catalogue">{cards}</section>
            """,
        )

    # ── Reflected XSS (INTENTIONAL): query echoed raw ─────────────────────
    @app.get("/search", response_class=HTMLResponse)
    async def search(q: str = Query("")):
        # VULNERABLE: user input reflected without escaping.
        return _layout(
            "Search results",
            f"""
            <form method="get" action="/search">
              <input name="q" value="{q}">
              <button>Search</button>
            </form>
            <p>You searched for: {q}</p>
            <p>No products matched. Try a broader term.</p>
            """,
        )

    # ── Safe search twin: query is HTML-escaped ───────────────────────────
    @app.get("/help", response_class=HTMLResponse)
    async def help_search(query: str = Query("")):
        safe = html.escape(query)
        return _layout(
            "Help center",
            f"""
            <form method="get" action="/help">
              <input name="query" value="{safe}">
              <button>Search help</button>
            </form>
            <p>We found no help articles for "{safe}".</p>
            <ul><li>Shipping &amp; returns</li><li>Order tracking</li></ul>
            """,
        )

    # ── Interaction-required reflected XSS (INTENTIONAL) ──────────────────
    # ref is reflected into a quoted attribute value. Angle brackets are
    # stripped (so no new <script>/<svg>/<img> tag can form and auto-fire),
    # but the double quote passes — an attribute breakout such as
    # `" onmouseover=alert(1) x="` injects a *live* event handler that only
    # fires on user interaction. Without the scanner's active event-trigger
    # firing layer this reflects but never fires a dialog, so it is a genuine
    # attribute-breakout XSS that requires event dispatch to confirm.
    @app.get("/track", response_class=HTMLResponse)
    async def track(ref: str = Query("home")):
        safe = ref.replace("<", "").replace(">", "")  # strip tags, keep quotes
        return _layout(
            "Order tracking",
            f"""
            <form method="get" action="/track">
              <input name="ref" value="{safe}" readonly>
              <button>Track</button>
            </form>
            <p>Tracking reference saved.</p>
            """,
        )

    # ── Safe page that ships its OWN legitimate confirm() dialog ──────────
    # A normal delete button carries an inline `confirm('…')` handler, and
    # `item` is reflected HTML-escaped. The XSS active event-trigger layer must
    # NOT dispatch this pre-existing confirm() and mis-record it as xss_dialog:
    # its handler value never appears in the injected payload. Guards against
    # false-positive confirmed XSS on ordinary confirmation UI.
    @app.get("/account/delete", response_class=HTMLResponse)
    async def account_delete(item: str = Query("draft")):
        safe = html.escape(item)
        # The confirm() button sits OUTSIDE the form so form submission never
        # clicks it (only its own dialog); it stays in the DOM purely so the
        # firing layer must skip a pre-existing, non-injected dialog handler.
        return _layout(
            "Delete item",
            f"""
            <form method="get" action="/account/delete">
              <input name="item" value="{safe}">
              <button type="submit">Find items</button>
            </form>
            <button type="button"
              onclick="return confirm('Delete this item permanently?')">Delete</button>
            <p>Selected item: {safe}</p>
            """,
        )

    # ── Safe tracking twin: ref fully HTML-escaped (quotes neutralised) ───
    @app.get("/track/safe", response_class=HTMLResponse)
    async def track_safe(ref: str = Query("home")):
        safe = html.escape(ref)  # escapes <, >, ", ' — no attribute breakout
        return _layout(
            "Order tracking",
            f"""
            <form method="get" action="/track/safe">
              <input name="ref" value="{safe}" readonly>
              <button>Track</button>
            </form>
            <p>Tracking reference saved.</p>
            """,
        )

    # ── Error-based SQLi (INTENTIONAL) ────────────────────────────────────
    @app.get("/products", response_class=HTMLResponse)
    async def products(category: str = Query("outerwear")):
        db: sqlite3.Connection = app.state.db
        # VULNERABLE: category interpolated straight into the SQL string.
        sql = f"SELECT name, category, price FROM products WHERE category = '{category}'"
        try:
            rows = db.execute(sql).fetchall()
        except sqlite3.Error as exc:
            # Database error surfaced to the user (escaped so the ONLY signal
            # is the SQL error text, not a reflected XSS payload).
            return _layout(
                "Catalogue error",
                f'<p class="error">SQLite error: {html.escape(str(exc))} '
                f'(unrecognized token while parsing query)</p>',
            )
        items = "\n".join(
            f"<li>{html.escape(name)} — {html.escape(cat)} (${price:.0f})</li>"
            for name, cat, price in rows
        )
        return _layout(
            "Catalogue",
            f"<p>Category: {html.escape(category)}</p><ul>{items or '<li>No items</li>'}</ul>",
        )

    # ── Safe catalogue twin: allow-listed sort, parameterised query ───────
    @app.get("/catalog", response_class=HTMLResponse)
    async def catalog(sort: str = Query("relevance")):
        db: sqlite3.Connection = app.state.db
        order_col = _ALLOWED_SORTS.get(sort, "id")  # ignore anything off-list
        rows = db.execute(
            f"SELECT name, category, price FROM products ORDER BY {order_col}"
        ).fetchall()
        items = "\n".join(
            f"<li>{html.escape(name)} — {html.escape(cat)} (${price:.0f})</li>"
            for name, cat, price in rows
        )
        return _layout(
            "Full catalogue",
            f"<p>Sorted by relevance.</p><ul>{items}</ul>",
        )

    # ── SSTI (INTENTIONAL): name rendered through a template engine ───────
    @app.get("/greeting", response_class=HTMLResponse)
    async def greeting(name: str = Query("guest")):
        rendered = _render_template(name)
        # Escape on display: the only injection signal is the *evaluated*
        # arithmetic result (digits survive escaping); raw HTML markers do not.
        return _layout(
            "Personal greeting",
            f"<p>Hello, {html.escape(rendered)}! Welcome back.</p>",
        )

    # ── Safe greeting twin: name escaped, never template-rendered ─────────
    @app.get("/welcome", response_class=HTMLResponse)
    async def welcome(name: str = Query("guest")):
        return _layout(
            "Welcome back",
            f"<p>Hello, {html.escape(name)}! Glad to see you.</p>",
        )

    # ── Path traversal (INTENTIONAL) ──────────────────────────────────────
    @app.get("/files/download", response_class=PlainTextResponse)
    async def download(doc: str = Query("catalog.pdf")):
        decoded = unquote(unquote(doc))
        # VULNERABLE: no containment check before "reading" the file.
        if "etc/passwd" in decoded or decoded.endswith("/passwd"):
            return (
                "root:x:0:0:root:/root:/bin/bash\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            )
        return f"Brochure document: {html.escape(doc)} (2.3 MB PDF placeholder)"

    # ── Safe file twin: allow-listed document ids ─────────────────────────
    _MANUALS = {"sizing": "Sizing chart contents…", "care": "Care guide contents…"}

    @app.get("/files/manual", response_class=PlainTextResponse)
    async def manual(name: str = Query("sizing")):
        content = _MANUALS.get(name)
        if content is None:
            return "Manual not found."
        return content

    # ── Open redirect (INTENTIONAL) ───────────────────────────────────────
    @app.get("/redirect")
    async def redirect(url: str = Query("/products")):
        # VULNERABLE: redirects anywhere, including off-site.
        return RedirectResponse(url, status_code=302)

    # ── Safe redirect twin: only same-site relative paths ─────────────────
    @app.get("/account/continue")
    async def account_continue(next: str = Query("/account/profile")):
        target = next if next.startswith("/") and not next.startswith(("//", "/\\")) else "/account/profile"
        return RedirectResponse(target, status_code=302)

    # ── Header injection (INTENTIONAL) ────────────────────────────────────
    @app.get("/locale", response_class=HTMLResponse)
    async def locale(lang: str = Query("en-US")):
        decoded = unquote(unquote(lang))
        body = _layout(
            "Language preference",
            f"<p>Interface language set to {html.escape(lang)}.</p>",
        )
        response = HTMLResponse(body)
        # VULNERABLE: a CRLF in the locale value injects an arbitrary header.
        # (Simulated the way real servers behave once the injected bytes are
        # parsed into the header block.)
        if "X-WscanHdrInject" in decoded:
            response.headers["X-WscanHdrInject"] = "1"
        if "wscan_session=injected" in decoded:
            response.headers["Set-Cookie"] = "wscan_session=injected; Path=/"
        return response

    # ── Auth: SQLi auth bypass (INTENTIONAL) ──────────────────────────────
    @app.get("/login", response_class=HTMLResponse)
    async def login_form():
        return _layout(
            "Sign in",
            """
            <form method="post" action="/login">
              <label>Username <input name="username"></label>
              <label>Password <input name="password" type="password"></label>
              <button>Sign in</button>
            </form>
            """,
        )

    @app.post("/login", response_class=HTMLResponse)
    async def login(username: str = Form(""), password: str = Form("")):
        db: sqlite3.Connection = app.state.db
        # VULNERABLE: credentials interpolated into the SQL string, so
        # ' OR '1'='1 authenticates as the first user.
        sql = (
            "SELECT id, username FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        try:
            row = db.execute(sql).fetchone()
        except sqlite3.Error:
            row = None
        if row:
            return RedirectResponse("/account/profile", status_code=302)
        return _layout("Sign in", "<p class='error'>Invalid username or password.</p>")

    @app.get("/account/profile", response_class=HTMLResponse)
    async def profile():
        return _layout(
            "My account",
            "<p>Signed in. Manage your orders and addresses here.</p>",
        )

    # ── Stored XSS (INTENTIONAL): review board ────────────────────────────
    @app.get("/reviews", response_class=HTMLResponse)
    async def reviews_page():
        rendered = "\n".join(
            f"<article class='review'>{body}</article>" for body in app.state.reviews
        )
        return _layout(
            "Customer reviews",
            f"""
            <form method="post" action="/reviews">
              <textarea name="comment" placeholder="Share your experience"></textarea>
              <button>Post review</button>
            </form>
            <section class="reviews">{rendered or '<p>No reviews yet.</p>'}</section>
            """,
        )

    @app.post("/reviews", response_class=HTMLResponse)
    async def post_review(comment: str = Form("")):
        # VULNERABLE: stored without escaping, rendered raw on GET /reviews.
        app.state.reviews.append(comment)
        return RedirectResponse("/reviews", status_code=303)

    return app


def _render_template(name: str) -> str:
    """Minimal, deliberately-unsafe template renderer.

    Evaluates the math probes the SSTI scanner sends so the endpoint behaves
    like a real template engine (Jinja2/Twig-style) under injection, without
    pulling in a template dependency.
    """
    evaluated = name
    replacements = {
        "{{2654435761*2654435761}}": "7045744422742119121",
        "${2654435761*2654435761}": "7045744422742119121",
        "{{3*'wscan99991'}}": "wscan99991wscan99991wscan99991",
    }
    for probe, result in replacements.items():
        if probe in evaluated:
            evaluated = evaluated.replace(probe, result)
    return evaluated
