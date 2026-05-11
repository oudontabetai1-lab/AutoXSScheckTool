from fastapi import FastAPI, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse


def create_app() -> FastAPI:
    app = FastAPI(title="WScan vulnerable fixture")
    app.state.comments = []

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return """
        <html><body>
          <a href="/search?q=hello">Search</a>
          <a href="/dom?next=hello">DOM preview</a>
          <a href="/feedback">Feedback</a>
          <a href="/comments">Comments</a>
          <a href="/login">Login</a>
          <form method="get" action="/search">
            <input name="q" value="">
            <button>Search</button>
          </form>
        </body></html>
        """

    @app.get("/search", response_class=HTMLResponse)
    async def search(q: str = Query("")):
        # Deliberately vulnerable reflected XSS fixture.
        return f"<html><body>Search result: {q}</body></html>"

    @app.get("/dom", response_class=HTMLResponse)
    async def dom(next: str = Query("")):
        # Deliberately vulnerable DOM XSS fixture: query string reaches innerHTML.
        return f"""
        <html><body>
          <div id="preview"></div>
          <form method="get" action="/dom">
            <input name="next" value="{next}">
            <button>Preview</button>
          </form>
          <script>
            const params = new URLSearchParams(location.search);
            document.getElementById('preview').innerHTML = params.get('next') || '';
          </script>
        </body></html>
        """

    @app.get("/feedback", response_class=HTMLResponse)
    async def feedback_form():
        return """
        <html><body>
          <form method="post" action="/feedback">
            <textarea name="message"></textarea>
            <button>Send</button>
          </form>
        </body></html>
        """

    @app.post("/feedback", response_class=HTMLResponse)
    async def feedback(message: str = Form("")):
        # Deliberately vulnerable persistent storage fixture.
        app.state.comments.append(message)
        return RedirectResponse("/comments", status_code=303)

    @app.get("/comments", response_class=HTMLResponse)
    async def comments():
        rendered = "\n".join(f"<article>{comment}</article>" for comment in app.state.comments)
        return f"<html><body><h1>Comments</h1>{rendered}</body></html>"

    @app.get("/login", response_class=HTMLResponse)
    async def login_form():
        return """
        <html><body>
          <form method="post" action="/login">
            <input name="username">
            <input name="password" type="password">
            <button>Login</button>
          </form>
        </body></html>
        """

    @app.post("/login", response_class=HTMLResponse)
    async def login(username: str = Form(""), password: str = Form("")):
        # Deliberately vulnerable auth-bypass fixture for SQLi regression tests.
        if "' OR '1'='1" in username or "' OR '1'='1" in password:
            return RedirectResponse("/admin", status_code=302)
        if username == "admin" and password == "correct-password":
            return RedirectResponse("/admin", status_code=302)
        return "<html><body>invalid login</body></html>"

    @app.get("/admin", response_class=HTMLResponse)
    async def admin():
        return "<html><body>Admin dashboard secret=fixture</body></html>"

    return app
