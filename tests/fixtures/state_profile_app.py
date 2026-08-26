"""状態変更プロファイル用の破壊的 POST／通常 POST／GET 安全ツイン。"""

from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse


def create_app() -> FastAPI:
    app = FastAPI()
    app.state.submissions = {"delete": 0, "login": 0, "search": 0}

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return """
        <form method="post" action="/account/delete">
          <input name="reason"><button type="submit">Delete account</button>
        </form>
        <form method="post" action="/login">
          <input name="username"><button type="submit">Sign in</button>
        </form>
        <form method="get" action="/search">
          <input name="q"><button type="submit">Search</button>
        </form>
        """

    async def _value(request: Request, field: str) -> str:
        body = (await request.body()).decode("utf-8", errors="replace")
        return parse_qs(body, keep_blank_values=True).get(field, [""])[0]

    @app.post("/account/delete", response_class=HTMLResponse)
    async def delete_account(request: Request):
        app.state.submissions["delete"] += 1
        return f"deleted:{await _value(request, 'reason')}"

    @app.post("/login", response_class=HTMLResponse)
    async def login(request: Request):
        app.state.submissions["login"] += 1
        username = await _value(request, "username")
        return "SQL syntax error" if "'" in username else "login failed"

    @app.get("/search", response_class=HTMLResponse)
    async def search(q: str = ""):
        app.state.submissions["search"] += 1
        return "SQL syntax error" if "'" in q else f"results:{q}"

    return app
