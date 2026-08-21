"""SPA API 収穫向けの最小 FastAPI フィクスチャ。"""
from __future__ import annotations

import asyncio
import html

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse


EXPECTED_FINDINGS = [
    {"endpoint": "/rest/products/search", "param": "q", "check": "xss"},
    {"endpoint": "/api/login", "pointer": "/email", "check": "sqli"},
]
SAFE_ENDPOINTS = [
    {"endpoint": "/rest/products/safe-search", "param": "q", "check": "xss"},
    {"endpoint": "/api/login_safe", "pointer": "/email", "check": "sqli"},
]


app = FastAPI(title="WScan SPA harvest fixture")


@app.get("/", response_class=HTMLResponse)
async def index():
    return """<!doctype html>
<html>
  <body>
    <app-root></app-root>
    <script>
      const q = 'starter';
      Promise.all([
        fetch('/rest/products/search?q=' + encodeURIComponent(q)).then(r => r.json()),
        fetch('/rest/products/safe-search?q=' + encodeURIComponent(q)).then(r => r.json()),
        fetch('/api/login', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({email: 'a@b.test', password: 'x'})}).then(r => r.json()),
        fetch('/api/login_safe', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({email: 'a@b.test', password: 'x'})}).then(r => r.json()),
      ]).then(([result]) => {
        document.querySelector('app-root').innerHTML = result.html;
      });
    </script>
  </body>
</html>"""


@app.get("/rest/products/search", response_class=JSONResponse)
async def search(q: str = Query("")):
    # domcontentloaded より後に描画される状態を決定的に再現する。
    await asyncio.sleep(0.05)
    return {"html": f"<section>Search result: {q}</section>"}


@app.get("/rest/products/safe-search", response_class=JSONResponse)
async def safe_search(q: str = Query("")):
    await asyncio.sleep(0.05)
    return {"html": f"<section>Search result: {html.escape(q)}</section>"}


@app.post("/api/login", response_class=JSONResponse)
async def login(request: Request):
    body = await request.json()
    email = str(body.get("email", ""))
    if "'" in email:
        return JSONResponse(
            status_code=500,
            content={
                "error": "You have an error in your SQL syntax; check the manual near ''' at line 1"
            },
        )
    return {"authenticated": False}


@app.post("/api/login_safe", response_class=JSONResponse)
async def login_safe(request: Request):
    await request.json()
    return {"authenticated": False}
