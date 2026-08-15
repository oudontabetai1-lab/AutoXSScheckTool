"""SPA GET API 収穫向けの最小 FastAPI フィクスチャ。"""
from __future__ import annotations

import asyncio
import html

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse


EXPECTED_FINDINGS = [
    {"endpoint": "/rest/products/search", "param": "q", "check": "xss"},
]
SAFE_ENDPOINTS = [
    {"endpoint": "/rest/products/safe-search", "param": "q", "check": "xss"},
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
