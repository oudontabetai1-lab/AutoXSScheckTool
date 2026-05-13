"""
Manual crawl recorder.

Opens a visible Chromium session, lets the operator browse naturally, and
records visited URLs, form structure, simple input/click steps, and cookies.
The saved JSON can be fed back into the normal scanner as seed URLs.
"""
from __future__ import annotations

import asyncio
import json
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse


@dataclass
class ManualCrawlSeed:
    urls: list[str] = field(default_factory=list)
    cookies: list[dict] = field(default_factory=list)
    forms_by_url: dict[str, list[dict]] = field(default_factory=dict)
    steps: list[dict] = field(default_factory=list)


def _same_origin(url: str, origin: str) -> bool:
    try:
        return urlparse(url).netloc == urlparse(origin).netloc
    except Exception:
        return False


def _matches_scope(url: str, scopes: list[str]) -> bool:
    candidate = url.rstrip("/")
    parsed = urlparse(candidate)
    for raw in scopes:
        scope = str(raw or "").strip().rstrip("/")
        if not scope:
            continue
        if scope.startswith(("http://", "https://")):
            if candidate == scope or candidate.startswith(scope + "/"):
                return True
        elif parsed.path == scope or parsed.path.startswith(scope + "/"):
            return True
    return False


def _unique_urls(values: list[str], origin: str = "", allowed_scopes: list[str] | None = None) -> list[str]:
    seen: set[str] = set()
    urls: list[str] = []
    allowed_scopes = allowed_scopes or []
    for raw in values:
        url = str(raw or "").split("#")[0].strip()
        if not url.startswith(("http://", "https://")):
            continue
        if origin and not _same_origin(url, origin) and not _matches_scope(url, allowed_scopes):
            continue
        if url in seen:
            continue
        seen.add(url)
        urls.append(url)
    return urls


def load_manual_crawl_seed(
    path: str,
    same_origin_as: str = "",
    allowed_scopes: list[str] | None = None,
) -> ManualCrawlSeed:
    """Load a saved manual crawl JSON file and normalize seed URLs."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("manual crawl file must be a JSON object")

    raw_urls: list[str] = []
    raw_urls.extend(data.get("seed_urls") or [])
    raw_urls.extend(data.get("urls") or [])
    for event in data.get("events") or []:
        if isinstance(event, dict) and event.get("url"):
            raw_urls.append(event["url"])

    return ManualCrawlSeed(
        urls=_unique_urls(raw_urls, same_origin_as, allowed_scopes),
        cookies=data.get("cookies") or [],
        forms_by_url=data.get("forms_by_url") or {},
        steps=data.get("steps") or [],
    )


class ManualCrawlSession:
    """Stateful visible-browser recorder used by CLI and dashboard APIs."""

    def __init__(self) -> None:
        self.start_url = ""
        self.output_path = ""
        self.headless = False
        self.proxy = ""
        self.started_at = 0.0
        self.stopped_at = 0.0
        self.running = False
        self.urls: list[str] = []
        self.events: list[dict[str, Any]] = []
        self.steps: list[dict[str, Any]] = []
        self.forms_by_url: dict[str, list[dict]] = {}
        self.cookies: list[dict] = []
        self.last_error = ""

        self._pw = None
        self._browser = None
        self._context = None
        self._page = None
        self._lock = asyncio.Lock()
        self._snapshot_tasks: set[asyncio.Task] = set()

    async def start(
        self,
        start_url: str,
        output_path: str,
        headless: bool = False,
        proxy: str = "",
    ) -> dict:
        if self.running:
            raise RuntimeError("manual crawl session is already running")
        if not start_url.startswith(("http://", "https://")):
            raise ValueError("start_url must begin with http:// or https://")

        from playwright.async_api import async_playwright

        self.start_url = start_url
        self.output_path = output_path
        self.headless = headless
        self.proxy = proxy
        self.started_at = time.time()
        self.stopped_at = 0.0
        self.running = True
        self.urls = []
        self.events = []
        self.steps = [{"action": "navigate", "url": start_url, "ts": self.started_at}]
        self.forms_by_url = {}
        self.cookies = []
        self.last_error = ""

        self._pw = await async_playwright().start()
        launch_kwargs: dict[str, Any] = {"headless": headless}
        if proxy:
            launch_kwargs["proxy"] = {"server": proxy}
        self._browser = await self._pw.chromium.launch(**launch_kwargs)
        self._context = await self._browser.new_context(ignore_https_errors=True)
        self._page = await self._context.new_page()

        token = secrets.token_hex(12)
        fill_fn = f"__wscan_manual_fill_{token}__"
        click_fn = f"__wscan_manual_click_{token}__"

        await self._page.expose_function(fill_fn, self._record_fill)
        await self._page.expose_function(click_fn, self._record_click)
        await self._page.add_init_script(
            f"""
            (() => {{
              const cssPath = (el) => {{
                if (!el || !el.tagName) return '';
                if (el.id) return '#' + CSS.escape(el.id);
                if (el.name) return el.tagName.toLowerCase() + '[name="' + CSS.escape(el.name) + '"]';
                const parts = [];
                while (el && el.nodeType === 1 && parts.length < 4) {{
                  let part = el.tagName.toLowerCase();
                  if (el.classList && el.classList.length) part += '.' + Array.from(el.classList).slice(0,2).map(CSS.escape).join('.');
                  parts.unshift(part);
                  el = el.parentElement;
                }}
                return parts.join(' > ');
              }};
              document.addEventListener('change', (e) => {{
                const el = e.target;
                if (!el || !['INPUT','TEXTAREA','SELECT'].includes(el.tagName)) return;
                window['{fill_fn}']({{
                  selector: cssPath(el),
                  name: el.name || '',
                  type: el.type || el.tagName.toLowerCase(),
                  url: location.href
                }});
              }}, true);
              document.addEventListener('click', (e) => {{
                const el = e.target && e.target.closest ? e.target.closest('a,button,input[type=submit],input[type=button]') : null;
                if (!el) return;
                window['{click_fn}']({{
                  selector: cssPath(el),
                  text: (el.innerText || el.value || '').slice(0,120),
                  href: el.href || '',
                  url: location.href
                }});
              }}, true);
            }})();
            """
        )

        def on_navigate(frame) -> None:
            if frame == self._page.main_frame:
                self._schedule_snapshot("navigate")

        def on_request_finished(request) -> None:
            if request.resource_type in {"document", "xhr", "fetch"}:
                url = request.url.split("#")[0]
                if _same_origin(url, self.start_url):
                    self._record_url(url, "request")

        self._page.on("framenavigated", on_navigate)
        self._page.on("requestfinished", on_request_finished)
        await self._page.goto(start_url, wait_until="domcontentloaded")
        await self.snapshot("start")
        return self.status()

    async def stop(self) -> dict:
        if not self.running:
            return self.status()

        self.running = False
        self.stopped_at = time.time()
        try:
            await self.snapshot("stop")
            if self._context:
                self.cookies = await self._context.cookies()
        finally:
            for task in list(self._snapshot_tasks):
                task.cancel()
            self._snapshot_tasks.clear()
            if self._browser:
                await self._browser.close()
            if self._pw:
                await self._pw.stop()
            self._browser = None
            self._context = None
            self._page = None
            self._pw = None

        self.save()
        return self.status()

    def status(self) -> dict:
        return {
            "running": self.running,
            "start_url": self.start_url,
            "output_path": self.output_path,
            "started_at": self.started_at,
            "stopped_at": self.stopped_at,
            "url_count": len(self.urls),
            "step_count": len(self.steps),
            "form_page_count": len(self.forms_by_url),
            "last_error": self.last_error,
            "urls": list(self.urls[-20:]),
        }

    def save(self) -> Path:
        output = Path(self.output_path or "manual_crawl.json")
        output.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version": 1,
            "start_url": self.start_url,
            "started_at": self.started_at,
            "stopped_at": self.stopped_at or time.time(),
            "seed_urls": _unique_urls(self.urls, self.start_url),
            "urls": self.urls,
            "events": self.events,
            "steps": self.steps,
            "forms_by_url": self.forms_by_url,
            "cookies": self.cookies,
        }
        output.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return output

    async def snapshot(self, reason: str = "manual") -> None:
        if not self._page:
            return
        async with self._lock:
            try:
                url = self._page.url.split("#")[0]
                if not _same_origin(url, self.start_url):
                    return
                self._record_url(url, reason)
                forms = await self._page.eval_on_selector_all(
                    "form",
                    """forms => forms.map((f, index) => ({
                      index,
                      action: f.action || location.href,
                      method: (f.method || 'get').toLowerCase(),
                      inputs: Array.from(f.querySelectorAll('input,select,textarea')).map(el => ({
                        name: el.name || '',
                        id: el.id || '',
                        type: el.type || el.tagName.toLowerCase(),
                        tag: el.tagName.toLowerCase(),
                        placeholder: el.placeholder || ''
                      }))
                    }))""",
                )
                self.forms_by_url[url] = forms
            except Exception as exc:
                self.last_error = str(exc)

    def _schedule_snapshot(self, reason: str) -> None:
        async def _run() -> None:
            await asyncio.sleep(0.3)
            await self.snapshot(reason)

        task = asyncio.create_task(_run())
        self._snapshot_tasks.add(task)
        task.add_done_callback(lambda t: self._snapshot_tasks.discard(t))

    def _record_url(self, url: str, source: str) -> None:
        url = url.split("#")[0]
        if not url.startswith(("http://", "https://")):
            return
        if url not in self.urls:
            self.urls.append(url)
            self.events.append({"type": "url", "source": source, "url": url, "ts": time.time()})

    def _record_fill(self, data: dict) -> None:
        step = {
            "action": "fill",
            "selector": data.get("selector", ""),
            "name": data.get("name", ""),
            "type": data.get("type", ""),
            "url": data.get("url", ""),
            "ts": time.time(),
        }
        self.steps.append(step)

    def _record_click(self, data: dict) -> None:
        step = {
            "action": "click",
            "selector": data.get("selector", ""),
            "text": data.get("text", ""),
            "href": data.get("href", ""),
            "url": data.get("url", ""),
            "ts": time.time(),
        }
        self.steps.append(step)
        href = data.get("href", "")
        if href and _same_origin(href, self.start_url):
            self._record_url(href, "click")
