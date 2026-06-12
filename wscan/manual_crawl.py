"""
Manual crawl recorder.

Opens a visible Chromium session, lets the operator browse naturally, and
records visited URLs, form structure, simple input/click steps, and cookies.
The saved JSON can be fed back into the normal scanner as seed URLs.
"""
from __future__ import annotations

import asyncio
import json
import re
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
    host = (parsed.hostname or "").lower()
    for raw in scopes:
        scope = str(raw or "").strip().rstrip("/")
        if not scope:
            continue
        if scope.startswith(("http://", "https://")):
            if candidate == scope or candidate.startswith(scope + "/"):
                return True
        elif "/" in scope:
            # パス系スコープ（/admin 等）
            if parsed.path == scope or parsed.path.startswith(scope + "/"):
                return True
        else:
            # ホスト系スコープ（auth.example.com 等）: 完全一致 or サブドメイン。
            # monitor の allowed_target_hosts と同じホスト許可判定を共有する。
            low = scope.lower().strip(".")
            if host and (host == low or host.endswith("." + low)):
                return True
    return False


def _unique_urls(values: list[str], origin: str = "", allowed_scopes: list[str] | None = None) -> list[str]:
    seen: set[str] = set()
    urls: list[str] = []
    allowed_scopes = allowed_scopes or []
    for raw in values:
        url = _strip_in_page_anchor(str(raw or "").strip())
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

    # 取込時に許可・検証済みのスコープ（import_scopes）も合算する。これが無いと
    # クロスホストの許可 URL（SSO/コールバック等）が再読込時の同一オリジン
    # 正規化で落ちてしまう（build_seed_payload が書き出す）。
    scopes = list(allowed_scopes or []) + [
        str(s) for s in (data.get("import_scopes") or [])
    ]

    return ManualCrawlSeed(
        urls=_unique_urls(raw_urls, same_origin_as, scopes),
        cookies=data.get("cookies") or [],
        forms_by_url=data.get("forms_by_url") or {},
        steps=data.get("steps") or [],
    )


def _strip_in_page_anchor(url: str) -> str:
    """ページ内アンカー（``#section`` 等）のみ除去し、SPA ハッシュルートは保持する。

    ``https://app/#/admin`` のような hash ルーティングや DOM XSS 対象は、``#`` 以降を
    捨てると別ページ（``https://app/``）になってしまうため落とさない。``/`` や ``!`` を
    含む（=ルート風の）フラグメントは保持し、単純なアンカーだけ除去する。
    """
    head, sep, frag = url.partition("#")
    if not sep or not frag:
        return head
    if frag[:1] in ("/", "!") or "/" in frag:
        return url
    return head


def parse_url_list(text: str | list[str]) -> list[str]:
    """貼り付けテキスト or リストから http(s) URL を抽出して順序保持で返す。

    改行・空白・カンマ区切りのいずれにも対応。サーバ/ヘッドレス環境では
    可視ブラウザを操作できないため、利用者が手元のブラウザで控えた URL を
    そのまま貼り付けてシード化できるようにする。
    """
    if isinstance(text, str):
        tokens = re.split(r"[\s,]+", text)
    else:
        tokens: list[str] = []
        for item in text or []:
            tokens.extend(re.split(r"[\s,]+", str(item or "")))
    seen: set[str] = set()
    urls: list[str] = []
    for tok in tokens:
        url = _strip_in_page_anchor(tok.strip())
        if not url.startswith(("http://", "https://")):
            continue
        if url in seen:
            continue
        seen.add(url)
        urls.append(url)
    return urls


def build_seed_payload(
    start_url: str,
    urls: list[str],
    *,
    cookies: list[dict] | None = None,
    allowed_scopes: list[str] | None = None,
) -> dict:
    """手入力の URL リストから ``save()`` と同形式のシード JSON を構築する（純粋関数）。

    通常スキャンの ``load_manual_crawl_seed`` がそのまま読める構造を返す。
    可視ブラウザの記録（events/steps/forms）は持たないが、``seed_urls`` を
    巡回起点として供給できる。

    ``allowed_scopes`` を渡すと start_url と異なるオリジンでも許可スコープ内なら
    seed に残す（複数の許可ホストにまたがる SSO/コールバック URL を落とさない）。
    """
    now = time.time()
    normalized = (
        _unique_urls(urls, start_url, allowed_scopes) if start_url
        else _unique_urls(urls, "", allowed_scopes)
    )
    return {
        "version": 1,
        "source": "manual_url_import",
        "start_url": start_url,
        "started_at": now,
        "stopped_at": now,
        "seed_urls": normalized,
        "urls": list(urls),
        # 再読込時にクロスホストの許可 URL を落とさないよう、許可スコープを残す。
        "import_scopes": [str(s) for s in (allowed_scopes or [])],
        "events": [{"type": "url", "source": "import", "url": u, "ts": now} for u in normalized],
        "steps": [],
        "forms_by_url": {},
        "cookies": cookies or [],
    }


def save_seed_payload(output_path: str, payload: dict) -> Path:
    """シード JSON をファイルへ書き出してパスを返す。"""
    output = Path(output_path or "flows/manual_crawl.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return output


# ── 遠隔操作（スクリーンキャスト）の入力正規化（純粋関数） ─────────────────
# ダッシュボードから届く生の入力イベントを検証・正規化する。座標は表示画像に
# 対する 0..1 の正規化値（nx, ny）で受け取り、ここでビューポート実座標へ変換
# できる形に整える。ブラウザ→サーバ間の untrusted 入力なので種類とキーを白
# リストで絞る。
_ALLOWED_KEYS = frozenset(
    {
        "Enter",
        "Backspace",
        "Tab",
        "Delete",
        "Escape",
        "ArrowUp",
        "ArrowDown",
        "ArrowLeft",
        "ArrowRight",
        "Home",
        "End",
        "PageUp",
        "PageDown",
    }
)
_ALLOWED_BUTTONS = frozenset({"left", "right", "middle"})


def _clamp01(value) -> float:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return 0.0
    if f < 0.0:
        return 0.0
    if f > 1.0:
        return 1.0
    return f


def coerce_input_event(ev: dict) -> dict | None:
    """遠隔操作イベントを検証して正規化する。不正なら ``None``。

    返す dict は ``type`` を持ち、種類ごとに以下を含む:
    - ``click`` / ``move`` … ``nx``,``ny``（0..1）、click は ``button``。
    - ``scroll``            … ``dy``（ピクセル、範囲制限）。
    - ``text``             … ``text``（長さ制限）。
    - ``key``              … ``key``（白リスト）。
    - ``navigate``         … ``url``（http(s) のみ）。
    """
    if not isinstance(ev, dict):
        return None
    etype = str(ev.get("type") or "").lower()
    if etype in ("click", "move"):
        out = {"type": etype, "nx": _clamp01(ev.get("nx")), "ny": _clamp01(ev.get("ny"))}
        if etype == "click":
            btn = str(ev.get("button") or "left").lower()
            out["button"] = btn if btn in _ALLOWED_BUTTONS else "left"
        return out
    if etype == "scroll":
        try:
            dy = float(ev.get("dy") or 0.0)
        except (TypeError, ValueError):
            return None
        dy = max(-2000.0, min(2000.0, dy))
        return {"type": "scroll", "dy": dy}
    if etype == "text":
        text = str(ev.get("text") or "")
        if not text:
            return None
        return {"type": "text", "text": text[:500]}
    if etype == "key":
        key = str(ev.get("key") or "")
        if key not in _ALLOWED_KEYS:
            return None
        return {"type": "key", "key": key}
    if etype == "navigate":
        url = str(ev.get("url") or "").strip()
        if not url.startswith(("http://", "https://")):
            return None
        return {"type": "navigate", "url": url}
    return None


def scale_point(nx: float, ny: float, width: int, height: int) -> tuple[float, float]:
    """正規化座標（0..1）をビューポート実座標へ変換する（純粋関数）。"""
    return (_clamp01(nx) * width, _clamp01(ny) * height)


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

        # 遠隔操作（スクリーンキャスト）用。
        self.streaming = False
        self.view_width = 1280
        self.view_height = 800
        self._cdp = None
        self._frame_callback = None
        self._frame_tasks: set[asyncio.Task] = set()

    async def start(
        self,
        start_url: str,
        output_path: str,
        headless: bool = False,
        proxy: str = "",
        stream: bool = False,
        frame_callback=None,
    ) -> dict:
        if self.running:
            raise RuntimeError("manual crawl session is already running")
        if not start_url.startswith(("http://", "https://")):
            raise ValueError("start_url must begin with http:// or https://")

        # 遠隔操作モードでは、サーバ側のヘッドレス Chromium の画面を CDP
        # スクリーンキャストでダッシュボードへ配信し、座標入力を返して操作する。
        # 可視ウィンドウは不要なので headless を強制する。
        if stream:
            headless = True
        self.streaming = bool(stream)
        self._frame_callback = frame_callback if stream else None

        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise RuntimeError(
                "Playwright がインストールされていません。`pip install playwright` "
                "の後に `playwright install chromium` を実行してください。"
            ) from exc

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

        try:
            self._pw = await async_playwright().start()
            launch_kwargs: dict[str, Any] = {"headless": headless}
            if proxy:
                launch_kwargs["proxy"] = {"server": proxy}
            try:
                self._browser = await self._pw.chromium.launch(**launch_kwargs)
            except Exception as exc:
                msg = str(exc)
                if "Executable doesn't exist" in msg or "playwright install" in msg.lower():
                    raise RuntimeError(
                        "Chromium ブラウザが見つかりません。ターミナルで "
                        "`playwright install chromium` を実行してから再度お試しください。"
                    ) from exc
                raise
            context_kwargs: dict[str, Any] = {"ignore_https_errors": True}
            if stream:
                context_kwargs["viewport"] = {
                    "width": self.view_width,
                    "height": self.view_height,
                }
            self._context = await self._browser.new_context(**context_kwargs)
            self._page = await self._context.new_page()
        except Exception:
            await self._cleanup_browser()
            self.running = False
            raise

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

        # goto は待たない: ナビゲーションが終わるまでブロックすると
        # 重いSPAや遅いサイトで API がタイムアウトしてしまうため、
        # バックグラウンドで実行する。ユーザは既に開いているブラウザ
        # 画面で操作できる。
        async def _initial_goto() -> None:
            try:
                await self._page.goto(start_url, wait_until="commit", timeout=15_000)
            except Exception as exc:
                self.last_error = f"goto failed: {exc}"
            try:
                await self.snapshot("start")
            except Exception:
                pass

        task = asyncio.create_task(_initial_goto())
        self._snapshot_tasks.add(task)
        task.add_done_callback(lambda t: self._snapshot_tasks.discard(t))

        if stream:
            try:
                await self._start_screencast()
            except Exception as exc:
                self.last_error = f"screencast failed: {exc}"

        return self.status()

    async def _start_screencast(self) -> None:
        """CDP スクリーンキャストを開始し、フレームを ``frame_callback`` へ流す。"""
        self._cdp = await self._context.new_cdp_session(self._page)
        self._cdp.on("Page.screencastFrame", self._on_screencast_frame)
        await self._cdp.send(
            "Page.startScreencast",
            {
                "format": "jpeg",
                "quality": 55,
                "maxWidth": self.view_width,
                "maxHeight": self.view_height,
                "everyNthFrame": 1,
            },
        )

    def _on_screencast_frame(self, params: dict) -> None:
        """CDP のフレームイベント（同期コールバック）→ 配信タスクを起こす。"""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            return
        t = loop.create_task(self._handle_frame(params))
        self._frame_tasks.add(t)
        t.add_done_callback(lambda x: self._frame_tasks.discard(x))

    async def _handle_frame(self, params: dict) -> None:
        # フレームを ack しないと次が届かない。ack 後にコールバックへ渡す。
        session_id = params.get("sessionId")
        if self._cdp is not None and session_id is not None:
            try:
                await self._cdp.send(
                    "Page.screencastFrameAck", {"sessionId": session_id}
                )
            except Exception:
                pass
        cb = self._frame_callback
        if cb is None:
            return
        try:
            await cb(
                {
                    "data": params.get("data", ""),
                    "width": self.view_width,
                    "height": self.view_height,
                }
            )
        except Exception:
            pass

    async def input_event(self, ev: dict) -> dict:
        """遠隔操作イベントを実ブラウザへ適用する。

        ``ev`` はダッシュボードからの生入力。``coerce_input_event`` で検証・正規化
        してから Playwright の mouse/keyboard へ反映する。戻り値は適用結果。
        """
        if not self.running or not self._page or not self.streaming:
            return {"ok": False, "error": "remote session not running"}
        norm = coerce_input_event(ev)
        if norm is None:
            return {"ok": False, "error": "invalid input event"}
        try:
            etype = norm["type"]
            if etype == "click":
                x, y = scale_point(norm["nx"], norm["ny"], self.view_width, self.view_height)
                await self._page.mouse.click(x, y, button=norm["button"])
            elif etype == "move":
                x, y = scale_point(norm["nx"], norm["ny"], self.view_width, self.view_height)
                await self._page.mouse.move(x, y)
            elif etype == "scroll":
                await self._page.mouse.wheel(0, norm["dy"])
            elif etype == "text":
                await self._page.keyboard.insert_text(norm["text"])
            elif etype == "key":
                await self._page.keyboard.press(norm["key"])
            elif etype == "navigate":
                # 同一オリジン内に限定（recorder と同じスコープ）。
                if not _same_origin(norm["url"], self.start_url):
                    return {"ok": False, "error": "out of scope"}
                await self._page.goto(norm["url"], wait_until="commit", timeout=15_000)
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "type": norm["type"]}

    async def _stop_screencast(self) -> None:
        for t in list(self._frame_tasks):
            t.cancel()
        self._frame_tasks.clear()
        if self._cdp is not None:
            try:
                await self._cdp.send("Page.stopScreencast")
            except Exception:
                pass
            try:
                await self._cdp.detach()
            except Exception:
                pass
        self._cdp = None
        self._frame_callback = None

    async def _cleanup_browser(self) -> None:
        await self._stop_screencast()
        self.streaming = False
        for task in list(self._snapshot_tasks):
            task.cancel()
        self._snapshot_tasks.clear()
        try:
            if self._browser:
                await self._browser.close()
        except Exception:
            pass
        try:
            if self._pw:
                await self._pw.stop()
        except Exception:
            pass
        self._browser = None
        self._context = None
        self._page = None
        self._pw = None

    async def stop(self) -> dict:
        if not self.running:
            return self.status()

        self.running = False
        self.stopped_at = time.time()
        try:
            await self.snapshot("stop")
            if self._context:
                try:
                    self.cookies = await self._context.cookies()
                except Exception:
                    pass
        finally:
            await self._cleanup_browser()

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
            "streaming": self.streaming,
            "view_width": self.view_width,
            "view_height": self.view_height,
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
