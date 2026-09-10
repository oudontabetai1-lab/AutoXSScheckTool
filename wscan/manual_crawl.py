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

from wscan.mfa import seconds_until_next_window
from wscan.totp import generate_totp, resolve_totp_secret
from wscan.url_normalize import normalize_proxy_server


_TOTP_MIN_REMAINING_SECONDS = 3


@dataclass
class ManualCrawlSeed:
    urls: list[str] = field(default_factory=list)
    cookies: list[dict] = field(default_factory=list)
    forms_by_url: dict[str, list[dict]] = field(default_factory=dict)
    steps: list[dict] = field(default_factory=list)


def _origin_tuple(u: str):
    """(scheme, host, 実効ポート) を返す。既定ポートを正規化し scheme を含める。"""
    p = urlparse(u)
    scheme = (p.scheme or "").lower()
    host = (p.hostname or "").lower()
    port = p.port or {"https": 443, "http": 80}.get(scheme)
    return scheme, host, port


def _same_origin(url: str, origin: str) -> bool:
    """同一 origin か（scheme+host+実効ポートで判定）。

    netloc だけの比較は (1) scheme を無視して http↔https を同一視し（cross-origin の SSO/決済
    popup の URL を same-origin と誤判定して記録し得る）、(2) 明示ポートと既定ポート
    （app.test と app.test:443）を別 origin 扱いして記録を取りこぼす。両方を正す（Codex #153）。
    """
    try:
        a, b = _origin_tuple(url), _origin_tuple(origin)
        return bool(a[0] and a[1]) and a == b
    except Exception:
        return False


def _cookie_host_matches(cookie_domain: str, host: str) -> bool:
    """cookie の domain が target host のものか（純粋）。

    先頭ドットを除いて完全一致、または host がその domain のサブドメインなら True。
    別サイト（IdP 等）の cookie を除外するために使う。空は False。
    """
    d = (cookie_domain or "").lower().lstrip(".")
    h = (host or "").lower()
    if not d or not h:
        return False
    return h == d or h.endswith("." + d)


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
    from .textio import read_text_resilient
    data = json.loads(read_text_resilient(path))
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

    # 起動時リダイレクト（http→https 等・同一ホスト）後の実効 origin を保存してあるので、
    # 同一ホストなら caller の same_origin_as より優先する。これをしないと、target が http の
    # まま保存が https のとき、厳密 origin 判定で全 seed が scheme 差で落ちる（Codex #153）。
    # 別ホストへは昇格しない（host 一致を条件にする）。
    effective_origin = same_origin_as
    saved_start = str(data.get("start_url") or "")
    if saved_start.startswith(("http://", "https://")):
        if not same_origin_as or (
                _origin_tuple(saved_start)[1] == _origin_tuple(same_origin_as)[1]):
            effective_origin = saved_start

    return ManualCrawlSeed(
        urls=_unique_urls(raw_urls, effective_origin, scopes),
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


def pick_active_page(pages: list[Any], closed_page: Any) -> Any | None:
    """閉じたページを除く最後のページを、次のアクティブページとして返す。"""
    remaining = [page for page in pages if page is not closed_page]
    return remaining[-1] if remaining else None


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
        self._page_tasks: set[asyncio.Task] = set()
        self._bound_pages: list[Any] = []
        self._fill_fn = ""
        self._click_fn = ""
        self._recorder_script = ""

        # TOTP はメモリ上だけに保持し、status/save/log には含めない。
        self.totp_uri = ""
        self.totp_secret = ""
        self.totp_qr = ""
        self.totp_digits = 6
        self.totp_period = 30
        self.totp_algorithm = "SHA1"
        self.last_mfa_selector = ""

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
        totp_uri: str = "",
        totp_secret: str = "",
        totp_qr: str = "",
        totp_digits: int = 6,
        totp_period: int = 30,
        totp_algorithm: str = "SHA1",
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
        self.totp_uri = str(totp_uri or "")
        self.totp_secret = str(totp_secret or "")
        self.totp_qr = str(totp_qr or "")
        self.totp_digits = totp_digits
        self.totp_period = totp_period
        self.totp_algorithm = str(totp_algorithm or "SHA1").upper()
        self.last_mfa_selector = ""

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
        # 空白のみ/scheme 欠落/不正値を正規化（launch の "Invalid URL" 回避）。
        self.proxy = proxy = normalize_proxy_server(proxy)
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
        self._fill_fn = f"__wscan_manual_fill_{token}__"
        self._click_fn = f"__wscan_manual_click_{token}__"
        guard = f"__wscan_manual_bound_{token}__"
        # target=_blank のリンククリックは同一タブ化して screencast 1 枚に収める（追従も容易）。
        # window.open は上書きしない: 偽の window を返すと w.closed/w.postMessage を使うアプリや
        # OAuth ポップアップが壊れる。真の popup として開かせ、context.on("page") 追従で拾う。
        # target=_blank のリンクだけ同一タブ化する。名前付きターゲット（<a target="preview"> が
        # 名前付き iframe/window を指す等）はアプリの意図した browsing context なので触らない。
        same_tab_script = """
              document.addEventListener('click', (e) => {
                const link = e.target && e.target.closest ? e.target.closest('a[target]') : null;
                if (link && (link.getAttribute('target') || '').toLowerCase() === '_blank') {
                  link.setAttribute('target', '_self');
                }
              }, true);
        """ if stream else ""
        self._recorder_script = f"""
            (() => {{
              if (window['{guard}']) return;
              window['{guard}'] = true;
              {same_tab_script}
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
                window['{self._fill_fn}']({{
                  selector: cssPath(el),
                  name: el.name || '',
                  type: el.type || el.tagName.toLowerCase(),
                  url: location.href
                }});
              }}, true);
              document.addEventListener('click', (e) => {{
                const el = e.target && e.target.closest ? e.target.closest('a,button,input[type=submit],input[type=button]') : null;
                if (!el) return;
                window['{self._click_fn}']({{
                  selector: cssPath(el),
                  text: (el.innerText || el.value || '').slice(0,120),
                  href: el.href || '',
                  url: location.href
                }});
              }}, true);
            }})();
            """
        await self._bind_page(self._page)
        self._context.on("page", self._on_new_page)

        # goto は待たない: ナビゲーションが終わるまでブロックすると
        # 重いSPAや遅いサイトで API がタイムアウトしてしまうため、
        # バックグラウンドで実行する。ユーザは既に開いているブラウザ
        # 画面で操作できる。
        initial_page = self._page

        async def _initial_goto() -> None:
            try:
                await initial_page.goto(start_url, wait_until="commit", timeout=15_000)
                # 起動時の**同一ホストの正規リダイレクト**（http→https 等のスキーム/ポート変更）だけを
                # 記録基準に採用する。これをしないと start_url が旧 origin に固定され、以降の
                # snapshot/forms/requests や手入力 URL が軒並み out-of-scope になり artifact が空になる。
                # 一方、保護 URL が即座に cross-origin の IdP へリダイレクトするケースで IdP を記録
                # origin に昇格させると、IdP の URL(OAuth パラメータ含む)や cookie を取り込んでしまう。
                # そのため **ホストが変わるリダイレクトは採用しない**（Codex #153）。
                landed = initial_page.url or ""
                if (landed.startswith(("http://", "https://"))
                        and _origin_tuple(landed)[1] == _origin_tuple(start_url)[1]):
                    self.start_url = landed
            except Exception as exc:
                self.last_error = f"goto failed: {exc}"
            try:
                await self.snapshot("start", page=initial_page)
            except Exception:
                pass

        task = asyncio.create_task(_initial_goto())
        self._snapshot_tasks.add(task)
        task.add_done_callback(lambda t: self._snapshot_tasks.discard(t))

        if stream:
            try:
                async with self._lock:
                    # popup の page イベントが先に処理済みなら、その CDP を維持する。
                    if self._cdp is None:
                        await self._start_screencast(self._page)
            except Exception as exc:
                self.last_error = f"screencast failed: {exc}"

        return self.status()

    def _track_page_task(self, coroutine) -> None:
        """Playwright の同期イベントからページ管理 coroutine を安全に起動する。"""
        try:
            task = asyncio.get_running_loop().create_task(coroutine)
        except RuntimeError:
            coroutine.close()
            return
        self._page_tasks.add(task)
        task.add_done_callback(lambda t: self._page_tasks.discard(t))

    def _on_new_page(self, page) -> None:
        self._track_page_task(self._activate_page(page, "new_page"))

    async def _bind_page(self, page) -> None:
        """URL/操作記録と close 監視をページごとに一度だけ設定する。"""
        if any(bound is page for bound in self._bound_pages):
            return
        await page.expose_function(self._fill_fn, self._record_fill)
        await page.expose_function(self._click_fn, self._record_click)
        await page.add_init_script(self._recorder_script)
        # popup は初期 document の読込後に通知される場合があるため即時にも注入する。
        try:
            await page.evaluate(self._recorder_script)
        except Exception:
            pass

        def on_navigate(frame) -> None:
            if frame == page.main_frame:
                # 追従タブ/popup が別オリジン（SSO/決済等）へ遷移したとき、その URL（クエリ含む）を
                # artifact に残さない。requestfinished と同じ same-origin 判定を記録前に適用（Codex #153 P2）。
                if _same_origin(page.url, self.start_url):
                    self._record_url(page.url, "navigate")
                    # 背景タブ（非アクティブ）でも same-origin なら form を snapshot する。active のみだと、
                    # 別 popup がアクティブな間に背景タブが新フォームを読み、そのまま停止すると
                    # forms_by_url に構造が残らず URL だけ保存される（Codex #153 P2）。
                    # snapshot() 自身が same-origin を再確認するため cross-origin の form は捕捉しない。
                    self._schedule_snapshot("navigate", page)

        def on_request_finished(request) -> None:
            if request.resource_type in {"document", "xhr", "fetch"}:
                url = request.url.split("#")[0]
                if _same_origin(url, self.start_url):
                    self._record_url(url, "request")

        page.on("framenavigated", on_navigate)
        page.on("requestfinished", on_request_finished)
        page.on("close", lambda *_: self._track_page_task(self._handle_page_closed(page)))
        self._bound_pages.append(page)

    async def _activate_page(self, page, source: str) -> None:
        """新規ページを記録対象・入力対象・配信対象へ原子的に切り替える。"""
        if not self.running:
            return
        async with self._lock:
            try:
                await self._bind_page(page)
                self._page = page
                if self.streaming:
                    await self._stop_screencast(clear_callback=False)
                    await self._start_screencast(page)
            except Exception as exc:
                self.last_error = f"page switch failed: {exc}"
        # バインド/有効化直後に snapshot（初期ページと同様）。popup の初期 document が context の page
        # コールバック前に commit 済みだと framenavigated を観測できず、URL のみ記録では forms を
        # 取り逃す（Codex #153 P1）。snapshot は _lock を取得し same-origin のみ記録するため、
        # cross-origin popup の URL/forms を artifact に残さない（P2 とも整合）。lock 外で呼ぶ（再入防止）。
        try:
            await self.snapshot(source, page=page)
        except Exception:
            pass

    async def _handle_page_closed(self, closed_page) -> None:
        """アクティブページ終了時に、残存ページのうち最新へフォールバックする。"""
        if not self.running:
            return
        fallback = None
        async with self._lock:
            if closed_page is not self._page:
                return
            pages = list(self._context.pages) if self._context else []
            fallback = pick_active_page(pages, closed_page)
            self._page = fallback
            if self.streaming:
                await self._stop_screencast(clear_callback=False)
            if fallback is None:
                return
            try:
                await self._bind_page(fallback)
                if self.streaming:
                    await self._start_screencast(fallback)
            except Exception as exc:
                self.last_error = f"page fallback failed: {exc}"
        # フォールバック先も same-origin なら snapshot（forms 取りこぼし防止・Codex #153 P1）。lock 外。
        if fallback is not None:
            try:
                await self.snapshot("page_fallback", page=fallback)
            except Exception:
                pass

    async def _start_screencast(self, page=None) -> None:
        """CDP スクリーンキャストを開始し、フレームを ``frame_callback`` へ流す。"""
        target = page or self._page
        if self._context is None or target is None:
            return
        cdp = await self._context.new_cdp_session(target)
        cdp.on(
            "Page.screencastFrame",
            lambda params: self._on_screencast_frame(params, cdp),
        )
        try:
            await cdp.send(
                "Page.startScreencast",
                {
                    "format": "jpeg",
                    "quality": 55,
                    "maxWidth": self.view_width,
                    "maxHeight": self.view_height,
                    "everyNthFrame": 1,
                },
            )
        except Exception:
            # startScreencast 失敗時に死んだ CDP セッションを self._cdp に残さない
            # （running/streaming=true なのに画面が届かない状態を防ぐ・Codex #153 P2）。
            try:
                await cdp.detach()
            except Exception:
                pass
            raise
        self._cdp = cdp  # 開始成功後にだけ確定する

    def _on_screencast_frame(self, params: dict, cdp=None) -> None:
        """CDP のフレームイベント（同期コールバック）→ 配信タスクを起こす。"""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            return
        t = loop.create_task(self._handle_frame(params, cdp or self._cdp))
        self._frame_tasks.add(t)
        t.add_done_callback(lambda x: self._frame_tasks.discard(x))

    async def _handle_frame(self, params: dict, cdp) -> None:
        # フレームを ack しないと次が届かない。ack 後にコールバックへ渡す。
        session_id = params.get("sessionId")
        if cdp is not None and session_id is not None:
            try:
                await cdp.send(
                    "Page.screencastFrameAck", {"sessionId": session_id}
                )
            except Exception:
                pass
        if cdp is not self._cdp:
            return
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

    async def select_mfa_field(self, nx: float, ny: float) -> dict:
        """遠隔画面で OTP 欄を特定し、TOTP 設定済みなら現在コードを入力する。"""
        if not self.running or not self._page or not self.streaming:
            raise ValueError("遠隔ブラウザを起動してください")
        x, y = scale_point(nx, ny, self.view_width, self.view_height)
        async with self._lock:
            if not self.running or not self.streaming:
                raise ValueError("遠隔ブラウザを起動してください")
            page = self._page
            if page is None:
                raise ValueError("操作できるページがありません")
            selector = await page.evaluate(
                """([x, y]) => {
                const el = document.elementFromPoint(x, y);
                if (!el || el.tagName !== 'INPUT' || el.disabled || el.readOnly ||
                    !['text','tel','number','password'].includes(el.type)) return '';
                const unique = s => document.querySelectorAll(s).length === 1;
                if (el.id) {
                    const s = '#' + CSS.escape(el.id);
                    if (unique(s)) return s;
                }
                if (el.name) {
                    const s = 'input[name="' + CSS.escape(el.name) + '"]';
                    if (unique(s)) return s;
                }
                const parts = [];
                for (let node = el; node && node.nodeType === 1; node = node.parentElement) {
                    const tag = node.tagName.toLowerCase();
                    const siblings = node.parentElement ?
                        Array.from(node.parentElement.children).filter(n => n.tagName === node.tagName) : [node];
                    parts.unshift(tag + ':nth-of-type(' + (siblings.indexOf(node) + 1) + ')');
                    const s = parts.join(' > ');
                    if (unique(s)) return s;
                }
                return '';
                }""", [x, y],
            )
            if not selector:
                raise ValueError("編集可能な OTP 入力欄そのものをクリックしてください")
            self.last_mfa_selector = selector
            result = {"selector": selector}
            if self._has_totp_config():
                filled = await self._fill_totp_locked(selector, page)
                result.update(filled)
            return result

    def _has_totp_config(self) -> bool:
        return bool(self.totp_uri or self.totp_secret or self.totp_qr)

    async def _current_totp_code(self) -> str | None:
        """設定を解決し、期限切れ直前なら次の TOTP 窓を待ってコードを生成する。"""
        resolved = resolve_totp_secret(
            uri=self.totp_uri,
            secret=self.totp_secret,
            qr=self.totp_qr,
            digits=self.totp_digits,
            period=self.totp_period,
            algorithm=self.totp_algorithm,
        )
        if not resolved:
            return None
        period = int(resolved["period"])
        remaining = seconds_until_next_window(time.time(), period)
        if remaining < _TOTP_MIN_REMAINING_SECONDS:
            await asyncio.sleep(min(remaining + 0.2, float(period)))
        return generate_totp(
            resolved["secret"],
            digits=resolved["digits"],
            period=period,
            algorithm=resolved["algorithm"],
        )

    async def _fill_totp_locked(self, selector: str, page) -> dict:
        if not self._has_totp_config():
            return {"ok": False, "error": "TOTP が設定されていません"}
        try:
            code = await self._current_totp_code()
        except Exception:
            code = None
        if not code:
            return {
                "ok": False,
                "error": "TOTP 設定を解決できません。URI・secret・QR と生成条件を確認してください",
            }
        try:
            await page.fill(selector, code)
        except Exception:
            try:
                await page.focus(selector)
                await page.keyboard.press("Control+A")
                await page.keyboard.type(code)
            except Exception:
                return {
                    "ok": False,
                    "error": "OTP 入力欄へ入力できません。selector と欄の表示・編集可否を確認してください",
                }
        self.last_mfa_selector = selector
        # cross-origin SSO ページの page.url（OAuth の state/code/token を含む）は steps に残さない。
        # URL のスコープ判定は _record_fill（_safe_step_url）へ集約している（Codex #153）。
        self._record_fill({
            "selector": selector,
            "name": "",
            "type": "totp",
            "url": page.url,
        })
        return {"ok": True, "filled": True, "digits": len(code)}

    async def fill_totp(self, selector: str) -> dict:
        """現在の TOTP をアクティブページの指定欄へ入力する（コードは返さない）。"""
        selector = str(selector or "").strip()
        if not selector:
            return {"ok": False, "error": "OTP 入力欄の selector を指定してください"}
        if not self.running or not self._page or not self.streaming:
            return {"ok": False, "error": "遠隔ブラウザを起動してください"}
        async with self._lock:
            if not self.running or not self.streaming:
                return {"ok": False, "error": "遠隔ブラウザを起動してください"}
            page = self._page
            if page is None:
                return {"ok": False, "error": "操作できるページがありません"}
            return await self._fill_totp_locked(selector, page)

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
            async with self._lock:
                if not self.running or not self.streaming:
                    return {"ok": False, "error": "remote session not running"}
                page = self._page
                if page is None:
                    return {"ok": False, "error": "remote page not available"}
                etype = norm["type"]
                if etype == "click":
                    x, y = scale_point(
                        norm["nx"], norm["ny"], self.view_width, self.view_height
                    )
                    await page.mouse.click(x, y, button=norm["button"])
                elif etype == "move":
                    x, y = scale_point(norm["nx"], norm["ny"], self.view_width, self.view_height)
                    await page.mouse.move(x, y)
                elif etype == "scroll":
                    await page.mouse.wheel(0, norm["dy"])
                elif etype == "text":
                    await page.keyboard.insert_text(norm["text"])
                elif etype == "key":
                    await page.keyboard.press(norm["key"])
                elif etype == "navigate":
                    # 同一オリジン内に限定（recorder と同じスコープ）。
                    if not _same_origin(norm["url"], self.start_url):
                        return {"ok": False, "error": "out of scope"}
                    await page.goto(norm["url"], wait_until="commit", timeout=15_000)
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "type": norm["type"]}

    async def _stop_screencast(self, *, clear_callback: bool = True) -> None:
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
        if clear_callback:
            self._frame_callback = None

    async def _cleanup_browser(self) -> None:
        await self._stop_screencast()
        self.streaming = False
        for task in list(self._snapshot_tasks):
            task.cancel()
        self._snapshot_tasks.clear()
        for task in list(self._page_tasks):
            task.cancel()
        self._page_tasks.clear()
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
        self._bound_pages = []

    async def stop(self) -> dict:
        if not self.running:
            return self.status()

        self.running = False
        self.stopped_at = time.time()
        try:
            await self.snapshot("stop")
            if self._context:
                try:
                    # 保存 cookie は target **ホスト**のものに限定する。cross-origin SSO popup で
                    # 認証しても IdP の cookie を JSON に書かない。ただし URL フィルタ（cookies([url])）だと
                    # 起動パス（/login）に送られる cookie しか返らず、認証後に path=/app 等へスコープされた
                    # セッション cookie を取りこぼす。そこで全 cookie を取得し host ドメイン一致で絞る
                    # （path に依らず同一ホストは保持・別ホストは除外・Codex #153）。
                    all_cookies = await self._context.cookies()
                    host = _origin_tuple(self.start_url)[1] if self.start_url else ""
                    self.cookies = (
                        [c for c in all_cookies if _cookie_host_matches(c.get("domain", ""), host)]
                        if host else all_cookies
                    )
                except Exception:
                    pass
        finally:
            async with self._lock:
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

    async def snapshot(self, reason: str = "manual", page=None) -> None:
        if not (page or self._page):
            return
        async with self._lock:
            try:
                target = page or self._page
                if target is None:
                    return
                url = target.url.split("#")[0]
                if not _same_origin(url, self.start_url):
                    return
                self._record_url(url, reason)
                forms = await target.eval_on_selector_all(
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

    def _schedule_snapshot(self, reason: str, page=None) -> None:
        async def _run() -> None:
            await asyncio.sleep(0.3)
            await self.snapshot(reason, page=page)

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

    def _safe_step_url(self, url: str) -> str:
        """steps に保存してよい URL に整える。

        cross-origin（SSO/決済 popup 等）の URL は state/code/token をクエリに含み得る。save() は
        steps をスコープ無しで永続化するため、same-origin のときだけ URL を残し、それ以外は空にする
        （urls/events/TOTP と同じ privacy 方針・Codex #153）。
        """
        url = url or ""
        return url if _same_origin(url, self.start_url) else ""

    def _record_fill(self, data: dict) -> None:
        step = {
            "action": "fill",
            "selector": data.get("selector", ""),
            "name": data.get("name", ""),
            "type": data.get("type", ""),
            "url": self._safe_step_url(data.get("url", "")),
            "ts": time.time(),
        }
        self.steps.append(step)

    def _record_click(self, data: dict) -> None:
        href = data.get("href", "")
        same_origin_href = bool(href) and _same_origin(href, self.start_url)
        step = {
            "action": "click",
            "selector": data.get("selector", ""),
            "text": data.get("text", ""),
            # cross-origin の href（OAuth callback 等）は残さない。
            "href": href if same_origin_href else "",
            "url": self._safe_step_url(data.get("url", "")),
            "ts": time.time(),
        }
        self.steps.append(step)
        if same_origin_href:
            self._record_url(href, "click")
