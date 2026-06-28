"""
Prototype Pollution Scanner（新クラス）
=======================================
JavaScript の ``Object.prototype`` 汚染を検出する。

  1. クライアントサイド（DOM）: URL クエリを ``__proto__[marker]=value`` /
     ``constructor[prototype][marker]=value`` の形で渡し、ページ読込後に
     ``({}).marker`` がその値になっていれば、クエリをマージするライブラリが
     プロトタイプを汚染している（決定論的・誤検知なし）。
  2. サーバサイド: JSON ボディに ``{"__proto__": {"<marker>": "<value>"}}`` を
     混ぜて送り、汚染前のベースライン応答に無かった ``value`` が応答に現れた
     場合に報告（マージ実装の汚染反射）。

検知判定はすべて純粋関数（``proto_query_variants`` / ``is_polluted`` /
``server_pollution_reflected``）に切り出し、ブラウザ/HTTP 非依存でテストする。
"""
from __future__ import annotations

import json
import secrets
from typing import Any, TYPE_CHECKING

import httpx

from .base import BaseScanner, Finding, merge_template_headers

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


def make_marker() -> str:
    """衝突しない一意なプロパティ名を生成する。"""
    return "wpp" + secrets.token_hex(4)


def proto_query_variants(marker: str, value: str) -> list[str]:
    """プロトタイプ汚染を狙う URL クエリ片を組む（純粋）。

    クエリパース→オブジェクトマージ系ライブラリの代表的なベクタを列挙する。
    """
    return [
        f"__proto__[{marker}]={value}",
        f"constructor[prototype][{marker}]={value}",
        f"__proto__.{marker}={value}",
    ]


def proto_json_bodies(marker: str, value: str) -> list[dict]:
    """サーバサイド汚染を狙う JSON ボディを組む（純粋）。"""
    return [
        {"__proto__": {marker: value}},
        {"constructor": {"prototype": {marker: value}}},
    ]


def is_polluted(evaluated: Any, expected: str) -> bool:
    """ブラウザで評価した ``({}).marker`` の値が汚染値と一致するか（純粋）。"""
    return evaluated is not None and str(evaluated) == str(expected)


def server_pollution_reflected(baseline_body: str, polluted_body: str, value: str) -> bool:
    """汚染値がベースラインに無く汚染後の応答に現れたか（純粋）。

    値がベースライン応答にも含まれているなら、単なる入力反射であって汚染の
    証拠にならないため False（誤検知抑止）。
    """
    if not value:
        return False
    return value in (polluted_body or "") and value not in (baseline_body or "")


def pollution_persisted(baseline_body: str, followup_body: str, value: str) -> bool:
    """汚染**後**の CLEAN リクエスト応答に汚染値が現れたか（純粋）。

    汚染送信そのものの応答ではなく、``value`` を含まない後続 CLEAN リクエスト
    （汚染前ベースラインと同一ボディ）の応答で判定する。create/update API は
    送信 JSON をそのままエコーするため、汚染送信の応答に ``value`` が出ても単なる
    エコーで汚染の証拠にならない。一方 CLEAN リクエストの応答に ``value`` が出るのは、
    ``Object.prototype`` が実際に汚染されて後続の新規オブジェクトへ波及した結果で
    あり、エコーでは説明できない強い証拠になる。汚染前ベースラインに既に ``value``
    があれば偶然一致として除外（誤検知抑止）。
    """
    if not value:
        return False
    return value in (followup_body or "") and value not in (baseline_body or "")


def _append_query(url: str, fragment: str) -> str:
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{fragment}"


class PrototypePollutionScanner(BaseScanner):
    """Prototype Pollution（クライアント/サーバ両面）スキャナ。"""

    CHECK_TYPE = "prototype_pollution"
    SEVERITY = "high"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._checked_urls: set[str] = set()

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        # ページ単位で評価するため、フィールド単位の注入は行わない。
        return []

    async def scan_page(self, url: str) -> list[Finding]:
        if url in self._checked_urls:
            return []
        self._checked_urls.add(url)

        findings: list[Finding] = []
        if self.monitor:
            await self.monitor.emit_status(f"Prototype pollution check on {url}")

        findings += await self._scan_client_side(url)
        # クライアント側で確証できたら（critical）サーバ側は省く
        if not findings:
            findings += await self._scan_server_side(url)
        return findings

    # ── クライアントサイド（DOM）──────────────────────────────────────
    async def _scan_client_side(self, url: str) -> list[Finding]:
        # 並列時(--concurrency>1)は engine.browser が現在のワーカーを返す。
        # self.browser は構築時（ワーカー文脈成立前）に固定されたメインブラウザ
        # なので、ここで動的に engine 側から取り直してページ取り違えを防ぐ。
        browser = getattr(self.engine, "browser", None) or self.browser
        page = getattr(browser, "page", None)
        if page is None:
            return []
        marker = make_marker()
        value = "polluted" + secrets.token_hex(2)
        findings: list[Finding] = []

        for fragment in proto_query_variants(marker, value):
            probe_url = _append_query(url, fragment)
            await self.log_payload_test("(URL)", fragment, "prototype_pollution", url)
            try:
                await browser.navigate(probe_url)
                evaluated = await page.evaluate(
                    "(k) => Object.prototype[k]", marker
                )
            except Exception as exc:
                if self.monitor:
                    await self.monitor.emit_status(
                        f"[warn] prototype_pollution: probe failed on {url}: {exc}"
                    )
                continue
            finally:
                # 汚染を確実に取り消し、後続スキャナへ波及させない。
                try:
                    await page.evaluate("(k) => { delete Object.prototype[k]; }", marker)
                except Exception:
                    pass

            if is_polluted(evaluated, value):
                pair = self.current_page_pair(probe_url) or {
                    "request": {"url": probe_url},
                    "response": {},
                }
                finding = await self.record_finding(
                    url=url,
                    field_name="(URL query — prototype pollution)",
                    payload=fragment,
                    evidence=(
                        f"Client-side prototype pollution: query parameter "
                        f"'{fragment}' polluted Object.prototype.{marker} "
                        f"(value '{value}' observed on every object). A merge/query "
                        f"parsing routine on the page is vulnerable, enabling "
                        f"DOM XSS or logic bypass via gadgets."
                    ),
                    pair=pair,
                    severity="high",
                    confidence="confirmed",
                    evidence_type="prototype_pollution_dom",
                    evidence_details={"marker": marker, "vector": fragment},
                )
                if finding:
                    findings.append(finding)
                break
        return findings

    # ── サーバサイド（JSON）─────────────────────────────────────────
    async def _scan_server_side(self, url: str) -> list[Finding]:
        marker = make_marker()
        value = "polluted" + secrets.token_hex(2)
        findings: list[Finding] = []

        # API スペック由来のテンプレートがあれば、その method と必須フィールドを使う。
        # 裸の POST({pollution}) だと PUT/PATCH 専用や必須フィールド要求の endpoint で
        # 405/400 になり server-side proto を検査できないため。
        tmpl = None
        for t in (getattr(self.engine, "api_seed_requests", []) or []):
            if getattr(t, "url", None) == url and (
                getattr(t, "method", "POST") or "POST"
            ).upper() in ("POST", "PUT", "PATCH"):
                tmpl = t
                break
        method = (getattr(tmpl, "method", "POST") or "POST").upper() if tmpl else "POST"
        base_obj = dict(tmpl.json_body) if (tmpl and isinstance(tmpl.json_body, dict)) else {}
        # テンプレートが vendor/patch JSON メディアタイプ（application/merge-patch+json 等）を
        # 宣言していればそれを使う。application/json 固定だと 415 で取りこぼす。
        ctype = (getattr(tmpl, "content_type", None) or "application/json") if tmpl else "application/json"

        hdrs: dict = {"Content-Type": ctype}
        if hasattr(self.engine, "auth_headers"):
            base = self.engine.auth_headers()
            base.update(hdrs)
            hdrs = base
        if tmpl and isinstance(getattr(tmpl, "headers", None), dict):
            # 認証情報ヘッダは利用者の --header / 更新トークン（auth_headers 由来）を
            # spec の example/default で上書きしない（必須の非認証ヘッダのみ補完）。
            hdrs = merge_template_headers(hdrs, tmpl.headers)
        kwargs: dict = {"timeout": getattr(self.engine, "timeout", 15),
                        "follow_redirects": True, "headers": hdrs}
        if hasattr(self.engine, "httpx_client_kwargs"):
            kwargs = self.engine.httpx_client_kwargs(**kwargs)
        elif getattr(self.engine, "proxy", ""):
            kwargs["proxy"] = self.engine.proxy

        # ベースライン（汚染なし＝テンプレ本体。value を含めない）
        try:
            async with httpx.AsyncClient(**kwargs) as client:
                baseline = await client.request(method, url, content=json.dumps(base_obj))
                baseline_body = baseline.text
        except Exception:
            return []

        # 認証失効を検知したらエンジンへ通知（API テンプレ検査の resume 誤スキップ防止）。
        from wscan import session_guard
        if session_guard.looks_logged_out(
            status=baseline.status_code,
            final_url=str(getattr(baseline, "url", url)),
            body=baseline_body,
            login_url=getattr(self.engine, "login_url", ""),
            logged_in_marker=getattr(self.engine, "logged_in_marker", ""),
        ):
            try:
                self.engine._api_auth_failed = True
            except Exception:
                pass
            return []

        clean_body = json.dumps(base_obj)
        for body_obj in proto_json_bodies(marker, value):
            # 必須フィールドを保ちつつ汚染キーを足す
            merged = dict(base_obj)
            merged.update(body_obj)
            body = json.dumps(merged)
            await self.log_payload_test("(JSON body)", body, "prototype_pollution", url)
            try:
                async with httpx.AsyncClient(**kwargs) as client:
                    r = await client.request(method, url, content=body)
                    # 受理(2xx)された場合のみ汚染候補。__proto__/constructor を 400/422 で
                    # 拒否しつつエラー本文にマーカーをエコーするケースを誤検知しない。
                    if not (200 <= r.status_code < 300):
                        continue
                    # 汚染送信そのものの応答（r.text）は create/update のエコーで value を
                    # 含みうるため証拠にしない。value を含まない CLEAN リクエストを再送し、
                    # その応答に value が現れたら Object.prototype 汚染の波及（=エコーでは
                    # 説明できない）と判定する。
                    followup = await client.request(method, url, content=clean_body)
                followup_text = followup.text
            except Exception:
                continue

            if not (200 <= followup.status_code < 300):
                continue
            if pollution_persisted(baseline_body, followup_text, value):
                pair = {
                    "request": {"url": url, "method": method, "body": body,
                                "followup": clean_body},
                    "response": {"status": followup.status_code,
                                 "body": followup_text[:1000]},
                }
                finding = await self.record_finding(
                    url=url,
                    field_name="(JSON body — prototype pollution)",
                    payload=body,
                    evidence=(
                        f"Server-side prototype pollution: after injecting "
                        f"'{body}', a subsequent clean request (without the marker) "
                        f"returned the polluted value '{value}', which was absent "
                        f"from the baseline. The leak into an unrelated clean "
                        f"response (not a mere echo of the submitted body) shows the "
                        f"server merges untrusted JSON into Object.prototype without "
                        f"guarding __proto__/constructor."
                    ),
                    pair=pair,
                    severity="high",
                    confidence="confirmed",
                    evidence_type="prototype_pollution_server",
                    evidence_details={"marker": marker, "value": value},
                )
                if finding:
                    findings.append(finding)
                break
        return findings
