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

from .base import BaseScanner, Finding

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
        page = getattr(self.browser, "page", None)
        if page is None:
            return []
        marker = make_marker()
        value = "polluted" + secrets.token_hex(2)
        findings: list[Finding] = []

        for fragment in proto_query_variants(marker, value):
            probe_url = _append_query(url, fragment)
            await self.log_payload_test("(URL)", fragment, "prototype_pollution", url)
            try:
                await self.browser.navigate(probe_url)
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

        hdrs: dict = {"Content-Type": "application/json"}
        if hasattr(self.engine, "auth_headers"):
            base = self.engine.auth_headers()
            base.update(hdrs)
            hdrs = base
        kwargs: dict = {"timeout": getattr(self.engine, "timeout", 15),
                        "follow_redirects": True, "headers": hdrs}
        if hasattr(self.engine, "httpx_client_kwargs"):
            kwargs = self.engine.httpx_client_kwargs(**kwargs)
        elif getattr(self.engine, "proxy", ""):
            kwargs["proxy"] = self.engine.proxy

        # ベースライン（汚染なし）
        try:
            async with httpx.AsyncClient(**kwargs) as client:
                baseline = await client.post(url, content=json.dumps({"wscan": value}))
                baseline_body = baseline.text
        except Exception:
            return []

        for body_obj in proto_json_bodies(marker, value):
            body = json.dumps(body_obj)
            await self.log_payload_test("(JSON body)", body, "prototype_pollution", url)
            try:
                async with httpx.AsyncClient(**kwargs) as client:
                    r = await client.post(url, content=body)
                resp_text = r.text
            except Exception:
                continue

            if server_pollution_reflected(baseline_body, resp_text, value):
                pair = {
                    "request": {"url": url, "method": "POST", "body": body},
                    "response": {"status": r.status_code, "body": resp_text[:1000]},
                }
                finding = await self.record_finding(
                    url=url,
                    field_name="(JSON body — prototype pollution)",
                    payload=body,
                    evidence=(
                        f"Server-side prototype pollution: injecting "
                        f"'{body}' caused the value '{value}' to appear in the "
                        f"response where it was absent in the baseline. The server "
                        f"merges untrusted JSON into objects without guarding "
                        f"__proto__/constructor."
                    ),
                    pair=pair,
                    severity="high",
                    confidence="likely",
                    evidence_type="prototype_pollution_server",
                    evidence_details={"marker": marker, "value": value},
                )
                if finding:
                    findings.append(finding)
                break
        return findings
