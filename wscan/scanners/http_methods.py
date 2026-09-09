"""HTTP メソッド設定不備スキャナ（危険メソッド告知 / XST / WebDAV）。

対象オリジンに対して **read-only なメソッド**だけを使い、以下を検出する:
- ``OPTIONS`` の ``Allow`` に危険メソッド（PUT/DELETE/PATCH/CONNECT/TRACE）が告知されている。
- ``TRACE`` が有効で、送信ヘッダをそのまま反射する（Cross-Site Tracing / XST）。
- WebDAV が有効（``OPTIONS`` の ``DAV`` ヘッダ、または ``PROPFIND`` が 207 Multi-Status を返す）。

状態を変更する PUT/DELETE 等は**送らない**（OPTIONS/TRACE/PROPFIND のみ）。判定ロジックは純粋関数に
分離し、通信失敗は graceful（Finding を作らない）。
"""
import re
import secrets
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import httpx

from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    ScannerContract, StateChangeClass,
)

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# OPTIONS の Allow に現れたら報告する危険メソッド。
_DANGEROUS_METHODS = frozenset({"PUT", "DELETE", "PATCH", "CONNECT", "TRACE"})
# WebDAV を示すメソッド/ヘッダ。
_WEBDAV_METHODS = frozenset({"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"})

_UNSUPPORTED = tuple(
    CarrierCapability(
        carrier=c, state=CapabilityState.UNSUPPORTED,
        reason="オリジンの HTTP メソッド設定を観測しパラメータ注入をしない",
    )
    for c in (
        Carrier.QUERY, Carrier.FORM, Carrier.JSON, Carrier.XML, Carrier.MULTIPART,
        Carrier.HEADER, Carrier.COOKIE, Carrier.PATH, Carrier.GRAPHQL, Carrier.WEBSOCKET,
    )
)


def parse_allow_methods(allow_header: str) -> set[str]:
    """``Allow`` / ``Access-Control-Allow-Methods`` ヘッダをメソッド集合へ（純粋）。"""
    return {
        tok.strip().upper()
        for tok in (allow_header or "").split(",")
        if tok.strip()
    }


def dangerous_methods(allowed: set[str]) -> set[str]:
    """告知メソッドのうち危険なものを返す（純粋）。"""
    return {m for m in allowed if m in _DANGEROUS_METHODS}


def webdav_methods(allowed: set[str]) -> set[str]:
    """告知メソッドのうち WebDAV 由来のものを返す（純粋）。"""
    return {m for m in allowed if m in _WEBDAV_METHODS}


def trace_reflects(status: int, headers: dict, body: str, token: str) -> bool:
    """TRACE 応答が送信ヘッダを反射している（XST 成立）かを判定する（純粋）。

    status 200 かつ、Content-Type が ``message/http`` か、本文に送信した probe トークンが
    反射していれば True。誤検知を避けるため token 反射を主判定にする。
    """
    if status != 200:
        return False
    ctype = ""
    for k, v in (headers or {}).items():
        if str(k).lower() == "content-type":
            ctype = str(v).lower()
            break
    if token and token in (body or ""):
        return True
    return "message/http" in ctype and "TRACE" in (body or "")


class HttpMethodsScanner(BaseScanner):
    """HTTP メソッド設定（危険メソッド告知 / XST / WebDAV）を検査する（origin 単位・read-only）。"""

    HAS_PAGE_LEVEL = True
    CHECK_TYPE = "http_methods"
    CONTRACT = ScannerContract(
        execution_kinds=frozenset({ExecutionKind.PAGE_ANALYSIS}),
        capabilities=_UNSUPPORTED,
        state_change=StateChangeClass.READ_ONLY,
        cost=CostClass.LOW,
    )

    SEVERITY = "medium"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._checked_origins: set[str] = set()

    async def scan_field(
        self, url: str, form_index: int, field: dict, is_url_param: bool = False,
    ) -> list[Finding]:
        return []

    def _client_kwargs(self, origin: str) -> dict:
        proxy = getattr(self.engine, "proxy", "") or None
        kwargs: dict = {"timeout": getattr(self.engine, "timeout", 15), "follow_redirects": False}
        if hasattr(self.engine, "httpx_client_kwargs"):
            kwargs = self.engine.httpx_client_kwargs(**kwargs)
        elif proxy:
            kwargs["proxy"] = proxy
        if hasattr(self.engine, "auth_headers"):
            kwargs["headers"] = self.auth_headers_for_url(origin)
        return kwargs

    async def scan_page(self, url: str) -> list[Finding]:
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin in self._checked_origins:
            return []
        self._checked_origins.add(origin)

        if self.monitor:
            await self.monitor.emit_status(f"HTTP methods check on {origin}")

        findings: list[Finding] = []
        try:
            async with httpx.AsyncClient(**self._client_kwargs(origin)) as client:
                findings += await self._check_options(client, origin)
                findings += await self._check_trace(client, origin)
                findings += await self._check_webdav(client, origin)
        except Exception:
            self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:client")
        return findings

    async def _check_options(self, client, origin) -> list[Finding]:
        try:
            r = await client.request("OPTIONS", origin)
            self._record_probe_status(r)
        except Exception:
            self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:options")
            return []
        allowed = parse_allow_methods(r.headers.get("allow", ""))
        allowed |= parse_allow_methods(r.headers.get("access-control-allow-methods", ""))
        dav = webdav_methods(allowed) or bool(r.headers.get("dav"))
        findings: list[Finding] = []
        danger = dangerous_methods(allowed)
        if danger:
            pair = {"request": {"url": origin, "method": "OPTIONS"},
                    "response": {"status": r.status_code, "headers": dict(r.headers), "body": ""}}
            findings.append(await self.record_finding(
                url=origin, field_name="(Allow header)",
                payload="OPTIONS", evidence=(
                    f"サーバが危険な HTTP メソッドを告知しています: {', '.join(sorted(danger))} "
                    f"(Allow: {r.headers.get('allow', '')})。不要なメソッドは無効化してください。"
                ),
                pair=pair, severity="low", confidence="likely",
                evidence_type="http_dangerous_methods",
                evidence_details={"allow": sorted(allowed), "dangerous": sorted(danger)},
                reproduction_steps=[
                    f"Send: OPTIONS {origin}",
                    f"Inspect the Allow header: {r.headers.get('allow', '')}",
                    "Disable unused methods (PUT/DELETE/PATCH/TRACE/CONNECT).",
                ],
            ))
        if dav:
            pair = {"request": {"url": origin, "method": "OPTIONS"},
                    "response": {"status": r.status_code, "headers": dict(r.headers), "body": ""}}
            findings.append(await self.record_finding(
                url=origin, field_name="(WebDAV)", payload="OPTIONS",
                evidence=(
                    "WebDAV が有効の可能性があります"
                    f"（DAV ヘッダ: {r.headers.get('dav', '')} / Allow: {r.headers.get('allow', '')}）。"
                    "不要なら WebDAV を無効化してください。"
                ),
                pair=pair, severity="medium", confidence="likely",
                evidence_type="http_webdav_enabled",
                evidence_details={"dav": r.headers.get("dav", ""), "allow": sorted(allowed)},
                reproduction_steps=[
                    f"Send: OPTIONS {origin}",
                    "Confirm a DAV response header or WebDAV verbs in Allow.",
                    "Disable WebDAV if not required.",
                ],
            ))
        return findings

    async def _check_trace(self, client, origin) -> list[Finding]:
        token = "XST-" + secrets.token_hex(8)
        try:
            r = await client.request("TRACE", origin, headers={"X-Xst-Probe": token})
            self._record_probe_status(r)
        except Exception:
            self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:trace")
            return []
        if not trace_reflects(r.status_code, dict(r.headers), r.text[:4000], token):
            return []
        pair = {"request": {"url": origin, "method": "TRACE"},
                "response": {"status": r.status_code, "headers": dict(r.headers),
                             "body": r.text[:2000]}}
        return [await self.record_finding(
            url=origin, field_name="(TRACE method)", payload="TRACE",
            evidence=(
                "TRACE メソッドが有効で送信ヘッダを反射します（Cross-Site Tracing / XST）。"
                "HttpOnly Cookie 等の窃取に悪用され得ます。TRACE を無効化してください。"
            ),
            pair=pair, severity="medium", confidence="confirmed",
            evidence_type="http_trace_xst",
            evidence_details={"reflected_token": True},
            reproduction_steps=[
                f"Send: TRACE {origin} with a custom header",
                "Confirm the response reflects the request (200, echoed header).",
                "Disable the TRACE method on the server/proxy.",
            ],
        )]

    async def _check_webdav(self, client, origin) -> list[Finding]:
        # OPTIONS で判定できなかった場合の補強。PROPFIND(Depth:0) は read-only。
        try:
            r = await client.request("PROPFIND", origin, headers={"Depth": "0"})
            self._record_probe_status(r)
        except Exception:
            self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:propfind")
            return []
        # 207 Multi-Status（WebDAV 応答）を強シグナルとする。
        if r.status_code != 207:
            return []
        pair = {"request": {"url": origin, "method": "PROPFIND"},
                "response": {"status": r.status_code, "headers": dict(r.headers),
                             "body": r.text[:2000]}}
        return [await self.record_finding(
            url=origin, field_name="(WebDAV PROPFIND)", payload="PROPFIND",
            evidence=(
                "PROPFIND が 207 Multi-Status を返し WebDAV が有効です。"
                "不要なら WebDAV を無効化してください。"
            ),
            pair=pair, severity="medium", confidence="confirmed",
            evidence_type="http_webdav_enabled",
            evidence_details={"propfind_status": 207},
            reproduction_steps=[
                f"Send: PROPFIND {origin} with Depth: 0",
                "Confirm a 207 Multi-Status WebDAV response.",
                "Disable WebDAV if not required.",
            ],
        )]
