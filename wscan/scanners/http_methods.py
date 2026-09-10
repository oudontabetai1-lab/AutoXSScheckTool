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

from .base import BaseScanner, Finding, PageDocumentUnavailable

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


def trace_reflection_strength(status: int, headers: dict, body: str, token: str) -> str:
    """TRACE 応答の XST 成立強度を返す（純粋）: ``"confirmed"`` / ``"likely"`` / ``""``。

    - probe トークンが本文に反射 → ``"confirmed"``（我々の送信ヘッダが実際に返っている）。
    - トークン非反射だが ``message/http`` かつ本文に ``TRACE`` → ``"likely"``（TRACE 応答らしいが
      我々のヘッダ反射までは未確証。canned 応答の誤検知を避けるため確定にしない）。
    - それ以外 → ``""``（不成立）。
    """
    if status != 200:
        return ""
    ctype = ""
    for k, v in (headers or {}).items():
        if str(k).lower() == "content-type":
            ctype = str(v).lower()
            break
    if token and token in (body or ""):
        return "confirmed"
    if "message/http" in ctype and "TRACE" in (body or ""):
        return "likely"
    return ""


def trace_reflects(status: int, headers: dict, body: str, token: str) -> bool:
    """後方互換: XST が成立（confirmed/likely いずれか）かを返す（純粋）。"""
    return bool(trace_reflection_strength(status, headers, body, token))


_TRACE_HEADER_LINE = re.compile(r"^([^\r\n:]+):(.*)$")


def redact_trace_body(body: str, limit: int = 2000) -> str:
    """TRACE が反射した送信ヘッダのうち秘匿値をマスクする（純粋）。

    XST の証跡（どのヘッダが反射したか）は残しつつ、Authorization/Cookie 等の実値は残さない。
    秘匿判定はハードコード列挙ではなく `request_logger.is_sensitive_header`（runtime 登録の
    カスタム認証ヘッダも含む正規の述語）を使う（Codex #157 P1）。
    """
    if not body:
        return ""
    from wscan.request_logger import is_sensitive_header

    out: list[str] = []
    for line in body[:limit].splitlines(keepends=True):
        m = _TRACE_HEADER_LINE.match(line.rstrip("\r\n"))
        if m and is_sensitive_header(m.group(1).strip()):
            nl = line[len(line.rstrip("\r\n")):]  # 改行（\r\n 等）を保持
            out.append(f"{m.group(1)}: [REDACTED]{nl}")
        else:
            out.append(line)
    return "".join(out)


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

    # origin だけでなくページのパスも検査するが、リクエスト増を抑えるため検査対象数を上限で抑える。
    _MAX_TARGETS = 25

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._checked_targets: set[str] = set()
        self._webdav_reported: set[str] = set()  # origin 単位（OPTIONS/PROPFIND の二重報告を防ぐ）

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
        # origin ルートに加えてページ自身のパスも検査する（パス単位の WebDAV/メソッド設定を
        # 見逃さない）。query/fragment は落として同一パスを 1 回だけ検査する。
        page_target = f"{origin}{parsed.path}" if parsed.path and parsed.path != "/" else origin

        findings: list[Finding] = []
        client_failed = False
        for target in (origin, page_target):
            if target in self._checked_targets:
                continue
            if len(self._checked_targets) >= self._MAX_TARGETS:
                self._record_scan_note(f"target_cap:{self.CHECK_TYPE}")
                break
            self._checked_targets.add(target)

            if self.monitor:
                await self.monitor.emit_status(f"HTTP methods check on {target}")
            try:
                async with httpx.AsyncClient(**self._client_kwargs(target)) as client:
                    findings += await self._check_options(client, target, origin)
                    findings += await self._check_trace(client, target)
                    findings += await self._check_webdav(client, target, origin)
            except Exception:
                # client 生成/接続失敗＝probe が 1 つも走っていない。この target は未検査なので
                # guard から外し、後で観測失敗を伝播できるようにする（checkpoint 完了→resume skip を防ぐ）。
                self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:client")
                self._checked_targets.discard(target)
                client_failed = True
        # 何も検査できず（findings 皆無）client 失敗があったなら、engine に error として扱わせ
        # resume で再試行させる（返り値 [] だと tested 完了扱いになり恒久 skip される・Codex #157）。
        if client_failed and not findings:
            raise PageDocumentUnavailable(
                f"{self.CHECK_TYPE}: HTTP クライアントを生成できませんでした: {origin}"
            )
        return findings

    async def _check_options(self, client, target, origin) -> list[Finding]:
        try:
            r = await client.request("OPTIONS", target)
            self._record_probe_status(r)
        except Exception:
            self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:options")
            return []
        # 危険メソッド/WebDAV の判定は Allow（そのエンドポイントが実際に受理するメソッド）だけに
        # 基づく。Access-Control-Allow-Methods は cross-origin ポリシーの告知でありメソッド対応の
        # 証明ではない（汎用 CORS ミドルウェアが PUT 等を返すと空 Allow で誤検知になる・Codex #157）。
        allowed = parse_allow_methods(r.headers.get("allow", ""))
        dav = webdav_methods(allowed) or bool(r.headers.get("dav"))
        findings: list[Finding] = []
        danger = dangerous_methods(allowed)
        if danger:
            pair = {"request": {"url": target, "method": "OPTIONS"},
                    "response": {"status": r.status_code, "headers": dict(r.headers), "body": ""}}
            findings.append(await self.record_finding(
                url=target, field_name="(Allow header)",
                payload="OPTIONS", evidence=(
                    f"サーバが危険な HTTP メソッドを告知しています: {', '.join(sorted(danger))} "
                    f"(Allow: {r.headers.get('allow', '')})。不要なメソッドは無効化してください。"
                ),
                pair=pair, severity="low", confidence="likely",
                evidence_type="http_dangerous_methods",
                evidence_details={"allow": sorted(allowed), "dangerous": sorted(danger)},
                reproduction_steps=[
                    f"Send: OPTIONS {target}",
                    f"Inspect the Allow header: {r.headers.get('allow', '')}",
                    "Disable unused methods (PUT/DELETE/PATCH/TRACE/CONNECT).",
                ],
            ))
        # WebDAV は「有効の告知」であり悪用可能性そのものではないため low（告知≠悪用可能）。
        # OPTIONS で報告したら origin 単位で記録し、PROPFIND 側の二重報告を抑止する。
        if dav and origin not in self._webdav_reported:
            self._webdav_reported.add(origin)
            pair = {"request": {"url": target, "method": "OPTIONS"},
                    "response": {"status": r.status_code, "headers": dict(r.headers), "body": ""}}
            findings.append(await self.record_finding(
                url=target, field_name="(WebDAV)", payload="OPTIONS",
                evidence=(
                    "WebDAV が有効の可能性があります"
                    f"（DAV ヘッダ: {r.headers.get('dav', '')} / Allow: {r.headers.get('allow', '')}）。"
                    "不要なら WebDAV を無効化してください。"
                ),
                pair=pair, severity="low", confidence="likely",
                evidence_type="http_webdav_enabled",
                evidence_details={"dav": r.headers.get("dav", ""), "allow": sorted(allowed)},
                reproduction_steps=[
                    f"Send: OPTIONS {target}",
                    "Confirm a DAV response header or WebDAV verbs in Allow.",
                    "Disable WebDAV if not required.",
                ],
            ))
        return findings

    async def _check_trace(self, client, target) -> list[Finding]:
        token = "XST-" + secrets.token_hex(8)
        try:
            r = await client.request("TRACE", target, headers={"X-Xst-Probe": token})
            self._record_probe_status(r)
        except Exception:
            self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:trace")
            return []
        strength = trace_reflection_strength(
            r.status_code, dict(r.headers), r.text[:4000], token)
        if not strength:
            return []
        # 反射本文には送信した Authorization/Cookie 等が含まれ得るのでマスクして保存する。
        pair = {"request": {"url": target, "method": "TRACE"},
                "response": {"status": r.status_code, "headers": dict(r.headers),
                             "body": redact_trace_body(r.text)}}
        confirmed = strength == "confirmed"
        evidence = (
            "TRACE メソッドが有効で送信ヘッダを反射します（Cross-Site Tracing / XST）。"
            "HttpOnly Cookie 等の窃取に悪用され得ます。TRACE を無効化してください。"
        ) if confirmed else (
            "TRACE メソッドが有効で TRACE 応答（message/http）を返します。送信ヘッダの反射までは"
            "未確証ですが XST の可能性があります。TRACE を無効化してください。"
        )
        return [await self.record_finding(
            url=target, field_name="(TRACE method)", payload="TRACE",
            evidence=evidence,
            pair=pair, severity="medium", confidence=strength,
            evidence_type="http_trace_xst",
            evidence_details={"reflected_token": confirmed},
            reproduction_steps=[
                f"Send: TRACE {target} with a custom header",
                "Confirm the response reflects the request (200, echoed header).",
                "Disable the TRACE method on the server/proxy.",
            ],
        )]

    async def _check_webdav(self, client, target, origin) -> list[Finding]:
        # OPTIONS で既に WebDAV を報告済みなら二重報告しない（origin 単位）。
        if origin in self._webdav_reported:
            return []
        # OPTIONS で判定できなかった場合の補強。PROPFIND(Depth:0) は read-only。
        try:
            r = await client.request("PROPFIND", target, headers={"Depth": "0"})
            self._record_probe_status(r)
        except Exception:
            self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:propfind")
            return []
        # 207 Multi-Status（WebDAV 応答）を強シグナルとする。
        if r.status_code != 207:
            return []
        self._webdav_reported.add(origin)
        pair = {"request": {"url": target, "method": "PROPFIND"},
                "response": {"status": r.status_code, "headers": dict(r.headers),
                             "body": r.text[:2000]}}
        return [await self.record_finding(
            url=target, field_name="(WebDAV)", payload="PROPFIND",
            evidence=(
                "PROPFIND が 207 Multi-Status を返し WebDAV が有効です。"
                "不要なら WebDAV を無効化してください。"
            ),
            pair=pair, severity="low", confidence="confirmed",
            evidence_type="http_webdav_enabled",
            evidence_details={"propfind_status": 207},
            reproduction_steps=[
                f"Send: PROPFIND {target} with Depth: 0",
                "Confirm a 207 Multi-Status WebDAV response.",
                "Disable WebDAV if not required.",
            ],
        )]
