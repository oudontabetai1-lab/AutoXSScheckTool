"""
Security Headers Audit Scanner (V-5)
Checks for missing or misconfigured HTTP security response headers that
are recommended by OWASP and browser security best practices.

Evaluated headers:
  - Strict-Transport-Security (HSTS)
  - Content-Security-Policy (CSP)
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
  - X-Frame-Options  (redundant with clickjacking scanner but consolidated here too)
  - Cross-Origin-Opener-Policy (COOP)
  - Cross-Origin-Resource-Policy (CORP)
"""
import re
from typing import TYPE_CHECKING

from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    PayloadShape, Prerequisite, ScannerContract, StateChangeClass, TransportKind,
    ValueKind,
)

from .base import BaseScanner, Finding, PageDocumentUnavailable

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# Each entry: (header_name_lower, description, severity, recommendation)
_HEADER_CHECKS = [
    (
        "strict-transport-security",
        "Strict-Transport-Security (HSTS) missing",
        "medium",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    (
        "content-security-policy",
        "Content-Security-Policy (CSP) missing",
        "medium",
        "Add a restrictive CSP to prevent XSS: Content-Security-Policy: default-src 'self'",
    ),
    (
        "x-content-type-options",
        "X-Content-Type-Options missing",
        "low",
        "Add: X-Content-Type-Options: nosniff",
    ),
    (
        "referrer-policy",
        "Referrer-Policy missing",
        "low",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    (
        "permissions-policy",
        "Permissions-Policy missing",
        "low",
        "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    ),
    (
        "cross-origin-opener-policy",
        "Cross-Origin-Opener-Policy (COOP) missing",
        "low",
        "Add: Cross-Origin-Opener-Policy: same-origin",
    ),
]


class SecurityHeadersScanner(BaseScanner):
    """HTTP security headers audit scanner."""

    HAS_PAGE_LEVEL = True
    CHECK_TYPE = "security_headers"
    CONTRACT = ScannerContract(
        execution_kinds=frozenset({ExecutionKind.PAGE_ANALYSIS}),
        capabilities=(
            CarrierCapability(
                carrier=Carrier.QUERY, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.FORM, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.JSON, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.XML, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.MULTIPART, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.HEADER, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.COOKIE, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.PATH, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.GRAPHQL, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.WEBSOCKET, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
        ),
        state_change=StateChangeClass.READ_ONLY,
        cost=CostClass.LOW,
    )

    SEVERITY = "low"

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
        return []

    async def scan_page(self, url: str) -> list[Finding]:
        """Audit HTTP response headers for this page."""
        if url in self._checked_urls:
            return []
        self._checked_urls.add(url)

        if self.monitor:
            await self.monitor.emit_status(f"Security headers audit on {url}")

        pair = await self._response_pair(url)
        response = pair.get("response") or {}
        # 観測失敗は「レスポンス証拠（status）の欠如」で判定する（_response_pair が fetch 例外を
        # 握りつぶし fallback の network pair も無いと {} が返る）。空ヘッダ*ではなく*空レスポンスが
        # 失敗のシグナル。失敗時は transport_error を刻み、degraded_checks が page-level tested 行を
        # 除外して passive case を誤 TN/FN でなく NOT_REACHED にする（Codex #142 P2）。
        if not response or response.get("status") is None:
            self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:no_response")
            if not response:
                # 完全な取得失敗（_get 失敗＋capture 無し）は例外で engine に伝え、checkpoint 未完了に
                # して resume 再試行を可能にする（[] だと tested/完了で恒久 skip・Codex #145 P2 round15）。
                # 3xx 等の legitimate NOT_REACHED（response は非空・status のみ無し）はそのまま [] を返す。
                raise PageDocumentUnavailable(f"{self.CHECK_TYPE}: 対象 document を取得できませんでした: {url}")
            return []
        # レスポンスは受信済み。ヘッダが空でも監査する（セキュリティヘッダ皆無＝全欠落＝最大級の
        # 脆弱ケースで、まさに本 scanner が報告すべき対象・Codex #142 P1）。
        headers = {k.lower(): v for k, v in response.get("headers", {}).items()}

        # CSP/HSTS/XFO 等の document セキュリティヘッダは **HTML document** に対して意味を持つ。
        # crawl が nav アンカー等で拾った raw asset（.js/.css/.json/画像）を監査すると、これらを
        # 持たない当然の非 document 応答を「未設定」と誤報する FP になる（clickjacking と同じガード・
        # Codex #147 P2）。content-type が **明示的に非 HTML** のときだけ skip し、欠落時は従来どおり
        # 監査して FN を作らない。
        ctype = (headers.get("content-type", "") or "").lower()
        if ctype and "html" not in ctype:
            return []

        findings = []
        for header, description, severity, recommendation in _HEADER_CHECKS:
            if header not in headers:
                finding = await self.record_finding(
                    url=url,
                    field_name=f"(Header: {header})",
                    payload="(no payload — response header analysis)",
                    evidence=f"{description}. {recommendation}",
                    pair=pair,
                    severity=severity,
                    confidence="likely",
                    evidence_type="security_header_missing",
                    evidence_details={
                        "header": header,
                        "recommendation": recommendation,
                    },
                    reproduction_steps=[
                        f"Request {url}",
                        f"Confirm response header '{header}' is absent.",
                        f"Apply recommended setting: {recommendation}",
                    ],
                )
                findings.append(finding)

        # Special check: CSP present but allows unsafe-inline
        csp = headers.get("content-security-policy", "")
        if csp and "unsafe-inline" in csp.lower():
            finding = await self.record_finding(
                url=url,
                field_name="(Header: content-security-policy)",
                payload="(no payload — header value analysis)",
                evidence=(
                    "Content-Security-Policy contains 'unsafe-inline', "
                    "which negates XSS protection. "
                    "Use nonces or hashes instead."
                ),
                pair=pair,
                severity="medium",
                confidence="likely",
                evidence_type="security_header_unsafe_csp",
                evidence_details={
                    "header": "content-security-policy",
                    "observed_value": csp,
                    "unsafe_directive": "unsafe-inline",
                },
                reproduction_steps=[
                    f"Request {url}",
                    "Inspect the Content-Security-Policy response header.",
                    "Confirm it contains 'unsafe-inline'.",
                ],
            )
            findings.append(finding)

        # Special check: HSTS present but max-age is too short
        hsts = headers.get("strict-transport-security", "")
        if hsts:
            m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
            if m and int(m.group(1)) < 86400:  # Less than 1 day
                finding = await self.record_finding(
                    url=url,
                    field_name="(Header: strict-transport-security)",
                    payload="(no payload — header value analysis)",
                    evidence=(
                        f"HSTS max-age is too short ({m.group(1)} seconds). "
                        "Recommended minimum: 31536000 (1 year)."
                    ),
                    pair=pair,
                    severity="low",
                    confidence="likely",
                    evidence_type="security_header_short_hsts",
                    evidence_details={
                        "header": "strict-transport-security",
                        "observed_value": hsts,
                        "max_age": int(m.group(1)),
                        "recommended_minimum": 31536000,
                    },
                    reproduction_steps=[
                        f"Request {url}",
                        "Inspect the Strict-Transport-Security response header.",
                        "Confirm max-age is shorter than the recommended minimum.",
                    ],
                )
                findings.append(finding)

        return findings

    async def verify_finding(self, finding: Finding) -> bool | None:
        """Re-fetch the page and confirm the same header weakness still exists."""
        evidence_type = getattr(finding, "evidence_type", "") or ""
        details = getattr(finding, "evidence_details", {}) or {}

        if evidence_type not in {
            "security_header_missing",
            "security_header_unsafe_csp",
            "security_header_short_hsts",
        }:
            return None

        try:
            response = await self._get(finding.url)
        except Exception:
            return None

        # verify の再取得(replay)も 2xx（描画された document）でなければ検証不能(None)とする。
        # 未消費の 3xx（セッション失効で外部 IdP へ redirect・hop 上限超過等）や、replay-sensitive
        # URL で 2 回目の GET が返す 401/404/410 等は、ブラウザが描画した document ではない。その
        # 欠落ヘッダを「再現確認」と誤判定して既報 finding を誤って reproduced にしないよう倒す
        # （初回スキャンは _response_pair の 2xx ガードで保護されるが verify は _get 直呼び。
        # Codex #145 P2 round10 で 3xx、round17 で 4xx/5xx へ一般化して _response_pair と揃える）。
        if not (200 <= response.status_code < 300):
            return None

        headers = {k.lower(): v for k, v in response.headers.items()}

        if evidence_type == "security_header_missing":
            header = (details.get("header") or "").lower()
            if not header:
                return None
            return header not in headers

        if evidence_type == "security_header_unsafe_csp":
            csp = headers.get("content-security-policy", "")
            return "unsafe-inline" in csp.lower()

        if evidence_type == "security_header_short_hsts":
            hsts = headers.get("strict-transport-security", "")
            match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
            if not match:
                return False
            minimum = int(details.get("recommended_minimum") or 31536000)
            return int(match.group(1)) < minimum

        return None

    # _get / _response_pair は BaseScanner の共有ヘルパー（page 観測系スキャナで再利用）。
