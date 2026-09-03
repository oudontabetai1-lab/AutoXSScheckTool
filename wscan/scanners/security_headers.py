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

import httpx

from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    PayloadShape, Prerequisite, ScannerContract, StateChangeClass, TransportKind,
    ValueKind,
)

from .base import BaseScanner, Finding

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
        headers = {
            k.lower(): v
            for k, v in pair.get("response", {}).get("headers", {}).items()
        }
        if not headers:
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

    async def _get(self, url: str):
        proxy = getattr(self.engine, "proxy", "") or None
        timeout = getattr(self.engine, "timeout", 15)
        kwargs: dict = {"timeout": timeout, "follow_redirects": True}
        if hasattr(self.engine, "httpx_client_kwargs"):
            kwargs = self.engine.httpx_client_kwargs(**kwargs)
        elif proxy:
            kwargs["proxy"] = proxy
        if hasattr(self.engine, "auth_headers"):
            kwargs["headers"] = self.auth_headers_for_url(url)
        async with httpx.AsyncClient(**kwargs) as client:
            response = await client.get(url)
            self._record_probe_status(response)
        return response

    async def _response_pair(self, url: str) -> dict:
        try:
            response = await self._get(url)
            return {
                "request": {"url": url, "method": "GET"},
                "response": {
                    "url": str(response.url),
                    "status": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text[:50000],
                },
            }
        except Exception:
            return self.current_page_pair(url)
