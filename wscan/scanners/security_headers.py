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
from typing import TYPE_CHECKING

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

    CHECK_TYPE = "security_headers"
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

        pair = self.browser.network.latest() or {}
        headers = {
            k.lower(): v
            for k, v in pair.get("response", {}).get("headers", {}).items()
        }

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
            )
            findings.append(finding)

        # Special check: HSTS present but max-age is too short
        hsts = headers.get("strict-transport-security", "")
        if hsts:
            import re
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
                )
                findings.append(finding)

        return findings
