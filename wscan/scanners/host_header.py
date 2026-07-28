"""
Host Header Injection Scanner (V-4)
Tests whether the application uses the HTTP Host header in its output
(e.g. password-reset links, canonical URLs) without validating it.

Attack vector: attacker sends a request with a spoofed Host header.
If the application reflects the header in a password-reset email link,
the victim clicks an attacker-controlled URL.

Detection:
  1. Send a GET request to the page with Host set to a canary domain.
  2. If the canary domain appears in the response body (e.g. inside an href
     or action attribute), flag it as Host Header Injection.
  3. Also test X-Forwarded-Host and X-Host override headers used by proxies.
"""
import re
import httpx
from urllib.parse import urlparse
from typing import TYPE_CHECKING

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine

_CANARY_HOST = "evil.wscan-test.example.com"

# Regex that matches the canary only when it appears as a hostname / URL, not
# as a substring of a larger domain (e.g. "trustedhost.evil.wscan-test.example.com.attacker"
# would otherwise trigger a false positive). The canary must be bounded by:
#   - a protocol delimiter "://", "//" or whitespace / quote / "="
#   - followed by end, "/", ":", quote, whitespace, or ">"
_CANARY_RE = re.compile(
    r"""(?:^|//|https?://|\s|['"=])"""
    + re.escape(_CANARY_HOST)
    + r"""(?:[/:?#'"\s>]|$)""",
    re.IGNORECASE,
)

# Override headers that some reverse proxies honour
_OVERRIDE_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
]


class HostHeaderScanner(BaseScanner):
    """Host Header Injection scanner."""

    CHECK_TYPE = "host_header"
    SEVERITY = "medium"

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
        """Check if the page reflects an injected Host header value."""
        # Only check each URL once
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if base_url in self._checked_urls:
            return []
        self._checked_urls.add(base_url)

        if self.monitor:
            await self.monitor.emit_status(f"Host header injection check on {url}")

        findings = []

        tests = [
            # (description, headers_dict)
            (
                "Host header spoofing",
                {"Host": _CANARY_HOST},
            ),
        ] + [
            (f"{h} override", {h: _CANARY_HOST})
            for h in _OVERRIDE_HEADERS
        ]

        for description, extra_headers in tests:
            try:
                r = await self._get_with_headers(url, extra_headers)
                body = r.text

                # Check if canary appears as a genuine URL/hostname, not
                # merely as a substring inside another domain.
                m = _CANARY_RE.search(body)
                if m:
                    idx = m.start()
                    snippet = body[max(0, idx - 60):idx + len(_CANARY_HOST) + 60]
                    header_name = next(iter(extra_headers.keys()))

                    pair = {
                        "request": {"url": url, "headers": extra_headers},
                        "response": {
                            "status": r.status_code,
                            "headers": dict(r.headers),
                            "body": body[:2000],
                        },
                    }
                    finding = await self.record_finding(
                        url=url,
                        field_name=f"(HTTP {header_name})",
                        payload=str(extra_headers),
                        evidence=(
                            f"Host Header Injection via {description}: "
                            f"canary domain '{_CANARY_HOST}' reflected in response. "
                            f"Context: ...{snippet}..."
                        ),
                        pair=pair,
                        severity="medium",
                        confidence="likely",
                        evidence_type="host_header_reflection",
                        evidence_details={
                            "header": header_name,
                            "value": _CANARY_HOST,
                            "snippet": snippet,
                        },
                    )
                    findings.append(finding)
                    break  # One confirmed finding is enough

            except Exception as exc:
                if self.monitor:
                    await self.monitor.emit_status(
                        f"[warn] host_header: {description} failed on {url}: {exc}"
                    )
                continue

        return findings

    async def _get_with_headers(self, url: str, headers: dict):
        proxy = getattr(self.engine, "proxy", "") or None
        timeout = getattr(self.engine, "timeout", 15)
        client_kwargs: dict = {"timeout": timeout, "follow_redirects": True}
        if proxy:
            client_kwargs["proxy"] = proxy
        # Merge engine-level auth headers (custom --header, Cookie, refreshed
        # bearer) underneath the probe-specific headers so the host-header
        # tests still authenticate.
        merged = {}
        if hasattr(self.engine, "auth_headers"):
            merged.update(self.auth_headers_for_url(url))
        merged.update(headers or {})
        async with httpx.AsyncClient(**client_kwargs) as client:
            return await client.get(url, headers=merged)

    async def verify_finding(self, finding: Finding) -> bool | None:
        if finding.evidence_type != "host_header_reflection":
            return None

        details = getattr(finding, "evidence_details", {}) or {}
        header = details.get("header")
        value = details.get("value") or _CANARY_HOST
        if not header:
            return None

        try:
            r = await self._get_with_headers(finding.url, {header: value})
        except Exception:
            return None

        return bool(_CANARY_RE.search(r.text or ""))
