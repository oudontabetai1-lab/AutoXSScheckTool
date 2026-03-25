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
        proxy = getattr(self.engine, "proxy", "") or None
        timeout = getattr(self.engine, "timeout", 15)

        client_kwargs: dict = {"timeout": timeout, "follow_redirects": True}
        if proxy:
            client_kwargs["proxy"] = proxy

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

        async with httpx.AsyncClient(**client_kwargs) as client:
            for description, extra_headers in tests:
                try:
                    r = await client.get(url, headers=extra_headers)
                    body = r.text

                    # Check if canary domain appears anywhere in the HTML
                    if _CANARY_HOST in body:
                        # Try to extract the context
                        idx = body.find(_CANARY_HOST)
                        snippet = body[max(0, idx - 60):idx + len(_CANARY_HOST) + 60]

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
                            field_name=f"(HTTP {list(extra_headers.keys())[0]})",
                            payload=str(extra_headers),
                            evidence=(
                                f"Host Header Injection via {description}: "
                                f"canary domain '{_CANARY_HOST}' reflected in response. "
                                f"Context: ...{snippet}..."
                            ),
                            pair=pair,
                            severity="medium",
                        )
                        findings.append(finding)
                        break  # One confirmed finding is enough

                except Exception:
                    continue

        return findings
