"""
HTTP Request Smuggling Scanner (V-9)
Detects potential HTTP request smuggling vulnerabilities by sending
ambiguous Transfer-Encoding / Content-Length headers and observing
timing anomalies or error responses.

Attack types tested:
  CL.TE — frontend uses Content-Length, backend uses Transfer-Encoding
  TE.CL — frontend uses Transfer-Encoding, backend uses Content-Length
  TE.TE — both use Transfer-Encoding but one obfuscates it

NOTE: True request smuggling confirmation requires out-of-band interaction
(e.g. a Burp Collaborator-like callback). This scanner can only detect
indicators such as:
  - Timeout differentials suggesting the backend is waiting for more data
  - Error messages referencing chunked encoding / content-length conflicts
  - HTTP 400 / 505 responses that suggest header parsing disagreement

This scanner operates at the HTTP level (httpx), bypassing Playwright.
"""
import asyncio
import time
from urllib.parse import urlparse
from typing import TYPE_CHECKING

import httpx

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine

# Error patterns that suggest smuggling-related parsing issues
_SMUGGLE_ERROR_PATTERNS = [
    r"400 Bad Request",
    r"chunked.*content-length",
    r"content-length.*chunked",
    r"invalid chunk",
    r"transfer.encoding.*not.*supported",
    r"request.*too.*large",
    r"invalid.*transfer.encoding",
]

# Timeout differential threshold (seconds) that suggests the backend
# is waiting for more data (indicating TE/CL discrepancy)
_TIMEOUT_DELTA_THRESHOLD = 5.0


class RequestSmugglingScanner(BaseScanner):
    """HTTP request smuggling detection scanner."""

    CHECK_TYPE = "request_smuggling"
    SEVERITY = "high"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._checked_hosts: set[str] = set()

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        return []

    async def scan_page(self, url: str) -> list[Finding]:
        """Run smuggling probes once per host."""
        parsed = urlparse(url)
        host = parsed.netloc
        if host in self._checked_hosts:
            return []
        self._checked_hosts.add(host)

        if self.monitor:
            await self.monitor.emit_status(f"Request smuggling probe on {host}")

        findings = []
        findings += await self._probe_cl_te(url)
        findings += await self._probe_te_cl(url)
        findings += await self._probe_te_te(url)
        return findings

    # ------------------------------------------------------------------

    async def _probe_cl_te(self, url: str) -> list[Finding]:
        """
        CL.TE probe: send a request where Content-Length says body is 6 bytes,
        but the body is actually chunked with an incomplete final chunk.
        A vulnerable backend (that reads by TE) will hang waiting for the
        0-length terminating chunk, causing a timeout differential.
        """
        # Body: "0\r\n\r\n" = 5 bytes but CL says 6 → backend waits for 1 more byte
        body = b"0\r\n\r\n"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "6",       # One more than actual body
            "Transfer-Encoding": "chunked",
        }
        return await self._time_probe(url, headers, body, "CL.TE")

    async def _probe_te_cl(self, url: str) -> list[Finding]:
        """
        TE.CL probe: send a valid chunked body but set Content-Length to a
        smaller value. A backend reading by CL will process only part of the
        chunked body, potentially treating the remainder as a new request.
        """
        chunk = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\ntest"
        chunk_hex = hex(len(chunk))[2:].encode()
        body = chunk_hex + b"\r\n" + chunk + b"\r\n0\r\n\r\n"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "4",       # Much smaller than actual body
            "Transfer-Encoding": "chunked",
        }
        return await self._time_probe(url, headers, body, "TE.CL")

    async def _probe_te_te(self, url: str) -> list[Finding]:
        """
        TE.TE probe: send obfuscated Transfer-Encoding headers.
        If one server accepts "chunked" and another accepts "xchunked",
        they will disagree on how to parse the body.
        """
        body = b"0\r\n\r\n"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Transfer-Encoding": "chunked",
            "Transfer-Encoding ": "xchunked",   # Trailing space → obfuscation
        }
        return await self._time_probe(url, headers, body, "TE.TE (obfuscated)")

    async def _time_probe(
        self,
        url: str,
        headers: dict,
        body: bytes,
        probe_name: str,
    ) -> list[Finding]:
        """Send the probe and measure response time / check for error patterns."""
        proxy = getattr(self.engine, "proxy", "") or None
        base_timeout = min(getattr(self.engine, "timeout", 15), 10)

        try:
            # First: measure normal response time as baseline
            normal_start = time.monotonic()
            async with httpx.AsyncClient(
                timeout=base_timeout,
                follow_redirects=False,
                **({"proxy": proxy} if proxy else {}),
            ) as client:
                r_normal = await client.get(url)
            normal_elapsed = time.monotonic() - normal_start

            # Second: send the smuggling probe
            probe_start = time.monotonic()
            try:
                async with httpx.AsyncClient(
                    timeout=base_timeout,
                    follow_redirects=False,
                    **({"proxy": proxy} if proxy else {}),
                ) as client:
                    r_probe = await client.post(url, content=body, headers=headers)
                probe_elapsed = time.monotonic() - probe_start
                probe_body = r_probe.text
                probe_status = r_probe.status_code
            except httpx.ReadTimeout:
                # Timeout is a strong positive signal for CL.TE
                probe_elapsed = base_timeout
                probe_body = ""
                probe_status = 0

            # --- Check 1: significant timeout differential ---
            delta = probe_elapsed - normal_elapsed
            if delta >= _TIMEOUT_DELTA_THRESHOLD or probe_status == 0:
                pair = {
                    "request": {"url": url, "headers": dict(headers)},
                    "response": {"status": probe_status},
                }
                finding = await self.record_finding(
                    url=url,
                    field_name="(HTTP request headers)",
                    payload=f"[{probe_name}] ambiguous CL+TE headers",
                    evidence=(
                        f"HTTP Request Smuggling indicator ({probe_name}): "
                        f"probe response took {probe_elapsed:.1f}s vs baseline {normal_elapsed:.1f}s "
                        f"(+{delta:.1f}s). Backend may be waiting for more data, "
                        f"suggesting a CL/TE parsing disagreement."
                    ),
                    pair=pair,
                    severity="high",
                )
                return [finding]

            # --- Check 2: error response suggesting header conflict ---
            err = self.check_response_for_patterns(probe_body, _SMUGGLE_ERROR_PATTERNS)
            if err and probe_status in (400, 501, 505):
                pair = {
                    "request": {"url": url, "headers": dict(headers)},
                    "response": {
                        "status": probe_status,
                        "body": probe_body[:500],
                    },
                }
                finding = await self.record_finding(
                    url=url,
                    field_name="(HTTP request headers)",
                    payload=f"[{probe_name}] ambiguous CL+TE headers",
                    evidence=(
                        f"HTTP Request Smuggling indicator ({probe_name}): "
                        f"server returned HTTP {probe_status} with message: '{err[:100]}'. "
                        f"This may indicate a proxy/server disagreement on header parsing."
                    ),
                    pair=pair,
                    severity="medium",
                )
                return [finding]

        except Exception:
            pass

        return []
