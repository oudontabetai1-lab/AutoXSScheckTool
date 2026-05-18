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

_PROBE_DEFINITIONS = {
    "CL.TE": {
        "body": b"0\r\n\r\n",
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "6",
            "Transfer-Encoding": "chunked",
        },
    },
    "TE.CL": {
        "body": None,
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "4",
            "Transfer-Encoding": "chunked",
        },
    },
    "TE.TE (obfuscated)": {
        "body": b"0\r\n\r\n",
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded",
            "Transfer-Encoding": "chunked",
            "Transfer-Encoding ": "xchunked",
        },
    },
}


def _probe_body(probe_name: str) -> bytes:
    if probe_name == "TE.CL":
        chunk = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\ntest"
        chunk_hex = hex(len(chunk))[2:].encode()
        return chunk_hex + b"\r\n" + chunk + b"\r\n0\r\n\r\n"
    body = _PROBE_DEFINITIONS.get(probe_name, {}).get("body")
    return body if isinstance(body, bytes) else b""


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
        probe_name = "CL.TE"
        return await self._time_probe(
            url,
            dict(_PROBE_DEFINITIONS[probe_name]["headers"]),
            _probe_body(probe_name),
            probe_name,
        )

    async def _probe_te_cl(self, url: str) -> list[Finding]:
        """
        TE.CL probe: send a valid chunked body but set Content-Length to a
        smaller value. A backend reading by CL will process only part of the
        chunked body, potentially treating the remainder as a new request.
        """
        probe_name = "TE.CL"
        return await self._time_probe(
            url,
            dict(_PROBE_DEFINITIONS[probe_name]["headers"]),
            _probe_body(probe_name),
            probe_name,
        )

    async def _probe_te_te(self, url: str) -> list[Finding]:
        """
        TE.TE probe: send obfuscated Transfer-Encoding headers.
        If one server accepts "chunked" and another accepts "xchunked",
        they will disagree on how to parse the body.
        """
        probe_name = "TE.TE (obfuscated)"
        return await self._time_probe(
            url,
            dict(_PROBE_DEFINITIONS[probe_name]["headers"]),
            _probe_body(probe_name),
            probe_name,
        )

    async def _measure_normal(self, url: str, timeout: float, proxy: str | None) -> float:
        normal_start = time.monotonic()
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            **({"proxy": proxy} if proxy else {}),
        ) as client:
            await client.get(url)
        return time.monotonic() - normal_start

    async def _send_probe(
        self,
        url: str,
        headers: dict,
        body: bytes,
        timeout: float,
        proxy: str | None,
    ) -> tuple[float, str, int]:
        probe_start = time.monotonic()
        try:
            # Merge engine custom headers underneath probe-specific ones so
            # smuggling probes still authenticate against gated endpoints.
            if hasattr(self.engine, "auth_headers"):
                base = self.engine.auth_headers()
                base.update(headers or {})
                headers = base
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                **({"proxy": proxy} if proxy else {}),
            ) as client:
                r_probe = await client.post(url, content=body, headers=headers)
            return time.monotonic() - probe_start, r_probe.text, r_probe.status_code
        except httpx.ReadTimeout:
            return timeout, "", 0

    def _classify_probe(
        self,
        url: str,
        headers: dict,
        probe_name: str,
        normal_elapsed: float,
        probe_elapsed: float,
        probe_body: str,
        probe_status: int,
    ) -> tuple[str, str, dict, str] | None:
        delta = probe_elapsed - normal_elapsed
        details = {
            "probe_name": probe_name,
            "headers": dict(headers),
            "normal_elapsed": round(normal_elapsed, 4),
            "probe_elapsed": round(probe_elapsed, 4),
            "delta": round(delta, 4),
            "probe_status": probe_status,
        }
        if delta >= _TIMEOUT_DELTA_THRESHOLD or probe_status == 0:
            evidence = (
                f"HTTP Request Smuggling indicator ({probe_name}): "
                f"probe response took {probe_elapsed:.1f}s vs baseline {normal_elapsed:.1f}s "
                f"(+{delta:.1f}s). Backend may be waiting for more data, "
                f"suggesting a CL/TE parsing disagreement."
            )
            return "request_smuggling_timing", "high", details, evidence

        err = self.check_response_for_patterns(probe_body, _SMUGGLE_ERROR_PATTERNS)
        if err and probe_status in (400, 501, 505):
            details["matched_error"] = err[:100]
            evidence = (
                f"HTTP Request Smuggling indicator ({probe_name}): "
                f"server returned HTTP {probe_status} with message: '{err[:100]}'. "
                f"This may indicate a proxy/server disagreement on header parsing."
            )
            return "request_smuggling_parser_error", "medium", details, evidence
        return None

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
            normal_elapsed = await self._measure_normal(url, base_timeout, proxy)
            probe_elapsed, probe_body, probe_status = await self._send_probe(
                url, headers, body, base_timeout, proxy
            )
            classified = self._classify_probe(
                url,
                headers,
                probe_name,
                normal_elapsed,
                probe_elapsed,
                probe_body,
                probe_status,
            )
            if classified:
                evidence_type, severity, details, evidence = classified
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
                    payload=probe_name,
                    evidence=evidence,
                    pair=pair,
                    severity=severity,
                    confidence="tentative",
                    evidence_type=evidence_type,
                    evidence_details=details,
                )
                return [finding]

        except Exception:
            pass

        return []

    async def verify_finding(self, finding: Finding) -> bool | None:
        details = getattr(finding, "evidence_details", {}) or {}
        probe_name = details.get("probe_name") or finding.payload
        if probe_name not in _PROBE_DEFINITIONS:
            return None
        proxy = getattr(self.engine, "proxy", "") or None
        base_timeout = min(getattr(self.engine, "timeout", 15), 10)
        headers = dict(_PROBE_DEFINITIONS[probe_name]["headers"])
        body = _probe_body(probe_name)
        try:
            normal_elapsed = await self._measure_normal(finding.url, base_timeout, proxy)
            probe_elapsed, probe_body, probe_status = await self._send_probe(
                finding.url,
                headers,
                body,
                base_timeout,
                proxy,
            )
        except Exception:
            return None
        classified = self._classify_probe(
            finding.url,
            headers,
            probe_name,
            normal_elapsed,
            probe_elapsed,
            probe_body,
            probe_status,
        )
        return bool(classified and classified[0] == finding.evidence_type)
