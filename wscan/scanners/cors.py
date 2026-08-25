"""
CORS Misconfiguration Scanner (V-2)
Detects dangerous Cross-Origin Resource Sharing configurations:
  1. Wildcard ACAO (*) combined with Access-Control-Allow-Credentials: true
  2. Arbitrary Origin reflection — server echoes back whatever Origin header is sent,
     which allows any website to make credentialed cross-origin requests.
"""
import httpx
from typing import TYPE_CHECKING

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine

# Canary origin used to test arbitrary-Origin reflection
_CANARY_ORIGIN = "https://evil.wscan-test.example.com"


class CORSScanner(BaseScanner):
    """CORS misconfiguration scanner."""

    HAS_PAGE_LEVEL = True
    CHECK_TYPE = "cors"
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
        return []

    async def scan_page(self, url: str) -> list[Finding]:
        """Check CORS headers on the page response."""
        if url in self._checked_urls:
            return []
        self._checked_urls.add(url)

        if self.monitor:
            await self.monitor.emit_status(f"CORS check on {url}")

        findings = []

        # ── Check 1: wildcard ACAO + credentials ──────────────────────
        pair = self.current_page_pair(url)
        resp_headers = {
            k.lower(): v
            for k, v in pair.get("response", {}).get("headers", {}).items()
        }
        acao = resp_headers.get("access-control-allow-origin", "")
        acac = resp_headers.get("access-control-allow-credentials", "").lower()

        if acao == "*" and acac == "true":
            finding = await self.record_finding(
                url=url,
                field_name="(CORS response headers)",
                payload="(no payload — header analysis)",
                evidence=(
                    "CORS misconfiguration: Access-Control-Allow-Origin: * combined with "
                    "Access-Control-Allow-Credentials: true. Any origin can make "
                    "credentialed cross-origin requests."
                ),
                pair=pair,
                severity="high",
                confidence="likely",
                evidence_type="cors_wildcard_credentials",
                evidence_details={"acao": acao, "acac": acac},
            )
            findings.append(finding)

        # ── Check 2: arbitrary Origin reflection ──────────────────────
        try:
            req_headers = self._origin_headers(_CANARY_ORIGIN)
            r = await self._get_with_origin(url, _CANARY_ORIGIN)

            reflected_acao = r.headers.get("access-control-allow-origin", "")
            reflected_acac = r.headers.get("access-control-allow-credentials", "").lower()

            if reflected_acao == _CANARY_ORIGIN:
                severity = "critical" if reflected_acac == "true" else "high"
                finding = await self.record_finding(
                    url=url,
                    field_name="(CORS: Origin header)",
                    payload=f"Origin: {_CANARY_ORIGIN}",
                    evidence=(
                        f"CORS arbitrary origin reflection: server responded with "
                        f"Access-Control-Allow-Origin: {reflected_acao}"
                        + (
                            " AND Access-Control-Allow-Credentials: true "
                            "(attacker can exfiltrate authenticated responses)"
                            if reflected_acac == "true"
                            else " (unauthenticated data may be readable cross-origin)"
                        )
                    ),
                    pair={"request": {"url": url, "headers": req_headers},
                          "response": {"status": r.status_code,
                                       "headers": dict(r.headers)}},
                    severity=severity,
                    confidence="likely",
                    evidence_type="cors_origin_reflection",
                    evidence_details={
                        "origin": _CANARY_ORIGIN,
                        "acao": reflected_acao,
                        "acac": reflected_acac,
                    },
                )
                findings.append(finding)

        except Exception as exc:
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] cors: arbitrary-origin probe failed on {url}: {exc}"
                )

        return findings

    async def _get_with_origin(self, url: str, origin: str):
        proxy = getattr(self.engine, "proxy", "") or None
        headers = self._origin_headers(origin)
        if hasattr(self.engine, "auth_headers"):
            base = self.auth_headers_for_url(url)
            base.update(headers)
            headers = base
        kwargs: dict = {
            "headers": headers,
            "timeout": getattr(self.engine, "timeout", 15),
            "follow_redirects": True,
        }
        if hasattr(self.engine, "httpx_client_kwargs"):
            kwargs = self.engine.httpx_client_kwargs(**kwargs)
        elif proxy:
            kwargs["proxy"] = proxy

        async with httpx.AsyncClient(**kwargs) as client:
            response = await client.get(url)
            self._record_probe_status(response)
        return response

    def _origin_headers(self, origin: str) -> dict:
        return {
            "Origin": origin,
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
        }

    async def verify_finding(self, finding: Finding) -> bool | None:
        details = getattr(finding, "evidence_details", {}) or {}
        if finding.evidence_type == "cors_wildcard_credentials":
            try:
                r = await self._get_with_origin(finding.url, _CANARY_ORIGIN)
            except Exception:
                return None
            acao = r.headers.get("access-control-allow-origin", "")
            acac = r.headers.get("access-control-allow-credentials", "").lower()
            return acao == "*" and acac == "true"

        if finding.evidence_type == "cors_origin_reflection":
            origin = details.get("origin") or _CANARY_ORIGIN
            try:
                r = await self._get_with_origin(finding.url, origin)
            except Exception:
                return None
            acao = r.headers.get("access-control-allow-origin", "")
            acac = r.headers.get("access-control-allow-credentials", "").lower()
            expected_acac = details.get("acac", "")
            return acao == origin and (not expected_acac or acac == expected_acac)

        return None
