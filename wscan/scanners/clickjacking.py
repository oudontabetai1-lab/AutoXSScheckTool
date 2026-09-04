"""
Clickjacking Scanner
Checks for missing framing-protection headers (IPA: 1.9 クリックジャッキング).

Checks per-page (not per-field) whether the HTTP response includes:
  - X-Frame-Options: DENY or SAMEORIGIN, OR
  - Content-Security-Policy: frame-ancestors directive

Only the first response for each URL is evaluated (the page navigation request).
"""
from typing import TYPE_CHECKING

from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    PayloadShape, Prerequisite, ScannerContract, StateChangeClass, TransportKind,
    ValueKind,
)

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


class ClickjackingScanner(BaseScanner):
    """Clickjacking vulnerability scanner — response-header analysis (IPA 1.9)."""

    HAS_PAGE_LEVEL = True
    CHECK_TYPE = "clickjacking"
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

    SEVERITY = "medium"

    # Track URLs already checked to avoid duplicate findings on re-navigation
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
        # Field-level scan is not applicable for a header check.
        return []

    async def scan_page(self, url: str) -> list[Finding]:
        """Check HTTP response headers for clickjacking protection."""
        if url in self._checked_urls:
            return []
        self._checked_urls.add(url)

        if self.monitor:
            await self.monitor.emit_status(f"Clickjacking check on {url}")

        pair = self.current_page_pair(url)
        headers = {
            k.lower(): v
            for k, v in pair.get("response", {}).get("headers", {}).items()
        }

        xfo = headers.get("x-frame-options", "").upper().strip()
        csp = headers.get("content-security-policy", "").lower()

        has_xfo_protection = xfo in ("DENY", "SAMEORIGIN")
        has_csp_frame_ancestors = "frame-ancestors" in csp

        if has_xfo_protection or has_csp_frame_ancestors:
            return []  # Protected

        detail_parts = []
        if not xfo:
            detail_parts.append("X-Frame-Options header absent")
        else:
            detail_parts.append(f"X-Frame-Options: {xfo} (not DENY/SAMEORIGIN)")
        if not has_csp_frame_ancestors:
            detail_parts.append("CSP frame-ancestors directive absent")

        finding = await self.record_finding(
            url=url,
            field_name="(HTTP response headers)",
            payload="(no payload — response header analysis)",
            evidence=(
                "Clickjacking risk: page can be embedded in a malicious <iframe>. "
                + "; ".join(detail_parts) + "."
            ),
            pair=pair,
            severity="medium",
        )
        return [finding]
