"""
XSS (Cross-Site Scripting) Scanner
Detects reflected and DOM-based XSS vulnerabilities.
"""
import asyncio
import html
from typing import TYPE_CHECKING

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# Markers used to detect reflected payloads
XSS_MARKERS = [
    "<script>",
    "onerror=",
    "onload=",
    "onfocus=",
    "ontoggle=",
    "ontouchstart=",
    "onwheel=",
    "onpointerenter=",
    "onmouseover=",
    "onanimationend=",
    "javascript:",
    "<svg",
    "<img",
    "<iframe",
    "<body",
    "<input",
    "<video",
    "<audio",
    "<details",
    "<marquee",
    "alert(",
]


class XSSScanner(BaseScanner):
    """XSS vulnerability scanner."""

    CHECK_TYPE = "xss"
    SEVERITY = "high"

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        """Scan a form field or URL parameter for XSS vulnerabilities."""
        findings = []
        field_name = field.get("name", "unknown")
        payloads = await self.get_payloads(field_name, url)

        if self.monitor:
            await self.monitor.emit_status(f"XSS testing: {field_name} on {url}")

        # Capture baseline before injecting any payload
        baseline_source = ""
        try:
            await self.browser.navigate(url)
            baseline_source = await self.browser.page.content()
        except Exception:
            pass

        for payload in payloads:
            if self.monitor:
                await self.monitor.emit_payload_test(field_name, payload, "xss", url)

            # Reset dialog detector
            self.browser.reset_dialog()

            # Apply payload
            source, pair = await self._apply_payload(
                url, form_index, field_name, payload, is_url_param
            )

            await asyncio.sleep(0.5 * self.sleep_factor)  # Wait for any JS execution

            # --- Check 1: Alert dialog fired (confirmed XSS) ---
            if self.browser.dialog_fired:
                finding = await self.record_finding(
                    url=url,
                    field_name=field_name,
                    payload=payload,
                    evidence=f"JavaScript alert() dialog triggered: '{self.browser.dialog_message}'",
                    pair=pair,
                    severity="critical",
                    dialog_confirmed=True,
                    dialog_message=self.browser.dialog_message,
                )
                findings.append(finding)
                self.browser.reset_dialog()
                break  # Confirmed - no need to test more payloads

            # --- Check 2: Payload reflected without HTML encoding ---
            if source:
                reflected = self._check_reflected(source, payload, baseline_source)
                if reflected:
                    finding = await self.record_finding(
                        url=url,
                        field_name=field_name,
                        payload=payload,
                        evidence=f"XSS payload reflected unencoded in response: '{reflected[:100]}'",
                        pair=pair,
                        severity="high",
                    )
                    findings.append(finding)
                    break

            await asyncio.sleep(0.2 * self.sleep_factor)

        return findings

    def _check_reflected(self, source: str, payload: str, baseline_source: str = "") -> str:
        """
        Check if the payload is reflected in the source without HTML encoding.
        Uses baseline comparison to avoid false positives from pre-existing page content.
        Returns the matched snippet or empty string.
        """
        # --- Priority check: full payload present verbatim (most reliable) ---
        if payload and len(payload) > 5 and payload in source:
            idx = source.find(payload)
            preceding = source.lower()[max(0, idx - 300):idx]
            if not (preceding.rfind("<!--") > preceding.rfind("-->")):
                return source[max(0, idx - 10):idx + len(payload) + 50]

        source_lower = source.lower()
        baseline_lower = baseline_source.lower() if baseline_source else ""
        payload_lower = payload.lower()

        for marker in XSS_MARKERS:
            marker_lower = marker.lower()
            if marker_lower not in payload_lower:
                continue
            if marker_lower not in source_lower:
                continue

            # Baseline comparison: skip if marker count did not increase after injection
            if baseline_lower:
                if source_lower.count(marker_lower) <= baseline_lower.count(marker_lower):
                    continue  # No new occurrence introduced by the payload

            # Skip if only the HTML-encoded form is present (not the raw marker)
            encoded = html.escape(marker).lower()
            if encoded != marker_lower and encoded in source_lower and marker_lower not in source_lower:
                continue

            idx = source_lower.find(marker_lower)
            if idx == -1:
                continue

            # Skip occurrences inside HTML comments (<!-- ... -->)
            preceding = source_lower[max(0, idx - 300):idx]
            if preceding.rfind("<!--") > preceding.rfind("-->"):
                continue

            return source[max(0, idx - 20):idx + len(marker) + 50]

        return ""

    async def _apply_payload(
        self,
        url: str,
        form_index: int,
        field_name: str,
        payload: str,
        is_url_param: bool,
    ) -> tuple[str, dict]:
        try:
            if is_url_param:
                return await self.browser.test_url_param(url, field_name, payload)
            else:
                await self.browser.navigate(url)
                return await self.browser.fill_and_submit_form(
                    form_index, field_name, payload
                )
        except Exception:
            return "", {}
