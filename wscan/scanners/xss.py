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
    "javascript:",
    "<svg",
    "<img",
    "<iframe",
    "<body",
    "<input",
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

        for payload in payloads:
            if self.monitor:
                await self.monitor.emit_payload_test(field_name, payload, "xss")

            # Reset dialog detector
            self.browser.reset_dialog()

            # Take before screenshot
            await self.browser.screenshot_b64(f"XSS test: {field_name}")

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
                reflected = self._check_reflected(source, payload)
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

    def _check_reflected(self, source: str, payload: str) -> str:
        """
        Check if the payload is reflected in the source without HTML encoding.
        Returns the matched snippet or empty string.
        """
        # Check for unencoded dangerous markers from the payload
        source_lower = source.lower()
        payload_lower = payload.lower()

        for marker in XSS_MARKERS:
            if marker.lower() in payload_lower and marker.lower() in source_lower:
                # Make sure it's not just in a comment or encoded
                encoded = html.escape(marker)
                if encoded.lower() not in source_lower or marker.lower() in source_lower:
                    # Find the context
                    idx = source_lower.find(marker.lower())
                    if idx != -1:
                        snippet = source[max(0, idx - 20):idx + len(marker) + 50]
                        return snippet

        # Direct payload match check
        if payload in source:
            idx = source.find(payload)
            return source[max(0, idx):idx + len(payload)]

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
