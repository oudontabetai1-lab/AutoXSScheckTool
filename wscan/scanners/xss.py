"""
XSS (Cross-Site Scripting) Scanner
Detects reflected and DOM-based XSS vulnerabilities.
"""
import asyncio
import html
import re
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
        except Exception as exc:
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] xss: baseline fetch failed on {url}: {exc}"
                )

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
                    confidence="confirmed",
                    evidence_type="xss_dialog",
                    evidence_details={
                        "execution_signal": "browser_dialog",
                        "dialog_message": self.browser.dialog_message,
                    },
                    reproduction_steps=[
                        f"Open {url}",
                        f"Submit the payload to '{field_name}'",
                        "Observe that the browser fires a JavaScript dialog.",
                    ],
                )
                findings.append(finding)
                self.browser.reset_dialog()
                break  # Confirmed - no need to test more payloads

            # --- Check 2: Payload reflected without HTML encoding ---
            if source:
                reflection = self._analyze_reflection(source, payload, baseline_source)
                if reflection:
                    context = reflection.get("context", "unknown")
                    confidence = reflection.get("confidence", "tentative")
                    severity = "high" if confidence == "likely" else "medium"
                    finding = await self.record_finding(
                        url=url,
                        field_name=field_name,
                        payload=payload,
                        evidence=(
                            f"XSS payload reflected unencoded in {context} context: "
                            f"'{reflection.get('snippet', '')[:100]}'"
                        ),
                        pair=pair,
                        severity=severity,
                        confidence=confidence,
                        evidence_type="xss_reflection",
                        evidence_details=reflection,
                        reproduction_steps=[
                            f"Open {url}",
                            f"Submit the payload to '{field_name}'",
                            f"Confirm the payload is reflected in {context} context without complete encoding.",
                            "Escalate manually with a context-specific event or script payload if no dialog fires.",
                        ],
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
        reflection = self._analyze_reflection(source, payload, baseline_source)
        if reflection:
            return reflection.get("snippet", "")
        return ""

    def _analyze_reflection(
        self, source: str, payload: str, baseline_source: str = ""
    ) -> dict:
        """
        Return structured reflection evidence.

        Reflection alone is not always executable XSS.  This classifies the
        reflected location so the report can distinguish executable-looking
        contexts from weaker text-node reflections.
        """
        if payload and len(payload) > 5 and payload in source:
            idx = source.find(payload)
            preceding = source.lower()[max(0, idx - 300):idx]
            if not (preceding.rfind("<!--") > preceding.rfind("-->")):
                return {
                    "context": self._classify_reflection_context(source, idx),
                    "match": "full_payload",
                    "snippet": source[max(0, idx - 10):idx + len(payload) + 50],
                    "confidence": self._confidence_for_context(
                        self._classify_reflection_context(source, idx)
                    ),
                    "raw_payload_present": True,
                    "baseline_marker_delta": None,
                }

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

            context = self._classify_reflection_context(source, idx)
            delta = None
            if baseline_lower:
                delta = source_lower.count(marker_lower) - baseline_lower.count(marker_lower)
            return {
                "context": context,
                "match": marker,
                "snippet": source[max(0, idx - 20):idx + len(marker) + 50],
                "confidence": self._confidence_for_context(context),
                "raw_payload_present": False,
                "baseline_marker_delta": delta,
            }

        return {}

    def _classify_reflection_context(self, source: str, idx: int) -> str:
        before = source[max(0, idx - 500):idx].lower()
        after = source[idx:idx + 500].lower()
        last_lt = before.rfind("<")
        last_gt = before.rfind(">")
        in_tag = last_lt > last_gt
        tag_fragment = before[last_lt:] if in_tag else ""

        if before.rfind("<!--") > before.rfind("-->"):
            return "html_comment"
        if "<script" in before and "</script" not in before.split("<script")[-1]:
            return "script"
        if in_tag:
            if re.search(r"\son[a-z]+\s*=\s*['\"]?$", tag_fragment):
                return "event_handler_attribute"
            if re.search(r"\s(?:href|src|action|formaction)\s*=\s*['\"]?$", tag_fragment):
                return "url_attribute"
            return "html_attribute"
        if after.startswith("</script"):
            return "script"
        return "html_text"

    def _confidence_for_context(self, context: str) -> str:
        if context in {"script", "event_handler_attribute", "url_attribute"}:
            return "likely"
        if context in {"html_attribute", "html_text"}:
            return "tentative"
        return "tentative"

    async def verify_finding(self, finding: Finding) -> bool | None:
        from urllib.parse import parse_qs, urlparse
        is_url_param = finding.field_name in parse_qs(
            urlparse(finding.url).query, keep_blank_values=True
        )
        source, _ = await self._apply_payload(
            finding.url,
            0,
            finding.field_name,
            finding.payload,
            is_url_param,
        )
        await asyncio.sleep(0.5 * self.sleep_factor)
        if self.browser.dialog_fired:
            return True
        return bool(source and self._analyze_reflection(source, finding.payload))

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
        except Exception as exc:
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] xss: _apply_payload failed on {field_name} @ {url}: {exc}"
                )
            return "", {}
