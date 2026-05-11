"""
Stored XSS Scanner (V-1)
Detects second-order / persistent XSS by injecting unique markers and
checking ALL subsequently visited pages for their appearance.

Flow:
  scan_field  → submits a uniquely-tagged payload into the field and records
                the marker in the shared _injected set.
  scan_page   → after each normal page load, inspects the HTML for any
                previously injected marker; if found on a DIFFERENT URL
                from the injection origin, it is a Stored XSS finding.
"""
import asyncio
import html as _html
import uuid
from typing import TYPE_CHECKING

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine

# Innocuous-looking probe prefix that survives most server-side sanitation
_PROBE_PREFIX = "wsxss"


class StoredXSSScanner(BaseScanner):
    """Stored / second-order XSS scanner."""

    CHECK_TYPE = "stored_xss"
    SEVERITY = "critical"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        # marker → {"url": injection_url, "field": field_name, "payload": payload_str}
        self._injected: dict[str, dict] = {}
        self._detected_markers: set[str] = set()
        # Protects concurrent _detected_markers reads/writes when multiple
        # page-workers invoke scan_page() in parallel.
        self._detect_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Field-level: inject uniquely-tagged payloads
    # ------------------------------------------------------------------

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        """Inject probe payloads that carry a unique marker for later detection."""
        field_name = field.get("name", "unknown")

        if self.monitor:
            await self.monitor.emit_status(
                f"Stored-XSS probe injection: {field_name} on {url}"
            )

        for _ in range(3):  # inject 3 different format probes
            marker = f"{_PROBE_PREFIX}{uuid.uuid4().hex[:8]}"
            # Payloads that survive common HTML-encoding but still carry the marker
            payload = f'<script id="{marker}">/*{marker}*/</script>'
            self._injected[marker] = {
                "url": url,
                "field": field_name,
                "payload": payload,
            }
            if self.monitor:
                await self.monitor.emit_payload_test(field_name, payload, "stored_xss", url)
            try:
                if is_url_param:
                    await self.browser.test_url_param(url, field_name, payload)
                else:
                    await self.browser.navigate(url)
                    await self.browser.fill_and_submit_form(
                        form_index, field_name, payload
                    )
            except Exception as exc:
                if self.monitor:
                    await self.monitor.emit_status(
                        f"[warn] stored_xss: probe injection failed on {field_name} @ {url}: {exc}"
                    )
            await asyncio.sleep(0.3 * self.sleep_factor)

        return []  # Findings are emitted in scan_page

    # ------------------------------------------------------------------
    # Page-level: check current page for any stored markers
    # ------------------------------------------------------------------

    async def scan_page(self, url: str) -> list[Finding]:
        """After loading a page, look for any previously injected markers."""
        if not self._injected:
            return []

        try:
            source = await self.browser.page.content()
        except Exception:
            return []

        findings = []
        for marker, meta in list(self._injected.items()):
            marker_encoded = _html.escape(marker)
            in_raw = marker in source
            in_encoded = marker_encoded in source

            if not in_raw and not in_encoded:
                continue

            # Stored XSS only if the marker appears on a page OTHER than where it was injected
            if url == meta["url"]:
                continue

            # Atomically claim this marker so concurrent workers cannot both
            # record a finding for the same marker.
            async with self._detect_lock:
                if marker in self._detected_markers:
                    continue
                self._detected_markers.add(marker)
            pair = self.browser.network.latest() or {}

            # Distinguish executable XSS (raw tags) from stored HTML injection (encoded)
            is_executable = in_raw
            severity = "critical" if is_executable else "medium"
            evidence_prefix = "Stored XSS" if is_executable else "Stored HTML injection (encoded)"

            finding = await self.record_finding(
                url=url,
                field_name=meta["field"],
                payload=meta["payload"],
                evidence=(
                    f"{evidence_prefix}: marker '{marker}' injected at {meta['url']} "
                    f"appeared on {url}"
                ),
                pair=pair,
                severity=severity,
                confidence="confirmed" if is_executable else "likely",
                evidence_type="stored_xss_marker" if is_executable else "stored_html_marker",
                evidence_details={
                    "marker": marker,
                    "injection_url": meta["url"],
                    "sink_url": url,
                    "raw_marker_present": in_raw,
                    "encoded_marker_present": in_encoded,
                    "executable": is_executable,
                },
                reproduction_steps=[
                    f"Open {meta['url']}",
                    f"Submit the payload into field '{meta['field']}'.",
                    f"Open {url}",
                    f"Confirm marker '{marker}' is rendered from persistent storage.",
                ],
            )
            findings.append(finding)

        return findings
