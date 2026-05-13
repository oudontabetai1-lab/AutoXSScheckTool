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
import re
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
            current_url = getattr(self.browser.page, "url", "") or ""
            if current_url.split("#")[0].rstrip("/") != url.split("#")[0].rstrip("/"):
                ok = await self.browser.navigate(url)
                if ok is False:
                    return []
                await asyncio.sleep(0.2 * self.sleep_factor)
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
            pair = self.current_page_pair(url)

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

    async def verify_finding(self, finding: Finding) -> bool | None:
        if finding.evidence_type not in {
            "stored_xss_marker",
            "stored_html_marker",
            "stored_xss_chain_title",
            "stored_html_chain_marker",
        }:
            return None

        details = getattr(finding, "evidence_details", {}) or {}
        source_url = (
            details.get("injection_url")
            or details.get("source_url")
            or finding.url
        )
        sink_url = (
            details.get("sink_url")
            or details.get("trigger_url")
            or finding.url
        )
        field_name = details.get("source_field") or finding.field_name
        marker = self._marker_for_finding(finding)
        if not source_url or not sink_url or not field_name or not marker:
            return None

        try:
            await self._submit_payload(source_url, field_name, finding.payload)
            self.browser.reset_dialog()
            ok = await self.browser.navigate(sink_url)
            if ok is False:
                return None
            await asyncio.sleep(0.5 * self.sleep_factor)
            html = await self.browser.get_page_source()
        except Exception:
            return None

        if self.browser.dialog_fired and marker in self.browser.dialog_message:
            return True

        try:
            title = await self.browser.page.title()
            if marker in (title or ""):
                return True
        except Exception:
            pass

        return self._marker_in_html(marker, html or "")

    async def _submit_payload(self, url: str, field_name: str, payload: str):
        from urllib.parse import parse_qs, urlparse

        is_url_param = field_name in parse_qs(
            urlparse(url).query, keep_blank_values=True
        )
        if is_url_param:
            return await self.browser.test_url_param(url, field_name, payload)

        await self.browser.navigate(url)
        return await self.browser.fill_and_submit_form(0, field_name, payload)

    def _marker_for_finding(self, finding: Finding) -> str:
        details = getattr(finding, "evidence_details", {}) or {}
        marker = details.get("marker") or details.get("probe_uid")
        if marker:
            return str(marker)

        match = re.search(r"(?:wsxss|wscc_|wscanchain_)[0-9a-fA-F]+", finding.payload or "")
        return match.group(0) if match else ""

    def _marker_in_html(self, marker: str, html: str) -> bool:
        candidates = {
            marker,
            _html.escape(marker),
            f"wscc_{marker}",
            f"wscanchain_{marker}",
            f'id="wscc_{marker}"',
        }
        return any(candidate in html for candidate in candidates)
