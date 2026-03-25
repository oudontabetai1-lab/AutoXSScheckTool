"""
SSTI (Server-Side Template Injection) Scanner
Detects template injection using math-probe technique.
"""
import asyncio
from typing import TYPE_CHECKING

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# Probe tuples: (payload, expected_substring, template_engine_name)
# Use 1337*1337=1787569 — a distinctive result that rarely appears naturally on pages.
SSTI_PROBES = [
    ("{{1337*1337}}", "1787569", "Jinja2/Twig"),
    ("${1337*1337}", "1787569", "Mako/Freemarker"),
    ("<%= 1337*1337 %>", "1787569", "ERB"),
    ("#{1337*1337}", "1787569", "Ruby/Pebble"),
    ("{{3*'wscan'}}", "wscanwscanwscan", "Jinja2-str"),
    ("*{1337*1337}", "1787569", "SpEL"),
    ("%{1337*1337}", "1787569", "OGNL"),
    ("[[${1337*1337}]]", "1787569", "Thymeleaf"),
]


class SSTIScanner(BaseScanner):
    """SSTI vulnerability scanner."""

    CHECK_TYPE = "ssti"
    SEVERITY = "critical"

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        """Scan a field for SSTI vulnerabilities."""
        findings = []
        field_name = field.get("name", "unknown")

        if self.monitor:
            await self.monitor.emit_status(f"SSTI testing: {field_name} on {url}")

        # Baseline: submit a neutral value to capture any pre-existing numbers in the response.
        baseline_source, _ = await self._apply_payload(
            url, form_index, field_name, "wscan_ssti_baseline", is_url_param
        )

        for payload, expected, engine_name in SSTI_PROBES:
            if self.monitor:
                await self.monitor.emit_payload_test(field_name, payload, "ssti")

            source, pair = await self._apply_payload(
                url, form_index, field_name, payload, is_url_param
            )

            await asyncio.sleep(0.2 * self.sleep_factor)

            if not source or expected not in source:
                continue

            # Reduce false positives: only flag if the expected value was NOT already
            # present in the baseline response (it appeared only after template evaluation).
            if baseline_source and expected in baseline_source:
                continue

            finding = await self.record_finding(
                url=url,
                field_name=field_name,
                payload=payload,
                evidence=(
                    f"SSTI detected ({engine_name}): "
                    f"payload '{payload}' evaluated to '{expected}' in response"
                ),
                pair=pair,
                severity="critical",
            )
            findings.append(finding)
            break  # Confirmed - no need to test more probes

        return findings

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
