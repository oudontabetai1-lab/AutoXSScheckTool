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
SSTI_PROBES = [
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("${7*7}", "49", "Mako/Freemarker"),
    ("<%= 7*7 %>", "49", "ERB"),
    ("#{7*7}", "49", "Ruby/Pebble"),
    ("{{7*'7'}}", "7777777", "Jinja2"),
    ("*{7*7}", "49", "SpEL"),
    ("%{7*7}", "49", "OGNL"),
    ("[[${7*7}]]", "49", "Thymeleaf"),
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
