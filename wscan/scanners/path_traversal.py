"""
Path Traversal / Directory Traversal Scanner
Detects parameter-based directory traversal (IPA: 1.3 パス名パラメータの未チェック).
"""
import asyncio
from typing import TYPE_CHECKING

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# Patterns indicating successful file content retrieval
PATH_TRAVERSAL_PATTERNS = [
    r"root:x:\d+:\d+:",        # /etc/passwd
    r"nobody:x:\d+",
    r"daemon:x:\d+",
    r"www-data:x:\d+",
    r"mysql:x:\d+",
    r"\[extensions\]",          # Windows win.ini
    r"for 16-bit app support",  # Windows win.ini
    r"\[boot loader\]",         # Windows boot.ini
    r"WINDOWS\\system32",
    r"<?php",                   # PHP source leak
    r"#!/usr/bin/perl",         # CGI source leak
    r"#!/usr/bin/python",
    r"# /etc/hosts",
    r"127\.0\.0\.1\s+localhost",  # /etc/hosts
]


class PathTraversalScanner(BaseScanner):
    """Directory / path traversal vulnerability scanner (IPA 1.3)."""

    CHECK_TYPE = "path_traversal"
    SEVERITY = "high"

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        """Scan a form field or URL parameter for path traversal."""
        findings = []
        field_name = field.get("name", "unknown")
        payloads = await self.get_payloads(field_name, url)

        if self.monitor:
            await self.monitor.emit_status(
                f"Path traversal testing: {field_name} on {url}"
            )

        # Baseline: capture what patterns already appear in a neutral response
        baseline_source, _ = await self._apply_payload(
            url, form_index, field_name, "baseline_test_value", is_url_param
        )

        for payload in payloads:
            if self.monitor:
                await self.monitor.emit_payload_test(field_name, payload, "path_traversal", url)

            source, pair = await self._apply_payload(
                url, form_index, field_name, payload, is_url_param
            )
            await asyncio.sleep(0.2 * self.sleep_factor)

            match = self.check_response_for_patterns(source, PATH_TRAVERSAL_PATTERNS)
            if match:
                # Skip when baseline already contained the same pattern.
                # When baseline retrieval failed (baseline_source is empty) we fall
                # through and flag — but we note this as a lower confidence case
                # below via evidence text.
                if baseline_source:
                    baseline_match = self.check_response_for_patterns(
                        baseline_source, PATH_TRAVERSAL_PATTERNS
                    )
                    if baseline_match:
                        continue  # Pattern pre-existed — not caused by our payload
                evidence_suffix = (
                    "" if baseline_source else " (baseline unavailable — verify manually)"
                )

                finding = await self.record_finding(
                    url=url,
                    field_name=field_name,
                    payload=payload,
                    evidence=(
                        f"Path traversal successful — file content in response: '{match}'"
                        f"{evidence_suffix}"
                    ),
                    pair=pair,
                    severity="high",
                )
                findings.append(finding)
                break

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
        except Exception as exc:
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] path_traversal: _apply_payload failed on {field_name} @ {url}: {exc}"
                )
            return "", {}
