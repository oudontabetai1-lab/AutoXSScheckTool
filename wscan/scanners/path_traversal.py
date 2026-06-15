"""
Path Traversal / Directory Traversal Scanner
Detects parameter-based directory traversal (IPA: 1.3 パス名パラメータの未チェック).
"""
import asyncio
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

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
    r"<\?php",                  # PHP source leak (literal <?php opening tag)
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
        # baseline もフィールド投入なので監査ログに残す（log_payload_test 一元化の不変条件）。
        await self.log_payload_test(
            field_name, "baseline_test_value", "path_traversal_baseline", url
        )
        baseline_source, _ = await self._apply_payload(
            url, form_index, field_name, "baseline_test_value", is_url_param
        )

        async def _test_payload(payload: str, check_label: str = "path_traversal") -> bool:
            await self.log_payload_test(field_name, payload, check_label, url)

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
                        return False  # Pattern pre-existed — not caused by our payload
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
                    confidence="likely",
                )
                findings.append(finding)
                return True
            return False

        for payload in payloads:
            if await _test_payload(payload):
                break

        if not findings:
            extra_payloads = await self.evolved_payloads(
                url, form_index, field_name, is_url_param
            )
            for payload in extra_payloads:
                if await _test_payload(payload, "path_traversal_evolved"):
                    break

        # --- Mutation wave: 二重エンコード + NULL バイト + 拡張子で素朴な防御を回避 ---
        if not findings:
            mutated = await self.mutated_payloads(field_name, url, payloads)
            for payload in mutated:
                if await _test_payload(payload, "path_traversal_mutation"):
                    break

        return findings

    async def verify_finding(self, finding: Finding) -> bool | None:
        is_url_param = finding.field_name in parse_qs(
            urlparse(finding.url).query, keep_blank_values=True
        )
        # verify 時の再投入（baseline + payload）も監査ログに残す。
        await self.log_payload_test(
            finding.field_name, "baseline_test_value",
            "path_traversal_verify_baseline", finding.url,
        )
        baseline_source, _ = await self._apply_payload(
            finding.url,
            0,
            finding.field_name,
            "baseline_test_value",
            is_url_param,
        )
        await self.log_payload_test(
            finding.field_name, finding.payload,
            "path_traversal_verify", finding.url,
        )
        source, _pair = await self._apply_payload(
            finding.url,
            0,
            finding.field_name,
            finding.payload,
            is_url_param,
        )
        match = self.check_response_for_patterns(source or "", PATH_TRAVERSAL_PATTERNS)
        if not match:
            return False
        if baseline_source:
            baseline_match = self.check_response_for_patterns(
                baseline_source,
                PATH_TRAVERSAL_PATTERNS,
            )
            if baseline_match:
                return False
        return True

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
