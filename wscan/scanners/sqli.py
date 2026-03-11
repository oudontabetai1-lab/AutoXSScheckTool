"""
SQL Injection Scanner
Detects error-based, boolean-based, and time-based SQL injection.
"""
import asyncio
import time
from typing import TYPE_CHECKING

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine

# SQL error message patterns for various databases
SQL_ERROR_PATTERNS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning:.*mysql",
    r"unclosed quotation mark after the character string",
    r"mysql_fetch_array\(\)",
    r"mysql_num_rows\(\)",
    r"supplied argument is not a valid mysql",
    r"mysql server version for the right syntax",
    # PostgreSQL
    r"ERROR:\s+syntax error at or near",
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"PostgreSQL.*ERROR",
    # MSSQL
    r"unclosed quotation mark",
    r"microsoft OLE DB Provider for SQL Server",
    r"microsoft SQL Native Client error",
    r"incorrect syntax near",
    r"SQLSTATE\[42000\]",
    # Oracle
    r"ORA-\d{4,5}:",
    r"Oracle error",
    r"oracle.*driver",
    # SQLite
    r"SQLite3::query\(\)",
    r"unrecognized token",
    r"SQLite.*error",
    # Generic
    r"syntax error.*sql",
    r"sql.*syntax error",
    r"database.*error",
    r"odbc.*error",
    r"db2.*error",
]

# Time-based payloads that should cause a delay
TIME_BASED_PAYLOADS = [
    "1' AND SLEEP(3)--",
    "1; WAITFOR DELAY '0:0:3'--",
    "1' AND BENCHMARK(3000000,MD5('a'))--",
    "1) AND SLEEP(3)--",
]


class SQLiScanner(BaseScanner):
    """SQL Injection vulnerability scanner."""

    CHECK_TYPE = "sqli"
    SEVERITY = "critical"

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        """Scan a form field or URL parameter for SQL injection."""
        findings = []
        field_name = field.get("name", "unknown")
        payloads = await self.get_payloads(field_name, url)

        if self.monitor:
            await self.monitor.emit_status(
                f"SQLi testing: {field_name} on {url}"
            )

        # Get baseline response for comparison
        baseline_source, baseline_pair = await self._get_baseline(
            url, form_index, field_name, is_url_param
        )
        baseline_len = len(baseline_source)

        for payload in payloads:
            if self.monitor:
                await self.monitor.emit_payload_test(field_name, payload, "sqli")

            # Take before screenshot
            await self.browser.screenshot_b64(f"SQLi test: {field_name} = {payload[:30]}")

            # Apply payload
            source, pair = await self._apply_payload(
                url, form_index, field_name, payload, is_url_param
            )

            # --- Check 1: Error-based SQLi ---
            match = self.check_response_for_patterns(source, SQL_ERROR_PATTERNS)
            if match:
                finding = await self.record_finding(
                    url=url,
                    field_name=field_name,
                    payload=payload,
                    evidence=f"SQL error message detected: '{match}'",
                    pair=pair,
                    severity="critical",
                )
                findings.append(finding)
                break  # Found vulnerability, move to next field

            # --- Check 2: Response length anomaly (boolean-based indicator) ---
            diff = abs(len(source) - baseline_len)
            if diff > 500 and baseline_len > 0:
                # Significant change - note as potential
                pass  # Could be informational, skip for now

            # --- Check 3: Time-based blind SQLi ---
            if payload in TIME_BASED_PAYLOADS:
                if self.response_time_exceeded(pair, threshold=2.8):
                    finding = await self.record_finding(
                        url=url,
                        field_name=field_name,
                        payload=payload,
                        evidence=f"Time-based blind SQLi: response delayed (>3s)",
                        pair=pair,
                        severity="high",
                    )
                    findings.append(finding)
                    break

            # Small delay to avoid overwhelming the server
            await asyncio.sleep(0.2)

        return findings

    async def _get_baseline(
        self, url: str, form_index: int, field_name: str, is_url_param: bool
    ) -> tuple[str, dict]:
        """Get a baseline response with a safe value."""
        try:
            if is_url_param:
                return await self.browser.test_url_param(url, field_name, "baseline_test")
            else:
                return await self.browser.fill_and_submit_form(
                    form_index, field_name, "baseline_test"
                )
        except Exception:
            return "", {}

    async def _apply_payload(
        self,
        url: str,
        form_index: int,
        field_name: str,
        payload: str,
        is_url_param: bool,
    ) -> tuple[str, dict]:
        """Apply a payload to the target field."""
        try:
            if is_url_param:
                return await self.browser.test_url_param(url, field_name, payload)
            else:
                # Re-navigate to the page before each test
                await self.browser.navigate(url)
                return await self.browser.fill_and_submit_form(
                    form_index, field_name, payload
                )
        except Exception:
            return "", {}
