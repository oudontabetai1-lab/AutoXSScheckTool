"""
OS Command Injection Scanner
Detects OS command injection vulnerabilities.
"""
import asyncio
from typing import TYPE_CHECKING

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# Patterns indicating command execution in response
OS_OUTPUT_PATTERNS = [
    # Linux/Mac command output
    r"uid=\d+\(",            # id command
    r"gid=\d+\(",            # id command
    r"root:x:\d+:\d+:",      # /etc/passwd
    r"/bin/bash",
    r"/bin/sh",
    r"/usr/bin",
    r"LISTENING|ESTABLISHED",  # netstat
    r"total \d+\ndr",          # ls -la
    r"Linux.*#\d+",            # uname -a
    r"Darwin Kernel Version",  # macOS
    # Windows command output
    r"Windows IP Configuration",    # ipconfig
    r"Microsoft Windows \[Version", # ver
    r"Volume in drive [A-Z]",       # dir
    r"Directory of [A-Z]:\\",       # dir
    r"\[extensions\]",              # win.ini
    r"for 16-bit app support",      # win.ini
    r"WINDOWS\\system32",
    # Environment variables
    r"PATH=|Path=",
    r"HOME=/",
    r"SHELL=",
    # Common Unix file contents
    r"nobody:x:\d+",
    r"daemon:x:\d+",
    r"www-data:x:\d+",
]

# Blind/time-based payloads
TIME_BASED_PAYLOADS = [
    "; sleep 3",
    "| sleep 3",
    "& sleep 3",
    "&& sleep 3",
    "; ping -c 3 127.0.0.1",
    "| ping -c 3 127.0.0.1",
    "& ping -n 3 127.0.0.1",
]


class OSInjectionScanner(BaseScanner):
    """OS Command Injection vulnerability scanner."""

    CHECK_TYPE = "os"
    SEVERITY = "critical"

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        """Scan a form field or URL parameter for OS command injection."""
        findings = []
        field_name = field.get("name", "unknown")
        payloads = await self.get_payloads(field_name, url)

        if self.monitor:
            await self.monitor.emit_status(
                f"OS injection testing: {field_name} on {url}"
            )

        for payload in payloads:
            if self.monitor:
                await self.monitor.emit_payload_test(field_name, payload, "os")

            await self.browser.screenshot_b64(f"OS inject test: {field_name}")

            # Apply payload
            source, pair = await self._apply_payload(
                url, form_index, field_name, payload, is_url_param
            )

            # --- Check 1: Command output in response ---
            match = self.check_response_for_patterns(source, OS_OUTPUT_PATTERNS)
            if match:
                finding = await self.record_finding(
                    url=url,
                    field_name=field_name,
                    payload=payload,
                    evidence=f"OS command output detected in response: '{match}'",
                    pair=pair,
                    severity="critical",
                )
                findings.append(finding)
                break

            # --- Check 2: Time-based blind injection ---
            if payload in TIME_BASED_PAYLOADS:
                if self.response_time_exceeded(pair, threshold=2.8):
                    finding = await self.record_finding(
                        url=url,
                        field_name=field_name,
                        payload=payload,
                        evidence="Time-based blind OS injection: response delayed (>3s)",
                        pair=pair,
                        severity="high",
                    )
                    findings.append(finding)
                    break

            await asyncio.sleep(0.2)

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
