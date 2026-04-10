"""
OS Command Injection Scanner
Detects OS command injection vulnerabilities.
"""
import asyncio
from typing import TYPE_CHECKING

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# Patterns indicating command execution in response.
OS_OUTPUT_PATTERNS = [
    # Linux/Mac — output from 'id' command (flexible: gid optional)
    r"uid=\d+",
    r"gid=\d+",
    # /etc/passwd entries (partial match is sufficient)
    r"root:x:\d+",
    r"nobody:x:\d+",
    r"daemon:x:\d+",
    r"www-data:x:\d+",
    # Shell paths
    r"/bin/(?:bash|sh|zsh|dash)",
    # ls -la output (relaxed)
    r"(?:total \d+|drwx|drwxr|drwxrwx)",
    # uname output
    r"Linux \S+ \d+\.\d+",
    r"Darwin Kernel Version",
    # Windows
    r"Windows IP Configuration",
    r"Microsoft Windows \[Version",
    r"(?:Volume in drive|Directory of [A-Z]:\\)",
    r"for 16-bit app support",
    r"WINDOWS\\system32\\cmd\.exe",
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

        # Baseline: capture pre-existing patterns and response time
        baseline_source, baseline_pair = await self._apply_payload(
            url, form_index, field_name, "baseline_os_test", is_url_param
        )
        _b_req = baseline_pair.get("request", {})
        _b_resp = baseline_pair.get("response", {})
        _b_ts_req = _b_req.get("timestamp", 0)
        _b_ts_resp = _b_resp.get("timestamp", 0)
        baseline_time = (
            float(_b_ts_resp - _b_ts_req)
            if _b_ts_req and _b_ts_resp
            else 0.0
        )
        # Threshold = baseline + 2.8 s (injected sleep) with 0.5 s margin
        time_threshold = max(2.8, baseline_time + 2.8)

        for payload in payloads:
            if self.monitor:
                await self.monitor.emit_payload_test(field_name, payload, "os", url)

            # Apply payload
            source, pair = await self._apply_payload(
                url, form_index, field_name, payload, is_url_param
            )

            # --- Check 1: Command output in response (not pre-existing in baseline) ---
            match = self.check_response_for_patterns(source, OS_OUTPUT_PATTERNS)
            if match:
                baseline_match = self.check_response_for_patterns(
                    baseline_source, OS_OUTPUT_PATTERNS
                ) if baseline_source else None
                if not baseline_match:
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
                if self.response_time_exceeded(pair, threshold=time_threshold):
                    finding = await self.record_finding(
                        url=url,
                        field_name=field_name,
                        payload=payload,
                        evidence=f"Time-based blind OS injection: response delayed (>{time_threshold:.1f}s, baseline {baseline_time:.2f}s)",
                        pair=pair,
                        severity="high",
                    )
                    findings.append(finding)
                    break

            await asyncio.sleep(0.2 * self.sleep_factor)

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
