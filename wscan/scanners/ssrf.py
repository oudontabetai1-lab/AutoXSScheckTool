"""
SSRF (Server-Side Request Forgery) Scanner
Detects vulnerabilities where user-supplied URLs are fetched server-side.

Detection methods:
1. Cloud metadata endpoint content in response (AWS / GCP / Azure)
2. Local file disclosure via file:// scheme
3. Internal service response signatures (localhost)

Only tests fields whose names suggest they hold URLs or server-side paths.
"""
import asyncio
import re
from typing import TYPE_CHECKING

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# Parameter name fragments that suggest server-side URL/path fetching
SSRF_PARAM_NAMES = {
    "url", "link", "href", "src", "image", "img", "avatar", "photo",
    "file", "path", "dir", "folder", "include", "template",
    "cmd", "command", "exec", "ping", "host", "server", "ip",
    "endpoint", "api", "service", "webhook", "callback", "fetch",
    "load", "target", "proxy", "uri", "resource", "import", "export",
    "destination", "redirect", "location", "action", "next",
}

# (label, payload, detection_pattern)
_SSRF_PROBES: list[tuple[str, str, re.Pattern]] = [
    (
        "AWS metadata (IMDSv1)",
        "http://169.254.169.254/latest/meta-data/",
        re.compile(r"ami-id|instance-id|instance-type|placement|local-ipv4|public-hostname", re.I),
    ),
    (
        "GCP metadata",
        "http://metadata.google.internal/computeMetadata/v1/",
        re.compile(r"computeMetadata|project.*id|serviceAccount|zone|instance", re.I),
    ),
    (
        "Azure IMDS",
        "http://169.254.169.254/metadata/instance",
        re.compile(r"subscriptionId|resourceGroupName|vmId|location.*eastus", re.I),
    ),
    (
        "Localhost HTTP",
        "http://127.0.0.1/",
        re.compile(
            r"<html[\s>]|Server\s*:|X-Powered-By\s*:|Apache|nginx|Index of /",
            re.I,
        ),
    ),
    (
        "Localhost (name)",
        "http://localhost/",
        re.compile(r"<html[\s>]|Server\s*:|X-Powered-By\s*:", re.I),
    ),
    (
        "File read (/etc/passwd)",
        "file:///etc/passwd",
        re.compile(r"root:.*:/bin/|daemon:.*:|nobody:.*:", re.I),
    ),
    (
        "IPv6 loopback",
        "http://[::1]/",
        re.compile(r"<html[\s>]|Server\s*:", re.I),
    ),
]


class SSRFScanner(BaseScanner):
    CHECK_TYPE = "ssrf"
    SEVERITY = "critical"

    def _is_ssrf_param(self, field_name: str) -> bool:
        """Return True if the field name suggests a server-side URL/path input."""
        name = field_name.lower().replace("-", "_").replace(" ", "_")
        return any(token in name for token in SSRF_PARAM_NAMES)

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        field_name = field.get("name", "unknown")

        # Only test fields that plausibly accept URLs or server-side paths
        if not (is_url_param or self._is_ssrf_param(field_name)):
            return []

        findings: list[Finding] = []

        if self.monitor:
            await self.monitor.emit_status(
                f"SSRF testing: {field_name} on {url}"
            )

        # Capture a clean baseline to avoid false-positives from pre-existing content
        baseline_source, _ = await self._apply_payload(
            url, form_index, field_name, "http://wscan-baseline-test.invalid/", is_url_param
        )

        for label, payload, pattern in _SSRF_PROBES:
            if self.monitor:
                await self.monitor.emit_payload_test(field_name, payload, "ssrf")

            source, pair = await self._apply_payload(
                url, form_index, field_name, payload, is_url_param
            )
            await asyncio.sleep(0.3 * self.sleep_factor)

            if not source:
                continue

            # Skip if the pattern already appears in baseline (pre-existing content)
            if baseline_source and pattern.search(baseline_source):
                continue

            match = pattern.search(source)
            if match:
                finding = await self.record_finding(
                    url=url,
                    field_name=field_name,
                    payload=payload,
                    evidence=(
                        f"SSRF confirmed ({label}): server response contains "
                        f"internal content marker '{match.group(0)[:100]}'"
                    ),
                    pair=pair,
                    severity="critical",
                )
                findings.append(finding)
                break  # one confirmed finding per field is sufficient

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
