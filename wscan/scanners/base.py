"""
Base Scanner Class
Provides common utilities for all vulnerability scanners.
"""
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


@dataclass
class Finding:
    """A security vulnerability finding."""
    check_type: str          # sqli, xss, os, etc.
    severity: str            # critical, high, medium, low, info
    url: str
    field_name: str
    payload: str
    evidence: str            # Description of what triggered the finding
    request: dict = field(default_factory=dict)
    response: dict = field(default_factory=dict)
    screenshot_b64: str = ""
    dialog_confirmed: bool = False   # True when JS alert() was actually triggered
    dialog_message: str = ""         # The alert message that appeared
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "check_type": self.check_type,
            "severity": self.severity,
            "url": self.url,
            "field_name": self.field_name,
            "payload": self.payload,
            "evidence": self.evidence,
            "request": self.request,
            "response": {k: v for k, v in self.response.items() if k != "body"},
            "response_body_excerpt": (self.response.get("body", "") or "")[:500],
            "screenshot_b64": self.screenshot_b64,
            "dialog_confirmed": self.dialog_confirmed,
            "dialog_message": self.dialog_message,
            "timestamp": self.timestamp,
        }


class BaseScanner(ABC):
    """Base class for all vulnerability scanners."""

    CHECK_TYPE = "base"
    SEVERITY = "medium"

    def __init__(self, engine: "ScanEngine"):
        self.engine = engine
        self.browser = engine.browser
        self.monitor = engine.monitor
        self.payload_gen = engine.payload_gen
        self.findings: list[Finding] = []

    @abstractmethod
    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        """Scan a single input field for vulnerabilities."""
        ...

    async def get_payloads(self, field_name: str, url: str) -> list[str]:
        """Get payloads for this scanner's check type."""
        return await self.payload_gen.generate(
            check_type=self.CHECK_TYPE,
            field_name=field_name,
            url=url,
            custom_payloads=self.engine.custom_payloads.get(self.CHECK_TYPE),
        )

    def check_response_for_patterns(self, body: str, patterns: list[str]) -> Optional[str]:
        """Check response body for any of the given regex patterns."""
        for pattern in patterns:
            match = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(0)[:200]
        return None

    def response_time_exceeded(self, pair: dict, threshold: float = 3.0) -> bool:
        """Check if response time suggests a time-based injection."""
        req = pair.get("request", {})
        resp = pair.get("response", {})
        req_ts = req.get("timestamp", 0)
        resp_ts = resp.get("timestamp", 0)
        if req_ts and resp_ts:
            return (resp_ts - req_ts) >= threshold
        return False

    async def record_finding(
        self,
        url: str,
        field_name: str,
        payload: str,
        evidence: str,
        pair: dict,
        severity: Optional[str] = None,
        screenshot_b64: Optional[str] = None,
        dialog_confirmed: bool = False,
        dialog_message: str = "",
    ) -> Finding:
        """Create and record a finding."""
        if screenshot_b64 is None:
            screenshot_b64 = await self.browser.screenshot_b64(
                label=f"[FINDING] {self.CHECK_TYPE} on {field_name}"
            )
        finding = Finding(
            check_type=self.CHECK_TYPE,
            severity=severity or self.SEVERITY,
            url=url,
            field_name=field_name,
            payload=payload,
            evidence=evidence,
            request=pair.get("request", {}),
            response=pair.get("response", {}),
            screenshot_b64=screenshot_b64,
            dialog_confirmed=dialog_confirmed,
            dialog_message=dialog_message,
        )
        self.findings.append(finding)
        self.engine.all_findings.append(finding)
        if self.monitor:
            await self.monitor.emit_finding(finding.to_dict())
        return finding
