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


# CVSS 3.1 base score lookup table: check_type → (vector_string, numeric_score)
# Vectors use worst-case assumptions for web scanner context.
_CVSS_TABLE: dict[str, tuple[str, float]] = {
    "sqli":              ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "sqli_auth_bypass":  ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "xss":               ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",  8.8),
    "dom_xss":           ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",  8.8),
    "os":                ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "ssti":              ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "path_traversal":    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  7.5),
    "open_redirect":     ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",  6.1),
    "csrf":              ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",  6.5),
    "header_injection":  ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",  5.3),
    "mail_header":       ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",  5.3),
    "clickjacking":      ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",  4.3),
    "session":           ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",  7.4),
    "privesc_unauth":    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  9.1),
    "privesc_vertical":  ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",  8.1),
    "privesc_horizontal":("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",  6.5),
    # V-1〜V-9 new scanners
    "stored_xss":        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",  9.6),
    "cors":              ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",  7.4),
    "info_disclosure":   ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  7.5),
    "host_header":       ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",  5.4),
    "security_headers":  ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",  3.1),
    "nosql":             ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  9.1),
    "deserialization":   ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "request_smuggling": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",  8.7),
    "ssrf":              ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",  9.8),
    # ② GraphQL scanner
    "graphql_introspection": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  5.3),
    "graphql_injection":     ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "graphql_batch":         ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",  5.3),
    "graphql_sensitive":     ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  5.3),
    # ④ JWT scanner
    "jwt_alg_none":      ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",  9.6),
    "jwt_weak_secret":   ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",  9.6),
    "jwt_kid_injection": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "jwt_payload_tamper":("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",  9.6),
    "jwt_no_expiry":     ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  5.3),
    "jwt_sensitive_data":("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  5.3),
    # A: Additional privesc check types
    "privesc_param_idor":("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",  6.5),
    "privesc_cross_acct":("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",  8.1),
    # Phase-4 new scanners
    "xxe":               ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "ldap":              ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",  9.6),
    "file_upload":       ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "race_condition":    ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",  6.8),
}


def _cvss_for(check_type: str) -> tuple[str, float]:
    """Return (vector, score) for a check type, or empty defaults."""
    base = check_type.split("_")[0] if "_" in check_type else check_type
    return _CVSS_TABLE.get(check_type) or _CVSS_TABLE.get(base, ("", 0.0))


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
    verified: bool = True            # False = could not reproduce on second attempt
    verification_note: str = ""      # Reason when verified=False
    confidence: str = "tentative"   # "confirmed" | "likely" | "tentative"

    @property
    def cvss_vector(self) -> str:
        return _cvss_for(self.check_type)[0]

    @property
    def cvss_score(self) -> float:
        return _cvss_for(self.check_type)[1]

    def to_dict(self) -> dict:
        from wscan.compliance_map import get_refs
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
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "verified": self.verified,
            "verification_note": self.verification_note,
            "confidence": self.confidence,
            "compliance_refs": get_refs(self.check_type),
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

    async def scan_page(self, url: str) -> list[Finding]:
        """
        Optional page-level check called once per URL, before per-field scanning.
        Override in scanners that inspect HTTP headers, cookies, or page structure
        (e.g. Clickjacking, Session, CSRF) rather than injecting payloads into fields.
        Default: returns empty list (no-op).
        """
        return []

    @property
    def sleep_factor(self) -> float:
        """Scaling factor for sleep durations (0.5 in CTF mode, 1.0 otherwise)."""
        return getattr(self.engine, "sleep_factor", 1.0)

    async def get_payloads(self, field_name: str, url: str) -> list[str]:
        """Get payloads for this scanner's check type, sorted by learning data."""
        payloads = await self.payload_gen.generate(
            check_type=self.CHECK_TYPE,
            field_name=field_name,
            url=url,
            custom_payloads=self.engine.custom_payloads.get(self.CHECK_TYPE),
        )
        # A-3 / ⑩: re-order by historical success rate (domain-aware)
        learner = getattr(self.engine, "payload_learner", None)
        if learner and getattr(self.engine, "enable_payload_learning", True):
            from urllib.parse import urlparse as _up
            _domain = _up(getattr(self.engine, "target_url", "")).hostname or None
            payloads = learner.sort_payloads(self.CHECK_TYPE, payloads, domain=_domain)
        # Fast mode: cap payload count (highest-priority payloads are already first)
        cap = getattr(self.engine, "max_payloads", 0)
        if cap > 0:
            payloads = payloads[:cap]
        return payloads

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
        # Dedup: skip if the same (url, field_name, check_type) was already recorded
        dedup_key = (url, field_name, self.CHECK_TYPE)
        if dedup_key in self.engine._finding_dedup:
            return None  # duplicate
        self.engine._finding_dedup.add(dedup_key)

        # Auto-assign confidence level
        if dialog_confirmed:
            confidence = "confirmed"
        else:
            resp_body = pair.get("response", {}).get("body", "") or ""
            base_body = pair.get("baseline_response", {}).get("body", "") or ""
            if resp_body and (len(resp_body) - len(base_body)) > 100:
                confidence = "likely"
            else:
                confidence = "tentative"

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
            confidence=confidence,
        )
        self.findings.append(finding)
        self.engine.all_findings.append(finding)
        if self.monitor:
            await self.monitor.emit_finding(finding.to_dict())
        return finding
