"""
HTTP Header Injection Scanner
Detects CRLF injection that allows arbitrary HTTP response header insertion (IPA: 1.7).
"""
import asyncio
from typing import TYPE_CHECKING

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# Unique marker embedded in injected header so we can confirm it was reflected
_MARKER = "WscanHdrInject"

# Payloads — each injects a custom header using various CRLF encodings
CRLF_PAYLOADS = [
    f"\r\nX-{_MARKER}: 1",
    f"\n X-{_MARKER}: 1",          # bare LF (some servers accept it)
    f"%0d%0aX-{_MARKER}:%201",
    f"%0aX-{_MARKER}:%201",
    f"%0d%0a X-{_MARKER}:%201",    # with space (some WAF bypasses)
    f"\r\nSet-Cookie: wscan_session=injected; Path=/",  # also test cookie injection
]


class HeaderInjectionScanner(BaseScanner):
    """HTTP Header Injection / CRLF injection scanner (IPA 1.7)."""

    CHECK_TYPE = "header_injection"
    SEVERITY = "high"

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        findings = []
        field_name = field.get("name", "unknown")

        if self.monitor:
            await self.monitor.emit_status(
                f"Header injection testing: {field_name} on {url}"
            )

        for payload in CRLF_PAYLOADS:
            if self.monitor:
                await self.monitor.emit_payload_test(field_name, payload, "header_injection")

            source, pair = await self._apply_payload(
                url, form_index, field_name, payload, is_url_param
            )
            await asyncio.sleep(0.2 * self.sleep_factor)

            resp_headers = {
                k.lower(): v
                for k, v in pair.get("response", {}).get("headers", {}).items()
            }

            # Confirmed: injected header name appears in the response headers
            marker_lower = f"x-{_MARKER.lower()}"
            if marker_lower in resp_headers:
                finding = await self.record_finding(
                    url=url,
                    field_name=field_name,
                    payload=payload,
                    evidence=(
                        f"HTTP header injection confirmed: "
                        f"'X-{_MARKER}' appeared in response headers"
                    ),
                    pair=pair,
                    severity="high",
                )
                findings.append(finding)
                break

            # Secondary: injected Set-Cookie appeared in cookies
            if "set-cookie" in resp_headers and "wscan_session=injected" in resp_headers.get("set-cookie", ""):
                finding = await self.record_finding(
                    url=url,
                    field_name=field_name,
                    payload=payload,
                    evidence=(
                        "HTTP header injection: attacker-controlled Set-Cookie header "
                        "injected into the HTTP response"
                    ),
                    pair=pair,
                    severity="high",
                )
                findings.append(finding)
                break

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
