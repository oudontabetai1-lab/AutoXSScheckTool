"""
HTTP Header Injection Scanner
Detects CRLF injection that allows arbitrary HTTP response header insertion (IPA: 1.7).
"""
import asyncio
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

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


def _response_headers(pair: dict) -> dict:
    return {
        k.lower(): v
        for k, v in pair.get("response", {}).get("headers", {}).items()
    }


def _injected_header_detected(pair: dict) -> tuple[bool, str]:
    resp_headers = _response_headers(pair)
    marker_lower = f"x-{_MARKER.lower()}"
    if marker_lower in resp_headers:
        return True, "marker_header"
    set_cookie = resp_headers.get("set-cookie", "").lower()
    if "wscan_session=injected" in set_cookie:
        return True, "set_cookie"
    return False, ""


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
            await self.log_payload_test(field_name, payload, "header_injection", url)

            source, pair = await self._apply_payload(
                url, form_index, field_name, payload, is_url_param
            )
            await asyncio.sleep(0.2 * self.sleep_factor)

            # Confirmed: injected header name appears in the response headers
            detected, signal = _injected_header_detected(pair)
            if detected and signal == "marker_header":
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

            # Secondary: injected Set-Cookie appeared in cookies (case-insensitive value check)
            if detected and signal == "set_cookie":
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

    async def verify_finding(self, finding: Finding) -> bool | None:
        is_url_param = finding.field_name in parse_qs(
            urlparse(finding.url).query, keep_blank_values=True
        )
        _source, pair = await self._apply_payload(
            finding.url,
            0,
            finding.field_name,
            finding.payload,
            is_url_param,
        )
        detected, _signal = _injected_header_detected(pair)
        return detected

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
        except Exception as exc:
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] header_injection: _apply_payload failed on {field_name} @ {url}: {exc}"
                )
            return "", {}
