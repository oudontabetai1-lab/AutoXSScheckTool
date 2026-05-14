"""
Open Redirect Scanner
Detects unvalidated URL redirect vulnerabilities (IPA: 1.11 アクセス制御・認可制御の欠落).

Only tests parameters whose names suggest they hold redirect targets.
Detection: after injecting an external URL, checks whether:
  - The browser's final URL contains the external domain, OR
  - The HTTP response has a Location header pointing to the external domain.
"""
import asyncio
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# Parameter names commonly used for redirect targets
REDIRECT_PARAM_NAMES = {
    "next", "redirect", "redirect_to", "redirect_url", "redirecturl",
    "return", "return_to", "returnto", "return_url", "returnurl",
    "url", "forward", "goto", "target", "dest", "destination",
    "redir", "continue", "ref", "callback", "back", "location",
    "jump", "link",
    # Additional common names
    "endpoint", "service", "webhook", "callback_url", "logout_url",
    "error_page", "api", "jump_to", "redirect_uri", "post_login_redirect",
    "success_url", "failure_url", "cancel_url", "after_login", "after_logout",
    "from", "from_url", "origin", "referrer", "referer", "path",
    "out", "go", "view", "page", "site", "host",
}

# External domain used in payloads — chosen to be distinctive and harmless
_CANARY_HOST = "evil.wscan-test.example.com"

REDIRECT_PAYLOADS = [
    f"https://{_CANARY_HOST}",
    f"//{_CANARY_HOST}",             # protocol-relative
    f"https:/{_CANARY_HOST}",        # single-slash variant
    f"/\\{_CANARY_HOST}",            # backslash bypass
    f"/%09/{_CANARY_HOST}",          # tab character bypass
    f"https://{_CANARY_HOST}%2F%2E", # trailing encoded chars
]


def _location_header(pair: dict) -> str:
    headers = pair.get("response", {}).get("headers", {}) or {}
    return headers.get("location", "") or headers.get("Location", "")


def _is_external_redirect(pair: dict, current_url: str = "") -> bool:
    return _CANARY_HOST in (current_url or "") or _CANARY_HOST in _location_header(pair)


class OpenRedirectScanner(BaseScanner):
    """Open redirect scanner — tests redirect-named parameters (IPA 1.11)."""

    CHECK_TYPE = "open_redirect"
    SEVERITY = "medium"

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        field_name = field.get("name", "unknown")

        # Only test fields/params whose names suggest a redirect target
        if field_name.lower() not in REDIRECT_PARAM_NAMES:
            return []

        findings = []

        if self.monitor:
            await self.monitor.emit_status(
                f"Open redirect testing: {field_name} on {url}"
            )

        for payload in REDIRECT_PAYLOADS:
            if self.monitor:
                await self.monitor.emit_payload_test(field_name, payload, "open_redirect", url)

            source, pair = await self._apply_payload(
                url, form_index, field_name, payload, is_url_param
            )
            await asyncio.sleep(0.3 * self.sleep_factor)

            # Check 1: browser actually navigated to the canary host
            try:
                current_url = self.browser.page.url
            except Exception as exc:
                if self.monitor:
                    await self.monitor.emit_status(
                        f"[warn] open_redirect: current_url read failed on {url}: {exc}"
                    )
                current_url = ""

            if _CANARY_HOST in current_url:
                finding = await self.record_finding(
                    url=url,
                    field_name=field_name,
                    payload=payload,
                    evidence=(
                        f"Open redirect confirmed: browser redirected to '{current_url}'"
                    ),
                    pair=pair,
                    severity="medium",
                    confidence="confirmed",
                )
                findings.append(finding)
                break

            # Check 2: Location header in the captured HTTP response points externally
            location = _location_header(pair)
            if location and _CANARY_HOST in location:
                finding = await self.record_finding(
                    url=url,
                    field_name=field_name,
                    payload=payload,
                    evidence=(
                        f"Open redirect via Location header: '{location}'"
                    ),
                    pair=pair,
                    severity="medium",
                    confidence="likely",
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
        try:
            current_url = self.browser.page.url
        except Exception:
            current_url = ""
        return _is_external_redirect(pair, current_url)

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
                    f"[warn] open_redirect: _apply_payload failed on {field_name} @ {url}: {exc}"
                )
            return "", {}
