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
from urllib.parse import parse_qs, urlparse, urljoin

from wscan.injection_point import InjectionPoint

from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    PayloadShape, Prerequisite, ScannerContract, StateChangeClass, TransportKind,
    ValueKind,
)

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


def _normalize_slashes(url: str) -> str:
    """バックスラッシュを ``/`` に正規化する。

    主要ブラウザは ``/\\host`` や ``\\/host`` を ``//host`` と解釈して外部遷移する。
    urlparse は ``\\`` を path 文字として扱い netloc を取りこぼすため、解決前に揃える。
    """
    return (url or "").replace("\\", "/")


def _url_host(url: str, base_url: str = "") -> str:
    """Return the lowercase host of a URL, stripped of user/port.

    バックスラッシュを ``/`` に正規化し、相対参照は ``base_url`` で解決してから
    netloc を取り出す（``/\\evil`` 等のバイパスをブラウザ同様に検出するため）。
    """
    if not url:
        return ""
    norm = _normalize_slashes(url)
    target = urljoin(base_url, norm) if base_url else norm
    try:
        netloc = urlparse(target).netloc.lower()
    except Exception:
        return ""
    return netloc.split("@")[-1].split(":")[0]


def _redirected_to_canary(current_url: str, base_url: str = "") -> bool:
    """
    True only when the *destination host* of ``current_url`` is the canary.

    Substring matching is unsafe: a non-vulnerable app that simply echoes
    the parameter back in its address bar (``?next=https://canary``) would
    otherwise be flagged.  We compare the resolved netloc instead.
    """
    if not current_url:
        return False
    return _url_host(current_url, base_url) == _CANARY_HOST.lower()


def _location_points_to_canary(pair: dict, base_url: str = "") -> bool:
    location = _location_header(pair)
    if not location:
        return False
    return _url_host(location, base_url) == _CANARY_HOST.lower()


def _is_external_redirect(pair: dict, current_url: str = "", base_url: str = "") -> bool:
    return _redirected_to_canary(current_url, base_url) or _location_points_to_canary(pair, base_url)


class OpenRedirectScanner(BaseScanner):
    """Open redirect scanner — tests redirect-named parameters (IPA 1.11)."""

    CHECK_TYPE = "open_redirect"
    CONTRACT = ScannerContract(
        execution_kinds=frozenset({ExecutionKind.FIELD_INJECTION}),
        capabilities=(
            CarrierCapability(
                carrier=Carrier.QUERY, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.PLAYWRIGHT}),
                payload_shapes=frozenset({PayloadShape.SCALAR}),
            ),
            CarrierCapability(
                carrier=Carrier.FORM, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.PLAYWRIGHT}),
                payload_shapes=frozenset({PayloadShape.SCALAR}),
            ),
            CarrierCapability(
                carrier=Carrier.JSON, state=CapabilityState.PLANNED,
                reason="JSON body 検出改修は 0012/0035-D",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.XML, state=CapabilityState.UNSUPPORTED,
                reason="redirect param 特化",
            ),
            CarrierCapability(
                carrier=Carrier.MULTIPART, state=CapabilityState.UNSUPPORTED,
                reason="redirect param 特化",
            ),
            CarrierCapability(
                carrier=Carrier.HEADER, state=CapabilityState.UNSUPPORTED,
                reason="redirect param 特化",
            ),
            CarrierCapability(
                carrier=Carrier.COOKIE, state=CapabilityState.UNSUPPORTED,
                reason="redirect param 特化",
            ),
            CarrierCapability(
                carrier=Carrier.PATH, state=CapabilityState.UNSUPPORTED,
                reason="redirect param 特化",
            ),
            CarrierCapability(
                carrier=Carrier.GRAPHQL, state=CapabilityState.UNSUPPORTED,
                reason="redirect param 特化",
            ),
            CarrierCapability(
                carrier=Carrier.WEBSOCKET, state=CapabilityState.UNSUPPORTED,
                reason="redirect param 特化",
            ),
        ),
    )

    SEVERITY = "medium"
    SUPPORTS_JSON_BODY = False

    async def scan_injection_point(
        self,
        ip: InjectionPoint,
        field: dict,
    ) -> list[Finding]:
        # redirect 判定は browser transport 前提。未対応 JSON は明示的に拒否する。
        if ip.location == "json_body":
            return []

        field_name = ip.display_name or ip.parameter_id

        # Only test fields/params whose names suggest a redirect target
        if field_name.lower() not in REDIRECT_PARAM_NAMES:
            return []

        findings = []

        if self.monitor:
            await self.monitor.emit_status(
                f"Open redirect testing: {field_name} on {ip.url}"
            )

        for payload in REDIRECT_PAYLOADS:
            await self.log_payload_test(
                field_name, payload, "open_redirect", ip.url
            )

            source, pair = await self._apply_ip(ip, payload)
            await asyncio.sleep(0.3 * self.sleep_factor)

            # Check 1: browser actually navigated to the canary host
            try:
                current_url = self.browser.page.url
            except Exception as exc:
                if self.monitor:
                    await self.monitor.emit_status(
                        f"[warn] open_redirect: current_url read failed on {ip.url}: {exc}"
                    )
                current_url = ""

            if _redirected_to_canary(current_url, ip.url):
                finding = await self.record_finding(
                    url=ip.url,
                    field_name=field_name,
                    payload=payload,
                    evidence=(
                        f"Open redirect confirmed: browser redirected to '{current_url}'"
                    ),
                    pair=pair,
                    severity="medium",
                    confidence="confirmed",
                    injection_point=ip,
                )
                findings.append(finding)
                break

            # Check 2: Location header in the captured HTTP response points externally
            location = _location_header(pair)
            if _location_points_to_canary(pair, ip.url):
                finding = await self.record_finding(
                    url=ip.url,
                    field_name=field_name,
                    payload=payload,
                    evidence=(
                        f"Open redirect via Location header: '{location}'"
                    ),
                    pair=pair,
                    severity="medium",
                    confidence="likely",
                    injection_point=ip,
                )
                findings.append(finding)
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
        name = field.get("name", "unknown")
        ip = (
            InjectionPoint.for_url_param(url, name)
            if is_url_param
            else InjectionPoint.for_form(url, name, form_index)
        )
        return await self.scan_injection_point(ip, field)

    async def verify_finding(self, finding: Finding) -> bool | None:
        is_url_param = finding.field_name in parse_qs(
            urlparse(finding.url).query, keep_blank_values=True
        )
        if hasattr(finding, "injection_location"):
            ip = self._verify_injection_point(finding, is_url_param)
            if ip is None:
                return None
        else:
            # provenance 属性を持たない旧 Finding 互換。
            ip = (
                InjectionPoint.for_url_param(finding.url, finding.field_name)
                if is_url_param
                else InjectionPoint.for_form(finding.url, finding.field_name, 0)
            )
        await self.log_payload_test(
            finding.field_name, finding.payload, "open_redirect_verify", finding.url
        )
        _source, pair = await self._apply_ip(ip, finding.payload)
        try:
            current_url = self.browser.page.url
        except Exception:
            current_url = ""
        return _is_external_redirect(pair, current_url, finding.url)

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
            self._record_scan_note(
                f"transport_error:{self.CHECK_TYPE}:{type(exc).__name__}"
            )
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] open_redirect: _apply_payload failed on {field_name} @ {url}: {exc}"
                )
            return "", {}
