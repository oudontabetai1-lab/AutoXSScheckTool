"""
SSRF (Server-Side Request Forgery) Scanner
Detects vulnerabilities where user-supplied URLs are fetched server-side.

Detection methods:
1. Cloud metadata endpoint content in response (AWS / GCP / Azure)
2. Local file disclosure via file:// scheme
3. Internal service response signatures (localhost)

Only tests fields whose names suggest they hold URLs or server-side paths.
"""
import asyncio
import re
from typing import TYPE_CHECKING

from wscan.injection_point import InjectionPoint

from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    PayloadShape, Prerequisite, ScannerContract, StateChangeClass, TransportKind,
    ValueKind,
)

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# Parameter name fragments that suggest server-side URL/path fetching
SSRF_PARAM_NAMES = {
    "url", "link", "href", "src", "image", "img", "avatar", "photo",
    "file", "path", "dir", "folder", "include", "template",
    "cmd", "command", "exec", "ping", "host", "server", "ip",
    "endpoint", "api", "service", "webhook", "callback", "fetch",
    "load", "target", "proxy", "uri", "resource", "import", "export",
    "destination", "redirect", "location", "action", "next",
}

# (label, payload, detection_pattern)
_SSRF_PROBES: list[tuple[str, str, re.Pattern]] = [
    (
        "AWS metadata (IMDSv1)",
        "http://169.254.169.254/latest/meta-data/",
        re.compile(r"ami-id|instance-id|instance-type|placement|local-ipv4|public-hostname", re.I),
    ),
    (
        "GCP metadata",
        "http://metadata.google.internal/computeMetadata/v1/",
        re.compile(r"computeMetadata|project.*id|serviceAccount|zone|instance", re.I),
    ),
    (
        "Azure IMDS",
        "http://169.254.169.254/metadata/instance",
        re.compile(r"subscriptionId|resourceGroupName|vmId|location.*eastus", re.I),
    ),
    (
        "Localhost HTTP",
        "http://127.0.0.1/",
        re.compile(
            r"<html[\s>]|Server\s*:|X-Powered-By\s*:|Apache|nginx|Index of /",
            re.I,
        ),
    ),
    (
        "Localhost (name)",
        "http://localhost/",
        re.compile(r"<html[\s>]|Server\s*:|X-Powered-By\s*:", re.I),
    ),
    (
        "File read (/etc/passwd)",
        "file:///etc/passwd",
        re.compile(r"root:.*:/bin/|daemon:.*:|nobody:.*:", re.I),
    ),
    (
        "IPv6 loopback",
        "http://[::1]/",
        re.compile(r"<html[\s>]|Server\s*:", re.I),
    ),
]


class SSRFScanner(BaseScanner):
    CHECK_TYPE = "ssrf"
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
                carrier=Carrier.JSON, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.HTTPX}),
                payload_shapes=frozenset({PayloadShape.SCALAR}),
            ),
            CarrierCapability(
                carrier=Carrier.XML, state=CapabilityState.PLANNED,
                reason="carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.MULTIPART, state=CapabilityState.PLANNED,
                reason="carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.HEADER, state=CapabilityState.PLANNED,
                reason="carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.COOKIE, state=CapabilityState.PLANNED,
                reason="carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.PATH, state=CapabilityState.PLANNED,
                reason="carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.GRAPHQL, state=CapabilityState.PLANNED,
                reason="carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.WEBSOCKET, state=CapabilityState.PLANNED,
                reason="carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
        ),
        cost=CostClass.HIGH,
    )

    SEVERITY = "critical"
    SUPPORTS_JSON_BODY = True

    @staticmethod
    def _strip_payload_echo(source: str, payload: str) -> str:
        """ペイロード(プローブURL)の反射分を応答から取り除く。

        プローブURL自体に検出マーカー語が含まれる場合（例: GCP の
        ``…/computeMetadata/…`` や Azure の ``…/metadata/instance``）、入力を
        そのまま画面に反射するだけの無害なページ（検索結果・プロフィール等）でも
        パターンに一致してしまい誤検知になる。SSRF の確証は「取得された内部
        コンテンツ」がマーカーを含むことなので、反射されたペイロードを除去した
        うえで判定する。生・URLエンコード両方の表記を除去する。
        """
        from urllib.parse import quote

        variants = {
            payload,
            quote(payload, safe=""),
            quote(payload, safe="/:"),
            quote(payload, safe=":/?#[]@!$&'()*+,;="),
        }
        cleaned = source
        for variant in variants:
            if variant:
                cleaned = cleaned.replace(variant, " ")
        return cleaned

    def _confirmed_match(self, source: str, payload: str, pattern):
        """反射分を除いてもパターンが残る場合のみ確証マッチを返す。"""
        if not source:
            return None
        match = pattern.search(source)
        if not match:
            return None
        # マーカーが反射されたペイロードに由来するだけなら確証しない
        if not pattern.search(self._strip_payload_echo(source, payload)):
            return None
        return match

    def _is_ssrf_param(self, field_name: str) -> bool:
        """Return True if the field name suggests a server-side URL/path input."""
        name = field_name.lower().replace("-", "_").replace(" ", "_")
        return any(token in name for token in SSRF_PARAM_NAMES)

    async def scan_injection_point(
        self,
        ip: InjectionPoint,
        field: dict,
    ) -> list[Finding]:
        field_name = field.get("name", "unknown")

        # Only test fields that plausibly accept URLs or server-side paths
        if not (ip.location == "url_param" or self._is_ssrf_param(field_name)):
            return []

        findings: list[Finding] = []

        if self.monitor:
            await self.monitor.emit_status(
                f"SSRF testing: {field_name} on {ip.url}"
            )

        # Capture a clean baseline to avoid false-positives from pre-existing content
        # baseline もフィールド投入なので監査ログに残す（log_payload_test 一元化の不変条件）。
        await self.log_payload_test(
            field_name,
            "http://wscan-baseline-test.invalid/",
            "ssrf_baseline",
            ip.url,
        )
        baseline_source, _ = await self._apply_ip(
            ip, "http://wscan-baseline-test.invalid/"
        )

        for label, payload, pattern in _SSRF_PROBES:
            await self.log_payload_test(field_name, payload, "ssrf", ip.url)

            source, pair = await self._apply_ip(ip, payload)
            await asyncio.sleep(0.3 * self.sleep_factor)

            if not source:
                continue

            # Skip if the pattern already appears in baseline (pre-existing content)
            if baseline_source and pattern.search(baseline_source):
                continue

            # 反射されたプローブURLに由来するだけのマッチは確証しない
            match = self._confirmed_match(source, payload, pattern)
            if match:
                finding = await self.record_finding(
                    url=ip.url,
                    field_name=field_name,
                    payload=payload,
                    evidence=(
                        f"SSRF confirmed ({label}): server response contains "
                        f"internal content marker '{match.group(0)[:100]}'"
                    ),
                    pair=pair,
                    severity="critical",
                    confidence="confirmed",
                    evidence_type="ssrf_internal_marker",
                    evidence_details={
                        "probe_label": label,
                        "matched_marker": match.group(0)[:100],
                    },
                    injection_point=ip,
                )
                findings.append(finding)
                break  # one confirmed finding per field is sufficient

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
        probe = next(
            (
                (label, pattern)
                for label, payload, pattern in _SSRF_PROBES
                if payload == finding.payload
            ),
            None,
        )
        if not probe:
            return None
        _label, pattern = probe

        from urllib.parse import parse_qs, urlparse

        is_url_param = finding.field_name in parse_qs(
            urlparse(finding.url).query, keep_blank_values=True
        )
        ip = self._verify_injection_point(finding, is_url_param)
        if ip is None:
            return None
        try:
            # verify 時の再投入（baseline + payload）も監査ログに残す。
            await self.log_payload_test(
                finding.field_name, "http://wscan-baseline-test.invalid/",
                "ssrf_verify_baseline", finding.url,
            )
            baseline_source, _ = await self._apply_ip(
                ip, "http://wscan-baseline-test.invalid/"
            )
            await self.log_payload_test(
                finding.field_name, finding.payload, "ssrf_verify", finding.url
            )
            probe_source, _ = await self._apply_ip(ip, finding.payload)
        except Exception:
            return None

        if baseline_source and pattern.search(baseline_source):
            return False
        return self._confirmed_match(probe_source, finding.payload, pattern) is not None

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
                    f"[warn] ssrf: _apply_payload failed on {field_name} @ {url}: {exc}"
                )
            return "", {}
