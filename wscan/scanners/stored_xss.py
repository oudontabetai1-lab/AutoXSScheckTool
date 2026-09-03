"""
Stored XSS Scanner (V-1)
Detects second-order / persistent XSS by injecting unique markers and
checking ALL subsequently visited pages for their appearance.

Flow:
  scan_field  → submits a uniquely-tagged payload into the field and records
                the marker in the shared _injected set.
  scan_page   → after each normal page load, inspects the HTML for any
                previously injected marker; if found on a DIFFERENT URL
                from the injection origin, it is a Stored XSS finding.
"""
import asyncio
import html as _html
import re
import uuid
from typing import TYPE_CHECKING

from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    PayloadShape, Prerequisite, ScannerContract, StateChangeClass, TransportKind,
    ValueKind,
)

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine

# Innocuous-looking probe prefix that survives most server-side sanitation
_PROBE_PREFIX = "wsxss"


def classify_stored_marker(marker: str, payload: str, source: str) -> dict:
    """格納マーカーが応答内でどう現れているかを純粋に分類する。

    マーカーは英数字のみ（``_html.escape(marker) == marker``）なので、
    「マーカー文字列が出現したか」だけでは実行可能性を判定できない。注入した
    タグ構造（``<script id="marker"``）が **生のまま** 出現しているかどうかで、
    実行可能な格納型XSSか、エンコードされ無害化された格納かを区別する。

    返り値: ``{"found", "in_raw", "in_encoded", "executable"}``。
    HTTP/ブラウザに依存しない判定ロジック（テスト容易性のため分離）。
    """
    if not marker or marker not in source:
        return {"found": False, "in_raw": False, "in_encoded": False, "executable": False}

    # 注入したタグの「生」表現。ブラウザの DOM 直列化は属性をダブルクォートへ
    # 正規化するため、実行された <script> はこの形で再出現する。
    raw_tag = f'<script id="{marker}"'
    encoded_tag = _html.escape(raw_tag)
    in_raw = raw_tag in source
    in_encoded = encoded_tag in source
    return {
        "found": True,
        "in_raw": in_raw,
        # 生タグが無ければ（マーカーは在るが）エンコード/テキスト化された無害な格納。
        "in_encoded": in_encoded or not in_raw,
        "executable": in_raw,
    }


class StoredXSSScanner(BaseScanner):
    """Stored / second-order XSS scanner."""

    HAS_PAGE_LEVEL = True
    CHECK_TYPE = "stored_xss"
    CONTRACT = ScannerContract(
        execution_kinds=frozenset({ExecutionKind.FIELD_INJECTION, ExecutionKind.STORED_OBSERVATION, ExecutionKind.PAGE_ANALYSIS}),
        capabilities=(
            CarrierCapability(
                carrier=Carrier.QUERY, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.PLAYWRIGHT}),
                payload_shapes=frozenset({PayloadShape.SCALAR}),
                browser_required=True,
            ),
            CarrierCapability(
                carrier=Carrier.FORM, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.PLAYWRIGHT}),
                payload_shapes=frozenset({PayloadShape.SCALAR}),
                browser_required=True,
            ),
            CarrierCapability(
                carrier=Carrier.JSON, state=CapabilityState.PLANNED,
                reason="JSON body 検出改修は 0012/0035-D",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.XML, state=CapabilityState.PLANNED,
                reason="stored XSS の carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.MULTIPART, state=CapabilityState.PLANNED,
                reason="stored XSS の carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.HEADER, state=CapabilityState.PLANNED,
                reason="stored XSS の carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.COOKIE, state=CapabilityState.PLANNED,
                reason="stored XSS の carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.PATH, state=CapabilityState.PLANNED,
                reason="stored XSS の carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.GRAPHQL, state=CapabilityState.PLANNED,
                reason="stored XSS の carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.WEBSOCKET, state=CapabilityState.PLANNED,
                reason="stored XSS の carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
        ),
        cost=CostClass.HIGH,
    )

    SEVERITY = "critical"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        # marker → {"url": injection_url, "field": field_name, "payload": payload_str}
        self._injected: dict[str, dict] = {}
        self._detected_markers: set[str] = set()
        # Protects concurrent _detected_markers reads/writes when multiple
        # page-workers invoke scan_page() in parallel.
        self._detect_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Field-level: inject uniquely-tagged payloads
    # ------------------------------------------------------------------

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        """Inject probe payloads that carry a unique marker for later detection."""
        field_name = field.get("name", "unknown")

        if self.monitor:
            await self.monitor.emit_status(
                f"Stored-XSS probe injection: {field_name} on {url}"
            )

        for _ in range(3):  # inject 3 different format probes
            marker = f"{_PROBE_PREFIX}{uuid.uuid4().hex[:8]}"
            # Payloads that survive common HTML-encoding but still carry the marker
            payload = f'<script id="{marker}">/*{marker}*/</script>'
            self._injected[marker] = {
                "url": url,
                "field": field_name,
                "payload": payload,
            }
            await self.log_payload_test(field_name, payload, "stored_xss", url)
            try:
                if is_url_param:
                    await self.browser.test_url_param(url, field_name, payload)
                else:
                    await self.browser.navigate(url)
                    await self.browser.fill_and_submit_form(
                        form_index, field_name, payload
                    )
            except Exception as exc:
                if self.monitor:
                    await self.monitor.emit_status(
                        f"[warn] stored_xss: probe injection failed on {field_name} @ {url}: {exc}"
                    )
            await asyncio.sleep(0.3 * self.sleep_factor)

        return []  # Findings are emitted in scan_page

    # ------------------------------------------------------------------
    # Page-level: check current page for any stored markers
    # ------------------------------------------------------------------

    async def scan_page(self, url: str) -> list[Finding]:
        """After loading a page, look for any previously injected markers."""
        if not self._injected:
            return []

        try:
            current_url = getattr(self.browser.page, "url", "") or ""
            if current_url.split("#")[0].rstrip("/") != url.split("#")[0].rstrip("/"):
                ok = await self.browser.navigate(url)
                if ok is False:
                    return []
                await asyncio.sleep(0.2 * self.sleep_factor)
            source = await self.browser.page.content()
        except Exception:
            return []

        findings = []
        for marker, meta in list(self._injected.items()):
            verdict = classify_stored_marker(marker, meta["payload"], source)
            if not verdict["found"]:
                continue
            in_raw = verdict["in_raw"]
            in_encoded = verdict["in_encoded"]

            # 完全に HTML エスケープされ実行不能になった反射(= 生タグ無し)は、
            # 正しい出力エンコードであって脆弱性ではない。finding にすると誤検知に
            # なるため、実行可能な格納(生 <script> が残る)のみ報告する。
            if not in_raw:
                continue

            # Stored XSS only if the marker appears on a page OTHER than where it was injected
            if url == meta["url"]:
                continue

            # Atomically claim this marker so concurrent workers cannot both
            # record a finding for the same marker.
            async with self._detect_lock:
                if marker in self._detected_markers:
                    continue
                self._detected_markers.add(marker)
            pair = self.current_page_pair(url)

            # Distinguish executable XSS (raw tags) from stored HTML injection (encoded)
            is_executable = in_raw
            severity = "critical" if is_executable else "medium"
            evidence_prefix = "Stored XSS" if is_executable else "Stored HTML injection (encoded)"

            finding = await self.record_finding(
                url=url,
                field_name=meta["field"],
                payload=meta["payload"],
                evidence=(
                    f"{evidence_prefix}: marker '{marker}' injected at {meta['url']} "
                    f"appeared on {url}"
                ),
                pair=pair,
                severity=severity,
                confidence="confirmed" if is_executable else "likely",
                evidence_type="stored_xss_marker" if is_executable else "stored_html_marker",
                evidence_details={
                    "marker": marker,
                    "injection_url": meta["url"],
                    "sink_url": url,
                    "raw_marker_present": in_raw,
                    "encoded_marker_present": in_encoded,
                    "executable": is_executable,
                },
                reproduction_steps=[
                    f"Open {meta['url']}",
                    f"Submit the payload into field '{meta['field']}'.",
                    f"Open {url}",
                    f"Confirm marker '{marker}' is rendered from persistent storage.",
                ],
            )
            findings.append(finding)

        return findings

    async def verify_finding(self, finding: Finding) -> bool | None:
        if finding.evidence_type not in {
            "stored_xss_marker",
            "stored_html_marker",
            "stored_xss_chain_title",
            "stored_html_chain_marker",
        }:
            return None

        details = getattr(finding, "evidence_details", {}) or {}
        source_url = (
            details.get("injection_url")
            or details.get("source_url")
            or finding.url
        )
        sink_url = (
            details.get("sink_url")
            or details.get("trigger_url")
            or finding.url
        )
        field_name = details.get("source_field") or finding.field_name
        marker = self._marker_for_finding(finding)
        if not source_url or not sink_url or not field_name or not marker:
            return None

        try:
            await self._submit_payload(source_url, field_name, finding.payload)
            self.browser.reset_dialog()
            ok = await self.browser.navigate(sink_url)
            if ok is False:
                return None
            await asyncio.sleep(0.5 * self.sleep_factor)
            html = await self.browser.get_page_source()
        except Exception:
            return None

        if self.browser.dialog_fired and marker in self.browser.dialog_message:
            return True

        try:
            title = await self.browser.page.title()
            if marker in (title or ""):
                return True
        except Exception:
            pass

        return self._marker_in_html(marker, html or "")

    async def _submit_payload(self, url: str, field_name: str, payload: str):
        from urllib.parse import parse_qs, urlparse

        is_url_param = field_name in parse_qs(
            urlparse(url).query, keep_blank_values=True
        )
        if is_url_param:
            return await self.browser.test_url_param(url, field_name, payload)

        await self.browser.navigate(url)
        return await self.browser.fill_and_submit_form(0, field_name, payload)

    def _marker_for_finding(self, finding: Finding) -> str:
        details = getattr(finding, "evidence_details", {}) or {}
        marker = details.get("marker") or details.get("probe_uid")
        if marker:
            return str(marker)

        match = re.search(r"(?:wsxss|wscc_|wscanchain_)[0-9a-fA-F]+", finding.payload or "")
        return match.group(0) if match else ""

    def _marker_in_html(self, marker: str, html: str) -> bool:
        candidates = {
            marker,
            _html.escape(marker),
            f"wscc_{marker}",
            f"wscanchain_{marker}",
            f'id="wscc_{marker}"',
        }
        return any(candidate in html for candidate in candidates)
