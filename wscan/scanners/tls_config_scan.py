"""TLS 設定不備スキャナ（OSS の sslyze を活用・opt-in）。

弱いプロトコル（SSLv2/SSLv3/TLS 1.0/1.1）の受理、Heartbleed / CCS Injection / ROBOT を検出する。
sslyze は optional 依存で未導入なら inert。https オリジンのみ対象。判定は ``wscan.tls_scan`` の
純粋関数へ委譲し、通信/スキャン失敗は graceful（Finding を作らない）。
"""
import asyncio
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from wscan import tls_scan
from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    ScannerContract, StateChangeClass,
)

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


_UNSUPPORTED = tuple(
    CarrierCapability(
        carrier=c, state=CapabilityState.UNSUPPORTED,
        reason="TLS 通信路の設定を観測しパラメータ注入をしない",
    )
    for c in (
        Carrier.QUERY, Carrier.FORM, Carrier.JSON, Carrier.XML, Carrier.MULTIPART,
        Carrier.HEADER, Carrier.COOKIE, Carrier.PATH, Carrier.GRAPHQL, Carrier.WEBSOCKET,
    )
)


class TlsConfigScanner(BaseScanner):
    """TLS プロトコル/既知脆弱性の設定不備を sslyze で検査する（origin 単位・opt-in・read-only）。"""

    HAS_PAGE_LEVEL = True
    CHECK_TYPE = "tls_scan"
    CONTRACT = ScannerContract(
        execution_kinds=frozenset({ExecutionKind.PAGE_ANALYSIS}),
        capabilities=_UNSUPPORTED,
        state_change=StateChangeClass.READ_ONLY,
        cost=CostClass.MEDIUM,
    )

    SEVERITY = "medium"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._checked_origins: set[str] = set()

    async def scan_field(
        self, url: str, form_index: int, field: dict, is_url_param: bool = False,
    ) -> list[Finding]:
        return []

    async def scan_page(self, url: str) -> list[Finding]:
        if not getattr(self.engine, "tls_scan_enabled", False):
            return []
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return []  # TLS 検査は https のみ
        host = parsed.hostname or ""
        port = parsed.port or 443
        origin = f"https://{host}:{port}"
        if not host or origin in self._checked_origins:
            return []
        self._checked_origins.add(origin)

        if not tls_scan.sslyze_available():
            self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:sslyze_unavailable")
            return []

        if self.monitor:
            await self.monitor.emit_status(f"TLS config scan on {origin}")

        timeout = float(getattr(self.engine, "timeout", 20) or 20)
        try:
            result = await asyncio.to_thread(tls_scan.run_sslyze_scan, host, port, timeout)
        except Exception:
            self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:scan")
            return []
        if result is None:
            self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:no_result")
            return []
        # sslyze は接続不能でも result を返す。到達失敗を「issue 無し」と取り違えない。
        if not tls_scan.server_scan_reachable(result):
            self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:unreachable")
            return []

        issues = tls_scan.extract_tls_issues(result)
        # 到達はしたが全コマンドが未完（部分 handshake 失敗）なら、黙った偽陰性として記録する。
        if not issues and not tls_scan.scan_has_completed_attempts(result):
            self._record_scan_note(f"scan_incomplete:{self.CHECK_TYPE}:no_completed_attempts")
        findings: list[Finding] = []
        pair = {"request": {"url": origin, "method": "TLS"},
                "response": {"url": origin, "headers": {}, "body": ""}}
        for issue in issues:
            findings.append(await self.record_finding(
                url=origin,
                field_name=f"(TLS: {issue['label']})",
                payload="(no payload — TLS handshake probe)",
                evidence=f"TLS 設定不備: {issue['label']} — {issue['detail']}",
                pair=pair,
                severity=issue.get("severity", "medium"),
                confidence="confirmed",
                evidence_type=f"tls_{issue['kind']}",
                evidence_details={"label": issue["label"], "kind": issue["kind"]},
                reproduction_steps=[
                    f"Run a TLS scan against {host}:{port} (e.g. sslyze).",
                    f"Confirm: {issue['detail']}",
                    "Disable weak protocols/ciphers or patch the affected component.",
                ],
            ))
        return findings
