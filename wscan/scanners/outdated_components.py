"""EOL（サポート終了）コンポーネント検出スキャナ。

サーバが開示する技術バナー（``Server`` / ``X-Powered-By`` / ``X-AspNet-Version`` /
``X-Generator``）から製品名+バージョンを抽出し、無料の endoflife.date API へ照会して
**サポート終了（EOL）の製品**を Finding 化する（IPA: 既知の脆弱性を持つコンポーネントの使用）。

方針:
- 検出（ローカル）は既存の ``component_intel.parse_components_from_headers`` を再利用し、
  判定（EOL）は endoflife.date に委譲する（全ローカル実装しない）。
- **opt-in**（``features.component_intel``＝既定 off）。engine が ``self.component_intel`` 設定を
  持たない/enabled でない場合は何もしない（スキャンのネット非依存原則を壊さない）。
- **graceful**：API 障害・照会不能は Finding を出さない（偽検出を作らない・確実性重視）。
- 外部へ送るのは製品 slug のみ（target URL・ヘッダ値全体は送らない）。
"""
from typing import TYPE_CHECKING

from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    ScannerContract, StateChangeClass,
)

from .. import component_intel
from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


_UNSUPPORTED = tuple(
    CarrierCapability(
        carrier=c, state=CapabilityState.UNSUPPORTED,
        reason="レスポンスバナー解析でありパラメータ注入をしない",
    )
    for c in (
        Carrier.QUERY, Carrier.FORM, Carrier.JSON, Carrier.XML, Carrier.MULTIPART,
        Carrier.HEADER, Carrier.COOKIE, Carrier.PATH, Carrier.GRAPHQL, Carrier.WEBSOCKET,
    )
)


class OutdatedComponentScanner(BaseScanner):
    """技術バナー→endoflife.date で EOL コンポーネントを検出する（page 観測系・opt-in）。"""

    HAS_PAGE_LEVEL = True
    CHECK_TYPE = "outdated_components"
    CONTRACT = ScannerContract(
        execution_kinds=frozenset({ExecutionKind.PAGE_ANALYSIS}),
        capabilities=_UNSUPPORTED,
        state_change=StateChangeClass.READ_ONLY,
        cost=CostClass.LOW,
    )

    SEVERITY = "medium"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._checked_urls: set[str] = set()

    async def scan_field(
        self, url: str, form_index: int, field: dict, is_url_param: bool = False,
    ) -> list[Finding]:
        return []

    def _config(self) -> dict:
        """engine から component_intel 設定を取得（未設定/無効なら空 dict）。"""
        cfg = getattr(self.engine, "component_intel", None)
        if isinstance(cfg, dict) and cfg.get("enabled"):
            return cfg
        return {}

    async def scan_page(self, url: str) -> list[Finding]:
        cfg = self._config()
        if not cfg:
            return []  # opt-in 無効時は何もしない（ネット非依存を維持）
        if url in self._checked_urls:
            return []
        self._checked_urls.add(url)

        if self.monitor:
            await self.monitor.emit_status(f"Component EOL check on {url}")

        pair = await self._response_pair(url)
        response = pair.get("response") or {}
        headers = {k.lower(): v for k, v in (response.get("headers") or {}).items()}
        components = component_intel.parse_components_from_headers(headers)
        if not components:
            return []

        base_url = cfg.get("eol_base_url") or component_intel.DEFAULT_EOL_BASE_URL
        timeout = float(cfg.get("timeout") or component_intel.DEFAULT_TIMEOUT)

        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for comp in components:
            key = (comp.product, comp.version)
            if key in seen:
                continue
            seen.add(key)
            try:
                result = await component_intel.check_component_eol(
                    comp, base_url=base_url, timeout=timeout,
                )
            except Exception as exc:  # 念のため（graceful）
                self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:{type(exc).__name__}")
                continue
            if not result or not result.get("is_eol"):
                continue  # サポート中・判定不能は報告しない
            eol_val = result.get("eol")
            latest = result.get("latest") or ""
            eol_desc = "サポート終了済み" if eol_val is True else f"{eol_val} にサポート終了"
            evidence = (
                f"{comp.product} {comp.version}（{comp.source} ヘッダで開示）は "
                f"{eol_desc}（endoflife.date: cycle {result.get('cycle')}"
                + (f", 最新 {latest}" if latest else "")
                + "）。EOL 版はセキュリティ更新が提供されず既知の脆弱性が残存します。"
            )
            finding = await self.record_finding(
                url=url,
                field_name=f"(Component: {comp.product})",
                payload="(no payload — banner/EOL lookup)",
                evidence=evidence,
                pair=pair,
                severity="medium",
                confidence="likely",
                evidence_type="eol_component",
                evidence_details={
                    "product": comp.product,
                    "version": comp.version,
                    "source": comp.source,
                    "cycle": result.get("cycle"),
                    "eol": eol_val,
                    "latest": latest,
                    "reference": f"{base_url.rstrip('/')}/{result.get('slug')}",
                },
                reproduction_steps=[
                    f"Request {url}",
                    f"Inspect the '{comp.source}' response header: {comp.product}/{comp.version}",
                    f"Confirm via endoflife.date that {comp.product} {result.get('cycle')} is end-of-life.",
                    f"Upgrade to a supported release (latest: {latest or 'see endoflife.date'}).",
                ],
            )
            findings.append(finding)

        return findings
