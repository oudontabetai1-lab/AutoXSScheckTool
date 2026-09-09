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
        body = response.get("body", "") or ""

        eol_base = cfg.get("eol_base_url") or component_intel.DEFAULT_EOL_BASE_URL
        osv_base = cfg.get("osv_base_url") or component_intel.DEFAULT_OSV_BASE_URL
        timeout = float(cfg.get("timeout") or component_intel.DEFAULT_TIMEOUT)

        findings: list[Finding] = []
        # ① 技術バナー → endoflife.date で EOL 判定
        findings.extend(await self._scan_eol(url, pair, headers, eol_base, timeout))
        # ② 外部 JS ライブラリ → OSV.dev で既知脆弱性照会
        findings.extend(await self._scan_osv(url, pair, body, osv_base, timeout))
        return findings

    async def _scan_eol(self, url, pair, headers, base_url, timeout) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for comp in component_intel.parse_components_from_headers(headers):
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
            findings.append(await self.record_finding(
                url=url,
                field_name=f"(Component: {comp.product})",
                payload="(no payload — banner/EOL lookup)",
                evidence=evidence,
                pair=pair,
                severity="medium",
                confidence="likely",
                evidence_type="eol_component",
                evidence_details={
                    "product": comp.product, "version": comp.version, "source": comp.source,
                    "cycle": result.get("cycle"), "eol": eol_val, "latest": latest,
                    "reference": f"{base_url.rstrip('/')}/{result.get('slug')}",
                },
                reproduction_steps=[
                    f"Request {url}",
                    f"Inspect the '{comp.source}' response header: {comp.product}/{comp.version}",
                    f"Confirm via endoflife.date that {comp.product} {result.get('cycle')} is end-of-life.",
                    f"Upgrade to a supported release (latest: {latest or 'see endoflife.date'}).",
                ],
            ))
        return findings

    async def _scan_osv(self, url, pair, body, base_url, timeout) -> list[Finding]:
        libs = component_intel.parse_js_libraries(body, url)
        if not libs:
            return []
        # 照会結果を engine 単位でキャッシュ（同一 (ecosystem,name,version) を複数ページで再照会しない）。
        cache = getattr(self.engine, "_osv_cache", None)
        if cache is None:
            cache = {}
            try:
                self.engine._osv_cache = cache
            except Exception:
                cache = None

        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for lib in libs:
            key = (lib.name, lib.version)
            if key in seen:
                continue
            seen.add(key)
            ck = (lib.ecosystem, lib.name, lib.version)
            if cache is not None and ck in cache:
                vulns = cache[ck]
            else:
                try:
                    vulns = await component_intel.lookup_osv(
                        lib.ecosystem, lib.name, lib.version, base_url=base_url, timeout=timeout,
                    )
                except Exception as exc:
                    self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:osv:{type(exc).__name__}")
                    continue
                if cache is not None:
                    cache[ck] = vulns
            if not vulns:
                continue  # 脆弱性なし・照会不能(None)は報告しない
            info = component_intel.summarize_osv_vulns(vulns)
            ids = info["ids"] or []
            cves = info["cves"] or []
            sev = (info["max_severity"] or "").lower()
            severity = {"critical": "critical", "high": "high", "moderate": "medium",
                        "medium": "medium", "low": "low"}.get(sev, "medium")
            id_disp = ", ".join((cves or ids)[:5])
            evidence = (
                f"外部 JS ライブラリ {lib.name} {lib.version} に既知の脆弱性があります"
                f"（OSV: {len(ids)} 件{('・' + id_disp) if id_disp else ''}"
                + (f"・{info['summary'][:80]}" if info.get("summary") else "")
                + "）。修正版へ更新してください。"
            )
            findings.append(await self.record_finding(
                url=url,
                field_name=f"(Library: {lib.name})",
                payload="(no payload — JS library / OSV lookup)",
                evidence=evidence,
                pair=pair,
                severity=severity,
                confidence="likely",
                evidence_type="vulnerable_library",
                evidence_details={
                    "library": lib.name, "version": lib.version, "ecosystem": lib.ecosystem,
                    "src": lib.url, "osv_ids": ids, "cves": cves,
                    "max_severity": info["max_severity"],
                },
                reproduction_steps=[
                    f"Load {url} and note the external script: {lib.url}",
                    f"Identify {lib.name} version {lib.version}.",
                    f"Check OSV.dev / GHSA: {id_disp or 'known advisories'} affect this version.",
                    f"Upgrade {lib.name} to a patched release.",
                ],
            ))
        return findings
