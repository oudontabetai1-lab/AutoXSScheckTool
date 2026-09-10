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
from .base import BaseScanner, Finding, PageDocumentUnavailable

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


def _origin_of(url: str) -> str:
    """URL の正規化 origin（engine._cms_origin と同じ表現）。壊れた入力は ""。"""
    try:
        from wscan.attack_planner import canonical_origin
        return canonical_origin(url)
    except Exception:
        return ""


# severity に整合する代表 CVSS（score, vector）。OSV の深刻度は issue ごとに
# critical〜low まで動くため、check_type 一律の _CVSS_TABLE 値ではなくこれを per-finding で渡す
# （high/critical の脆弱ライブラリを medium 4.8 で出さない・Codex #155）。
_SEV_CVSS: dict[str, tuple[float, str]] = {
    "critical": (9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "high":     (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "medium":   (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "low":      (3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
}


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
        # URL しか無い経路（body は _response_pair の 50KB 打ち切り本文）。
        return await self._run(url)

    async def scan_page_context(self, page) -> list[Finding]:
        # CrawledPage 経由。full HTML と捕捉済み external_scripts（全件）を使い、
        # 大きなページで末尾の script を取りこぼさない（Codex #155）。
        full_html = getattr(page, "html", None)
        scripts = getattr(page, "external_scripts", None) or {}
        return await self._run(getattr(page, "url", ""), full_html=full_html,
                               extra_script_urls=list(scripts.keys()))

    async def _run(self, url: str, full_html=None, extra_script_urls=()) -> list[Finding]:
        cfg = self._config()
        if not cfg:
            return []  # opt-in 無効時は何もしない（ネット非依存を維持）
        if not url or url in self._checked_urls:
            return []

        if self.monitor:
            await self.monitor.emit_status(f"Component EOL check on {url}")

        pair = await self._response_pair(url)
        # 空 pair（408/429/5xx 等の transient）を「正常な空レスポンス」と取り違えない。
        # [] を返すと page-level ループが tested 完了として checkpoint を埋め、pair もキャッシュ済みで
        # この run 内の再試行もできず resume でも skip される。他の document 観測系と同様に
        # PageDocumentUnavailable を投げ、engine に error（resume 再試行）扱いさせる（Codex #155）。
        if not pair:
            self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:page_unavailable")
            raise PageDocumentUnavailable(
                f"{self.CHECK_TYPE}: 対象ページを取得できませんでした: {url}"
            )
        self._checked_urls.add(url)
        response = pair.get("response") or {}
        headers = {k.lower(): v for k, v in (response.get("headers") or {}).items()}
        # JS ライブラリ抽出は full HTML を優先（50KB 打ち切り本文だと末尾 script を取りこぼす）。
        body = full_html if full_html is not None else (response.get("body", "") or "")

        eol_base = cfg.get("eol_base_url") or component_intel.DEFAULT_EOL_BASE_URL
        osv_base = cfg.get("osv_base_url") or component_intel.DEFAULT_OSV_BASE_URL
        timeout = float(cfg.get("timeout") or component_intel.DEFAULT_TIMEOUT)

        # EOL 照会対象＝技術バナー（ヘッダ）＋クロール中に検出した CMS（あれば）。
        components = list(component_intel.parse_components_from_headers(headers))
        # CMS は検出元 origin と現在 URL の origin が一致するときだけ付与する
        # （origin A で検出した CMS を origin B の URL に付けて誤検知/重複しない）。
        cms = getattr(self.engine, "detected_cms", None)
        cms_origin = getattr(self.engine, "_cms_origin", "") or ""
        if (cms is not None and getattr(cms, "is_known", False) and getattr(cms, "version", "")
                and cms_origin and cms_origin == _origin_of(url)):
            components.append(component_intel.Component(
                product=cms.name, version=cms.version, source="cms",
            ))

        # 外部照会は record_finding を**末尾まで遅延**する。各 _scan_* は finding の spec(kwargs)を
        # 集め、transient 失敗は invocation ローカルな state に記録する（self に持たせると
        # --concurrency>1 で別 page と混信する・Codex #155）。transient があれば record 前に raise
        # するので、dedup 汚染も配信漏れも起きず、resume で安全に再試行できる（Codex #155）。
        state = {"transient": False}
        specs: list[dict] = []
        # ① 技術バナー/CMS → endoflife.date で EOL 判定
        specs += await self._scan_eol(url, pair, components, eol_base, timeout, state)
        # ② 外部 JS ライブラリ → OSV.dev で既知脆弱性照会（full HTML＋捕捉済み script URL）
        specs += await self._scan_osv(url, pair, body, osv_base, timeout, state,
                                      extra_script_urls=extra_script_urls)
        # ③ NVD で CVE 照会（限定オプション・nvd_enabled 時のみ・参考集約）
        if cfg.get("nvd_enabled"):
            nvd_base = cfg.get("nvd_base_url") or component_intel.DEFAULT_NVD_BASE_URL
            specs += await self._scan_nvd(url, pair, components, nvd_base, timeout, state)

        # いずれかの照会が一時失敗していたら、**まだ record していない**ので page を tested 完了に
        # せず resume 対象にする（dedup 汚染・webhook 未発火・配信漏れを避ける）。
        if state["transient"]:
            self._checked_urls.discard(url)
            raise PageDocumentUnavailable(
                f"{self.CHECK_TYPE}: 外部照会が一時失敗しました（resume で再試行）: {url}"
            )
        # 全照会が確定したので、ここで初めて record_finding する。
        findings: list[Finding] = []
        for spec in specs:
            f = await self.record_finding(**spec)
            if f is not None:
                findings.append(f)
        return findings

    async def _scan_nvd(self, url, pair, components, base_url, timeout, state) -> list[dict]:
        import os
        api_key = os.environ.get("WSCAN_NVD_API_KEY", "") or ""
        cache = getattr(self.engine, "_nvd_cache", None)
        if cache is None:
            cache = {}
            try:
                self.engine._nvd_cache = cache
            except Exception:
                cache = None

        specs: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for comp in components:
            if not component_intel.nvd_product_cpe(comp.product):
                continue  # CPE 対応製品のみ（保守側）
            key = (comp.product, comp.version)
            if key in seen:
                continue
            seen.add(key)
            if cache is not None and key in cache:
                info = cache[key]
            else:
                try:
                    info = await component_intel.lookup_nvd(
                        comp.product, comp.version, base_url=base_url,
                        api_key=api_key, timeout=timeout,
                    )
                except component_intel.ComponentIntelUnavailable as exc:
                    self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:nvd:{type(exc).__name__}")
                    state["transient"] = True
                    continue
                except Exception as exc:
                    self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:nvd:{type(exc).__name__}")
                    continue
                if cache is not None:
                    cache[key] = info
            if not info or not info.get("total"):
                continue  # 照会不能・0 件は報告しない
            ids = info.get("cve_ids") or []
            sev = (info.get("max_severity") or "").lower()
            id_disp = ", ".join(ids[:5])
            # max_severity は取得した先頭サンプル（resultsPerPage 件）での最大であり、total 全件の
            # 真の最大とは限らない（後続ページに上位 severity があり得る）。その旨を明示する（Codex #155）。
            sampled = info.get("total", 0) > len(ids)
            sev_phrase = ""
            if info.get("max_severity"):
                sev_phrase = (f"（取得{len(ids)}件中の最大深刻度 {info['max_severity']}）" if sampled
                              else f"（最大深刻度 {info['max_severity']}）")
            evidence = (
                f"参考: NVD に {comp.product} {comp.version} に該当し得る CVE が {info['total']} 件"
                + sev_phrase
                + (f"・例: {id_disp}" if id_disp else "")
                + "。CPE 一致は範囲が広く誤差を含むため、実際の影響は各 CVE を確認してください。"
            )
            specs.append(dict(
                url=url,
                field_name=f"(CVE: {comp.product}@{comp.version})",
                payload="(no payload — NVD CPE lookup)",
                evidence=evidence,
                pair=pair,
                severity="low",  # 参考情報（CPE ノイズを考慮して低め）
                confidence="tentative",
                evidence_type="known_cve_advisory",
                cvss_score=_SEV_CVSS["low"][0],
                cvss_vector=_SEV_CVSS["low"][1],
                evidence_details={
                    "product": comp.product, "version": comp.version, "source": comp.source,
                    "cve_count": info["total"], "cve_ids": ids,
                    "max_severity": info.get("max_severity", ""),
                    "reference": f"{base_url.rstrip('/')}/vuln/search",
                },
                reproduction_steps=[
                    f"Detected {comp.product} {comp.version} ({comp.source}).",
                    f"Query NVD by CPE ({component_intel.nvd_product_cpe(comp.product)}:{comp.version}).",
                    "Review the matched CVEs to confirm which apply to this exact build.",
                ],
            ))
        return specs

    async def _scan_eol(self, url, pair, components, base_url, timeout, state) -> list[dict]:
        # 同一 (product,version) を複数ページで再照会しないよう engine 単位でキャッシュ。
        # 失敗（ComponentIntelUnavailable）はキャッシュせず（note のみ）、確定結果だけ載せる。
        cache = getattr(self.engine, "_eol_cache", None)
        if cache is None:
            cache = {}
            try:
                self.engine._eol_cache = cache
            except Exception:
                cache = None
        specs: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for comp in components:
            key = (comp.product, comp.version)
            if key in seen:
                continue
            seen.add(key)
            if cache is not None and key in cache:
                result = cache[key]
            else:
                try:
                    result = await component_intel.check_component_eol(
                        comp, base_url=base_url, timeout=timeout,
                    )
                except component_intel.ComponentIntelUnavailable as exc:
                    # 一時失敗: page を再試行可能に残す（キャッシュしない）。
                    self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:eol:{type(exc).__name__}")
                    state["transient"] = True
                    continue
                except Exception as exc:  # その他は graceful（非キャッシュ・継続）
                    self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:{type(exc).__name__}")
                    continue
                if cache is not None:
                    cache[key] = result
            if not result or not result.get("is_eol"):
                continue  # サポート中・判定不能は報告しない
            eol_val = result.get("eol")
            latest = result.get("latest") or ""
            eol_desc = "サポート終了済み" if eol_val is True else f"{eol_val} にサポート終了"
            origin = "CMS 検出" if comp.source == "cms" else f"{comp.source} ヘッダで開示"
            evidence = (
                f"{comp.product} {comp.version}（{origin}）は "
                f"{eol_desc}（endoflife.date: cycle {result.get('cycle')}"
                + (f", 最新 {latest}" if latest else "")
                + "）。EOL 版はセキュリティ更新が提供されず既知の脆弱性が残存します。"
            )
            specs.append(dict(
                url=url,
                field_name=f"(Component: {comp.product}@{comp.version})",
                payload="(no payload — banner/EOL lookup)",
                evidence=evidence,
                pair=pair,
                severity="medium",
                confidence="likely",
                evidence_type="eol_component",
                cvss_score=_SEV_CVSS["medium"][0],
                cvss_vector=_SEV_CVSS["medium"][1],
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
        return specs

    async def _scan_osv(self, url, pair, body, base_url, timeout, state, extra_script_urls=()) -> list[dict]:
        # full HTML から抽出した lib に、クロールが捕捉した external_scripts URL 由来の lib を足す
        # （HTML の 50KB 打ち切りや inline 記述漏れで取りこぼさない）。(name,version) で重複排除。
        libs = list(component_intel.parse_js_libraries(body, url))
        if extra_script_urls:
            seen = {(lib.name, lib.version) for lib in libs}
            for lib in component_intel.parse_js_libraries_from_urls(extra_script_urls):
                if (lib.name, lib.version) not in seen:
                    seen.add((lib.name, lib.version))
                    libs.append(lib)
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

        specs: list[dict] = []
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
                except component_intel.ComponentIntelUnavailable as exc:
                    self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:osv:{type(exc).__name__}")
                    state["transient"] = True
                    continue
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
            # CDN の構造化 URL 由来は likely、ファイル名推測（任意 origin の name-x.y.z.js）は
            # 名称/版が内容と一致しない可能性があるため tentative に落とす（過検知抑制）。
            is_guess = getattr(lib, "reliability", "cdn") == "filename"
            confidence = "tentative" if is_guess else "likely"
            guess_note = (
                "（ファイル名からの推測のため、実際のライブラリ/版と異なる可能性があります）"
                if is_guess else ""
            )
            evidence = (
                f"外部 JS ライブラリ {lib.name} {lib.version} に既知の脆弱性があります"
                f"（OSV: {len(ids)} 件{('・' + id_disp) if id_disp else ''}"
                + (f"・{info['summary'][:80]}" if info.get("summary") else "")
                + "）。修正版へ更新してください。" + guess_note
            )
            cvss_score, cvss_vector = _SEV_CVSS.get(severity, _SEV_CVSS["medium"])
            specs.append(dict(
                url=url,
                # 同一ページが同一パッケージの複数版を読む場合、版を identity に含めないと
                # record_finding の dedup(field_name+check+evidence_type+url)で 2 つ目が消える・Codex #155。
                field_name=f"(Library: {lib.name}@{lib.version})",
                payload="(no payload — JS library / OSV lookup)",
                evidence=evidence,
                pair=pair,
                severity=severity,
                confidence=confidence,
                evidence_type="vulnerable_library",
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
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
        return specs
