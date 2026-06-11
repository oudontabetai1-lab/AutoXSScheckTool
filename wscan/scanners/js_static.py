"""
JavaScript 静的危険性スキャナ（DOM XSS の前段階評価）。

ペイロードを投げて実行を確認する ``dom_xss`` の手前で、ページのインライン
JavaScript と読み込まれた外部 ``.js`` を静的に読み、危険な DOM シンクと
ユーザ制御ソースの source → sink フローを洗い出す（``wscan/js_analysis.py``）。

ページ単位の検査（``scan_page``）。注入は行わないため誤検知ゼロを優先し、
- 汚染フロー（source→sink）が辿れたものは ``likely``、
- 単独の危険シンクは ``tentative``、
- ライブラリ（クロスオリジン）由来は汚染フローが辿れた時だけ報告、
という運用で情報過多を抑える。``--checks js_static`` で明示的に有効化する。
"""
from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

from .base import BaseScanner, Finding
from wscan import js_analysis

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


class JsStaticScanner(BaseScanner):
    """インライン/外部 JavaScript の危険パターンを静的に評価する。"""

    CHECK_TYPE = "js_static"
    SEVERITY = "medium"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._checked_urls: set[str] = set()
        self._scanned_scripts: set[str] = set()

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        return []

    async def scan_page(self, url: str) -> list[Finding]:
        if url in self._checked_urls:
            return []
        self._checked_urls.add(url)

        if self.monitor:
            await self.monitor.emit_status(f"JS static audit on {url}")

        page_host = _host_of(url)
        findings: list[Finding] = []

        # 1) ドキュメント HTML を取得（ネットワーク捕捉 → だめなら DOM から）。
        pair = self.current_page_pair(url)
        html = (pair.get("response", {}) or {}).get("body", "") or ""
        if not html:
            try:
                html = await self.browser.page.content()
            except Exception:
                html = ""

        # 2) インライン script を解析（first-party 扱い）。
        for idx, script in enumerate(js_analysis.extract_inline_scripts(html)):
            label = f"(inline script #{idx + 1})"
            findings += await self._record_risks(
                url, label, script, first_party=True, source_url=url
            )

        # 3) 捕捉済みの外部 .js を解析。
        network = getattr(self.browser, "network", None)
        pairs = list(getattr(network, "pairs", []) or [])
        for p in pairs:
            resp = p.get("response", {}) or {}
            js_url = resp.get("url") or (p.get("request", {}) or {}).get("url") or ""
            if not js_url or js_url in self._scanned_scripts:
                continue
            ctype = (resp.get("headers", {}) or {}).get("content-type", "")
            if not js_analysis.is_javascript_response(js_url, ctype):
                continue
            body = resp.get("body", "") or ""
            if not body.strip():
                continue
            self._scanned_scripts.add(js_url)
            first_party = _host_of(js_url) == page_host
            findings += await self._record_risks(
                url, f"({js_url})", body, first_party=first_party, source_url=js_url
            )

        return findings

    async def _record_risks(
        self,
        page_url: str,
        field_label: str,
        source: str,
        *,
        first_party: bool,
        source_url: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for risk in js_analysis.analyze_js(source, origin=source_url):
            # クロスオリジン（ライブラリ等）は汚染フローが辿れた時だけ報告。
            # 単独の危険シンクはライブラリ実装由来の正常コードが多く誤検知源。
            if not first_party and not risk.tainted:
                continue

            confidence = "likely" if risk.tainted else "tentative"
            # record_finding は (check_type,url,field_name,evidence_type) で重複排除
            # するため、1スクリプト内に複数シンクがあると潰れる。sink/line を
            # field_name に含め、別シンクが別 Finding として残るようにする。
            field_id = f"{field_label} [{risk.sink} L{risk.line}]"
            finding = await self.record_finding(
                url=page_url,
                field_name=field_id,
                payload="(no payload — static JS audit)",
                evidence=(
                    f"{risk.evidence} @ {field_label} line {risk.line}: "
                    f"{risk.snippet}"
                ),
                pair=self.current_page_pair(page_url),
                severity=risk.severity,
                confidence=confidence,
                evidence_type="js_dangerous_sink",
                evidence_details={
                    "sink": risk.sink,
                    "source": risk.source,
                    "tainted": risk.tainted,
                    "line": risk.line,
                    "script": source_url,
                    "snippet": risk.snippet,
                },
                reproduction_steps=[
                    f"Open {page_url}",
                    f"Inspect JavaScript: {source_url}",
                    f"Review line {risk.line} where '{risk.sink}' is used"
                    + (
                        f" with data from '{risk.source}'."
                        if risk.tainted
                        else " (verify whether attacker-controlled input can reach it)."
                    ),
                ],
            )
            if finding is not None:
                findings.append(finding)
        return findings
