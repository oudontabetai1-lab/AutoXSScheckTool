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

    async def scan_page_context(self, page) -> list[Finding]:
        """クロール時に保持した ``page.html`` を解析する（推奨経路）。

        マルチページ走査では、ページ単位スキャナの実行時に既にブラウザが別ページ
        へ遷移している（``navigate()`` が network 捕捉も毎回クリアする）ため、
        現在タブの DOM を読むと別ページを解析してしまう。クロール時点で確定した
        HTML を使うことで、正しいページの inline script を確実に解析する。

        外部スクリプトの本文も、クロール時点でスナップショットした
        ``page.external_scripts``（{絶対URL: body}）を優先して使う（navigate で
        network 捕捉が消えても外部 JS を解析できる）。
        """
        return await self._scan(
            getattr(page, "url", "") or "",
            getattr(page, "html", "") or "",
            getattr(page, "external_scripts", None) or {},
        )

    async def scan_page(self, url: str) -> list[Finding]:
        # scan_page_context が使えない経路向けのフォールバック（現在タブの DOM）。
        pair = self.current_page_pair(url)
        html = (pair.get("response", {}) or {}).get("body", "") or ""
        if not html:
            try:
                html = await self.browser.page.content()
            except Exception:
                html = ""
        return await self._scan(url, html, {})

    async def _scan(self, url: str, html: str, external_scripts: dict) -> list[Finding]:
        if not url or url in self._checked_urls:
            return []
        self._checked_urls.add(url)

        if self.monitor:
            await self.monitor.emit_status(f"JS static audit on {url}")

        page_host = _host_of(url)
        findings: list[Finding] = []

        # 1) インライン script を解析（first-party 扱い）。
        for idx, script in enumerate(js_analysis.extract_inline_scripts(html)):
            label = f"(inline script #{idx + 1})"
            findings += await self._record_risks(
                url, label, script, first_party=True, source_url=url
            )

        # 2) このページが参照する外部 .js のみを解析（別ページの資源を誤って
        #    取り込まないよう、現在ページの HTML に出てくる src に限定する）。
        #    本文はクロール時スナップショット → 無ければ現在の network 捕捉から引く。
        network = getattr(self.browser, "network", None)
        from urllib.parse import urljoin

        for src in js_analysis.extract_external_script_srcs(html):
            js_url = urljoin(url, src)
            if js_url in self._scanned_scripts:
                continue
            body = external_scripts.get(js_url, "") if external_scripts else ""
            if not body:
                pair = (
                    network.latest_for_url(js_url, match_query=False)
                    if network and hasattr(network, "latest_for_url")
                    else None
                )
                body = (pair or {}).get("response", {}).get("body", "") if pair else ""
            if not body or not body.strip():
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
