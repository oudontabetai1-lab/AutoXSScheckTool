"""実 ScanEngine を suite 単位で実行する adapter（0034-R2）。"""
from __future__ import annotations

import asyncio
import math
import tempfile
from urllib.parse import urlparse

from wscan.benchmark_runner import ScanOutcome, ScanRunner


# scan_matrix の location は人間可読（"URL param"/"form field"）で、MatchSpec.location や
# Finding.injection_location（"url_param"/"form"）とは別語彙。exercised を case と比較できるよう
# 後者へ正規化する（Codex #134 P2）。未知値はそのまま通す（_location_compatible が空/不一致を扱う）。
_LOCATION_NORMALIZE = {"url param": "url_param", "form field": "form"}

# 「成功して突いた」＝実際に採点可能な行だけ exercised に入れる。error（scanner が payload 完了前に
# 例外）や skipped（未実行）は未計測なので除く（Codex #134 P1）。
_EXERCISED_STATUSES = frozenset({"tested", "finding"})


def _normalize_location(raw: str) -> str:
    return _LOCATION_NORMALIZE.get(str(raw or "").strip().lower(), str(raw or ""))


def _exercised_from_scan_matrix(scan_matrix) -> frozenset:
    """scan_matrix から (check, path, field, location) の exercised 集合を作る（純粋）。

    tested/finding（成功して突いた）行だけ。error/skip は未計測なので除く。location は正規化する。
    """
    return frozenset(
        (
            str(row.get("check", "")),
            urlparse(str(row.get("url", "") or "")).path,
            str(row.get("field_name", "")),
            _normalize_location(row.get("location", "")),
        )
        for row in (scan_matrix or [])
        if row.get("status") in _EXERCISED_STATUSES
    )


class ScanEngineScanRunner(ScanRunner):
    def __init__(self, timeout: float = 840.0) -> None:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be finite and positive")
        self.timeout = timeout

    def __call__(self, base_url: str, checks: list[str]) -> ScanOutcome:
        # 単体テスト/manifest 読み込み時には engine/browser を引き込まない。
        from wscan.engine import ScanEngine

        async def scan(output_dir: str) -> ScanOutcome:
            engine = ScanEngine(
                base_url.rstrip("/") + "/", checks=list(checks), llm_provider="none",
                headless=True, output_dir=output_dir, open_report=False,
                enable_waf_detection=False, enable_ai_analysis=False,
                enable_payload_learning=False, enable_adaptive_payloads=False,
                enable_sitemap_crawl=False, depth=2, fast_mode=True, max_payloads=8,
                request_delay=0, use_planner=False, sarif=False, timeout=8,
                navigation_retries=0,
            )
            await asyncio.wait_for(engine.run(), timeout=self.timeout)
            # 実際に「成功して」攻撃した注入点の実行台帳（scan_matrix）から exercised を作る。
            # crawler 未到達/errored/別 carrier だけの case を NOT_REACHED にし TN/FN に混ぜない（#134）。
            exercised = _exercised_from_scan_matrix(getattr(engine, "scan_matrix", None))
            return ScanOutcome(findings=list(engine.all_findings), exercised=exercised)

        # worker が終了するまで出力先を保持し、例外/キャンセル時も後始末する。
        with tempfile.TemporaryDirectory(prefix="wscan-benchmark-") as output_dir:
            return asyncio.run(scan(output_dir))
