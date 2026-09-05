"""実 ScanEngine を suite 単位で実行する adapter（0034-R2）。"""
from __future__ import annotations

import asyncio
import math
import tempfile
from urllib.parse import urlparse

from wscan.benchmark_runner import ScanOutcome, ScanRunner


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
            # 実際に攻撃した注入点の実行台帳（scan_matrix）から exercised を作る。resume-only の
            # skip 行は「実行していない」ので除く。これで crawler が到達しなかった case を
            # NOT_REACHED にでき、未計測を TN/FN へ混ぜない（Codex #134 P1）。
            exercised = frozenset(
                (
                    str(row.get("check", "")),
                    urlparse(str(row.get("url", "") or "")).path,
                    str(row.get("field_name", "")),
                )
                for row in (getattr(engine, "scan_matrix", None) or [])
                if row.get("status") != "skipped"
            )
            return ScanOutcome(findings=list(engine.all_findings), exercised=exercised)

        # worker が終了するまで出力先を保持し、例外/キャンセル時も後始末する。
        with tempfile.TemporaryDirectory(prefix="wscan-benchmark-") as output_dir:
            return asyncio.run(scan(output_dir))
