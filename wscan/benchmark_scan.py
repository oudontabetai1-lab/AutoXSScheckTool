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


# probe が transport 層で握りつぶされた/template が実行不能だった check を示す観測ノート
# （engine.wave_errors、0007 D1）。status="tested" でも実際には probe が送達していない場合がある
# ため、劣化した check の行は exercised から除く（Codex #134 P1）。
_DEGRADATION_PREFIXES = ("transport_error:", "unexecutable_template:")


def _degraded_checks(wave_errors) -> frozenset:
    """wave_errors から transport 劣化/実行不能が記録された check 名の集合を作る（純粋）。"""
    degraded = set()
    for note in (wave_errors or []):
        if not isinstance(note, str):
            continue
        for prefix in _DEGRADATION_PREFIXES:
            if note.startswith(prefix):
                check = note[len(prefix):].split(":", 1)[0].strip()
                if check:
                    degraded.add(check)
    return frozenset(degraded)


def _row_exercised(row, degraded_checks) -> bool:
    """1 行が exercised か。finding は送達の陽性証拠なので常に採る。tested は劣化 check なら除く。

    - finding: 実際に finding を出した＝probe が送達され check が走った陽性証拠。劣化があっても採る
      （別 field の transport error で成功検出まで消さない・Codex #134 P2）。
    - tested: 空振り。probe が送達したか曖昧なので、劣化 check（transport 握りつぶし等）では除く。
    - error/skip 等: 未計測なので採らない。
    """
    status = row.get("status")
    if status == "finding":
        return True
    if status == "tested":
        return str(row.get("check", "")) not in degraded_checks
    return False


def _exercised_from_scan_matrix(scan_matrix, degraded_checks=frozenset()) -> frozenset:
    """scan_matrix から (check, path, field, location) の exercised 集合を作る（純粋）。

    finding/tested（成功して突いた）行を採り、error/skip は未計測なので除く。degraded_checks
    （transport 握りつぶし等が観測された check）の曖昧な tested 行は除くが、finding 行は残す
    （送達の陽性証拠・Codex #134 P1/P2）。location は正規化する。
    """
    return frozenset(
        (
            str(row.get("check", "")),
            urlparse(str(row.get("url", "") or "")).path,
            str(row.get("field_name", "")),
            _normalize_location(row.get("location", "")),
        )
        for row in (scan_matrix or [])
        if _row_exercised(row, degraded_checks)
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
            # crawler 未到達/errored/別 carrier だけ/transport 劣化した case を NOT_REACHED にし
            # TN/FN に混ぜない（#134）。ScanEngineScanRunner は前提を用意しない匿名スキャンなので
            # fulfilled_prerequisites は空（前提付き case は score 側で UNSUPPORTED）。
            degraded = _degraded_checks(getattr(engine, "wave_errors", None))
            exercised = _exercised_from_scan_matrix(
                getattr(engine, "scan_matrix", None), degraded_checks=degraded
            )
            return ScanOutcome(findings=list(engine.all_findings), exercised=exercised)

        # worker が終了するまで出力先を保持し、例外/キャンセル時も後始末する。
        with tempfile.TemporaryDirectory(prefix="wscan-benchmark-") as output_dir:
            return asyncio.run(scan(output_dir))
