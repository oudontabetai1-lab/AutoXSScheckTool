"""注入型 benchmark runner と反射 XSS 用の最小 HTTP executor（0034-R1）。"""
from __future__ import annotations

from contextlib import AbstractContextManager, ExitStack
import json
import math
from pathlib import Path
import re
import threading
from typing import Any, Mapping, Protocol
from uuid import uuid4

import httpx

from wscan.benchmark_model import (
    BenchmarkCase, BenchmarkSuite, CaseExecutionState, CaseResult,
    build_scorecard, scorecard_to_markdown,
)
from wscan.scanner_contract import Carrier


class CaseExecutor(Protocol):
    def __call__(self, case: BenchmarkCase, base_url: str) -> CaseResult: ...


class FixtureLauncher(Protocol):
    def launch(self, fixture_id: str) -> AbstractContextManager[str]: ...


def _execute(executor: CaseExecutor, case: BenchmarkCase, base_url: str) -> CaseResult:
    try:
        return executor(case, base_url)
    except Exception:
        # executor 自身の I/O timeout 例外も、待機期限切れ(TIMEOUT)とは分けて扱う。
        return CaseResult(case.case_id, CaseExecutionState.TRANSPORT_ERROR)


def _run_case_with_timeout(
    executor: CaseExecutor, case: BenchmarkCase, base_url: str, timeout: float
) -> CaseResult:
    """case を **daemon スレッド**で実行し、timeout 秒待つ。

    ThreadPoolExecutor は実行中の future を cancel できず、その非 daemon worker が残ると
    インタプリタ終了時に Python がそれを join して**プロセスが永久ハング**する（Codex #133）。
    そのため daemon スレッドを使い、期限切れ時はスレッドを放置する（daemon なので終了を
    ブロックしない）。executor は自前の I/O timeout（cooperative cancellation）を持つ前提で、
    このスレッド timeout はその backstop。遅れて返った結果は採用しない。
    """
    box: dict[str, CaseResult] = {}

    def target() -> None:
        box["result"] = _execute(executor, case, base_url)

    thread = threading.Thread(
        target=target, name=f"benchmark-case-{case.case_id}", daemon=True
    )
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        return CaseResult(case.case_id, CaseExecutionState.TIMEOUT)
    # 完了していれば target が必ず box を埋める。空なら想定外なので TRANSPORT_ERROR。
    return box.get("result") or CaseResult(case.case_id, CaseExecutionState.TRANSPORT_ERROR)


def run_suite(
    suite: BenchmarkSuite,
    *,
    executor: CaseExecutor,
    launcher: FixtureLauncher,
    run_id: str,
    source_sha: str,
    manifest_digest: str,
    registry_digest: str,
    environment: Mapping[str, Any] | None = None,
    per_case_timeout: float = 30.0,
) -> dict[str, Any]:
    """各 case の実行状態を集め、既存モデルに集計を委ねる。

    timeout は待機を打ち切る。実行中のスレッドは強制停止できないため、注入する
    executor 自身にも I/O timeout が必要。遅れて返った結果は採用しない。
    """
    if not math.isfinite(per_case_timeout) or per_case_timeout <= 0:
        raise ValueError("per_case_timeout must be finite and positive")

    def scorecard(results: list[CaseResult]) -> dict[str, Any]:
        return build_scorecard(
            suite, results, run_id=run_id, source_sha=source_sha,
            manifest_digest=manifest_digest, registry_digest=registry_digest,
            environment=environment,
        )

    if not suite.cases:
        out = scorecard([])
        out["run_error"] = "empty_suite"
        return out

    with ExitStack() as stack:
        try:
            base_url = stack.enter_context(launcher.launch(suite.fixture_id))
        except Exception:
            out = scorecard([
                CaseResult(case.case_id, CaseExecutionState.FIXTURE_UNAVAILABLE)
                for case in suite.cases
            ])
            out["run_error"] = "fixture_unavailable"
            return out

        results = []
        for case in suite.cases:
            # case ごとに分離し、前の timeout が次の case を待たせない（daemon スレッド）。
            result = _run_case_with_timeout(executor, case, base_url, per_case_timeout)
            if not isinstance(result, CaseResult):
                raise TypeError("executor must return CaseResult")
            if result.case_id != case.case_id:
                raise ValueError(f"case_id mismatch: {result.case_id} != {case.case_id}")
            results.append(result)
    return scorecard(results)


def write_scorecard(scorecard: dict[str, Any], out_dir: str | Path) -> tuple[Path, Path]:
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / "scorecard.json"
    md_path = directory / "scorecard.md"
    json_path.write_text(json.dumps(scorecard, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(scorecard_to_markdown(scorecard), encoding="utf-8")
    return json_path, md_path


class HttpxCaseExecutor(CaseExecutor):
    """**参照オラクル**（製品スキャナではない）。query/form の生タグ反射だけを測る。

    fixture の健全性チェック（脆弱は反射・安全は非反射）と runner 配管の検証に使う参照実装。
    製品の検出ロジック（XSSScanner/ScanEngine）を一切呼ばないので、**これで採点した scorecard は
    製品スキャナの recall/回帰を測れない**（Codex #133 P1）。実スキャナを走らせて実 findings から
    採点する scanner-backed executor は 0034-R2 で追加する。期待値との比較は集計側（build_scorecard）。
    """

    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout

    def __call__(self, case: BenchmarkCase, base_url: str) -> CaseResult:
        injection = case.injection
        if (
            injection is None
            or injection.carrier not in {Carrier.QUERY, Carrier.FORM}
            or any(p.lower() in {"browser", "browser_required", "chromium", "playwright"}
                   for p in case.prerequisites)
        ):
            return CaseResult(case.case_id, CaseExecutionState.UNSUPPORTED)

        marker = re.sub(r"[^a-zA-Z0-9]", "", f"wscanbench{case.case_id}{uuid4().hex}")
        probe = f"{marker}<svg/onload=alert(1)>"
        url = base_url.rstrip("/") + "/" + case.request.path.lstrip("/")
        # manifest の宣言メソッドを尊重する（verb 違いで別ハンドラを叩かないよう）。carrier は
        # 注入位置（query=URL パラメータ / form=body）を決め、method は HTTP verb を決める。
        method = (case.request.method or "GET").upper()
        with httpx.Client(timeout=self.timeout, trust_env=False) as client:
            if injection.carrier == Carrier.QUERY:
                # path 内の既存 query は保ち、対象パラメータだけ差し替える。宣言メソッドで送る。
                target = httpx.URL(url).copy_merge_params({injection.parameter_id: probe})
                response = client.request(method, target)
            else:
                response = client.request(
                    method, url, data={injection.parameter_id: probe}
                )
            response.raise_for_status()
            matched = probe in response.text
        return CaseResult(case.case_id, CaseExecutionState.COMPLETED, matched, matched)
