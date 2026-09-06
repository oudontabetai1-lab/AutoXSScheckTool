"""注入型 benchmark runner と反射 XSS 用の最小 HTTP executor（0034-R1）。"""
from __future__ import annotations

from contextlib import AbstractContextManager, ExitStack
from dataclasses import dataclass
import json
import math
from pathlib import Path
import re
import threading
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlparse
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


_MISSING = object()  # box に結果が「入っていない」ことを falsey な値と区別するための番兵

# spawn 済みでまだ完了していない worker 数を **プロセス横断**で数える予約カウンタ。per-call の
# cap や「後から登録」方式だと、①長命プロセスが run_suite を繰り返すと cap 分ずつ跨いで累積
# ②並行 run_suite が「確認」と「登録」の隙間で同時に spawn して cap を超過（TOCTOU）する
# （Codex #133）。よって spawn 前に atomic に**予約**し、worker 完了時に解放する。ハングした
# worker は解放されないので予約が残り、cap がプロセス全体で正しく効く。
_lingering_lock = threading.Lock()
_reserved_workers = 0
_worker_limit: int | None = None  # プロセス横断の単一 limit（最初の run_suite が確立）


def _establish_worker_limit(cap: int) -> None:
    """プロセス横断の単一 limit を確立/検証する。異なる値の混在は拒否する（Codex #133）。

    caller ごとに cap が違うと「自分の cap でしか判定しない」ため、cap1 の後 cap100 が
    大量予約して bound を回避できる。プロセス全体で一つの limit を強制し、不整合は loud に拒否。
    """
    global _worker_limit
    with _lingering_lock:
        if _worker_limit is None:
            _worker_limit = cap
        elif cap != _worker_limit:
            raise ValueError(
                f"inconsistent max_lingering_workers: {cap} != process-wide {_worker_limit}"
            )


def _try_reserve_worker() -> bool:
    """共有 limit 未満なら予約(+1)して True。到達済みなら False（atomic な check-and-reserve）。"""
    global _reserved_workers
    with _lingering_lock:
        if _worker_limit is None or _reserved_workers >= _worker_limit:
            return False
        _reserved_workers += 1
        return True


def _release_worker() -> None:
    global _reserved_workers
    with _lingering_lock:
        _reserved_workers = max(0, _reserved_workers - 1)


def _reserved_worker_count() -> int:
    with _lingering_lock:
        return _reserved_workers


def _reset_lingering_workers() -> None:
    """テスト用: 予約カウンタと共有 limit を初期化する（放置 daemon スレッドは残る）。"""
    global _reserved_workers, _worker_limit
    with _lingering_lock:
        _reserved_workers = 0
        _worker_limit = None


def _execute(executor: CaseExecutor, case: BenchmarkCase, base_url: str) -> CaseResult:
    try:
        return executor(case, base_url)
    except Exception:
        # executor 自身の I/O timeout 例外も、待機期限切れ(TIMEOUT)とは分けて扱う。
        return CaseResult(case.case_id, CaseExecutionState.TRANSPORT_ERROR)


def _run_with_timeout(operation: Callable[[], Any], *, name: str, timeout: float) -> Any:
    """予約済み worker を実行する共通 backstop。期限切れの予約は完了時まで保持する。"""
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["result"] = operation()
        except BaseException as exc:
            box["error"] = exc
        finally:
            _release_worker()

    try:
        thread = threading.Thread(target=target, name=name, daemon=True)
        thread.start()
    except BaseException:
        # 構築/start 失敗では target が走らないため、呼び出し側で予約を解放する。
        _release_worker()
        raise
    thread.join(timeout)
    if thread.is_alive():
        raise TimeoutError("benchmark worker timed out")
    if "error" in box:
        raise box["error"]
    return box.get("result", _MISSING)


def _run_case_with_timeout(
    executor: CaseExecutor, case: BenchmarkCase, base_url: str, timeout: float
) -> CaseResult:
    try:
        result = _run_with_timeout(
            lambda: _execute(executor, case, base_url),
            name=f"benchmark-case-{case.case_id}", timeout=timeout,
        )
    except TimeoutError:
        return CaseResult(case.case_id, CaseExecutionState.TIMEOUT)
    if result is _MISSING:
        return CaseResult(case.case_id, CaseExecutionState.TRANSPORT_ERROR)
    return result


class Finding(Protocol):
    check_type: str
    url: str
    field_name: str
    injection_location: str
    verified: bool


@dataclass(frozen=True)
class ScanOutcome:
    """1 スキャンの結果。findings に加え「実際に攻撃した注入点」の集合を持つ（0034-R2）。

    ``exercised`` は ``(check, path, field, location)`` の集合。ran_checks（要求した check）だけ
    では「crawler が注入点に到達し実際に突いたか」が分からず、未実行の safe case を空マッチ＝TN
    と誤計上して precision を水増しする（Codex #134 P1）。実行台帳から exercised を渡すことで、
    突いていない case は NOT_REACHED（未計測）にできる。error/skip 行は「成功して突いた」ではない
    ので exercised に入れない。location も含め、同名の別 carrier を突いただけの case を exercised と
    誤認しない（Codex #134 P2）。location の語彙は case.match.location と揃える（adapter が正規化）。
    """

    findings: list[Any]
    exercised: frozenset[tuple[str, str, str, str]] = frozenset()
    # このスキャンが実際にプロビジョニングした前提の集合（例: 認証済みなら auth_session）。
    # ScanEngineScanRunner は匿名スキャンなので空。前提を宣言した case のうち、ここに無いものは
    # 契約未充足として UNSUPPORTED にし、満たされない環境で TP/FN/FP/TN を作らない（Codex #134 P2）。
    fulfilled_prerequisites: frozenset[str] = frozenset()


# このオラクル/adapter が忠実に採点できる carrier。json_body/page-level 等は scan_matrix の
# field/location が report 用プレースホルダ（"(json-body)"/"(page)"）で finding の実 identity と
# 一致せず、method 次元も台帳に無い。R2 はこれらを UNSUPPORTED にし、R3 で carrier 固有の実行
# identity を導入する（Codex #134 P2）。
_SCOREABLE_CARRIERS = frozenset({"query", "form"})

# passive/page 観測系 case の canonical identity。engine の _attack_one_page が page-level scan_page
# 行に刻む field="(page)"/location="page-level" と一致させる。injection を宣言せず、かつこの identity
# を持つ case だけを passive 採点する（偶発的に injection を省いた field carrier を passive 化しない）。
_PAGE_FIELD = "(page)"
_PAGE_LOCATION = "page-level"


class ScanRunner(Protocol):
    def __call__(self, base_url: str, checks: list[str]) -> ScanOutcome: ...


def _attribute(value: Any, name: str, default: Any = None) -> Any:
    return value.get(name, default) if isinstance(value, Mapping) else getattr(value, name, default)


def _location_compatible(case_location: str, other_location: str) -> bool:
    """宣言側と相手側（finding/実行台帳）の両方が location を持つときだけ一致を要求する。

    どちらかが空なら弁別できないので compatible とみなす（3 キー一致で採る）。両方 populated で
    値が違うときのみ不一致＝別 carrier の取り違えを防ぐ（Codex #134 P2）。
    """
    if not case_location or not other_location:
        return True
    return case_location == other_location


def _case_exercised(
    exercised: frozenset[tuple[str, str, str, str]],
    check: str, path: str, field: str, location: str,
) -> bool:
    """実行台帳に (check, path, field) が location 互換で存在するか（Codex #134 P2）。"""
    return any(
        entry[0] == check and entry[1] == path and entry[2] == field
        and _location_compatible(location, entry[3])
        for entry in exercised
    )


def _finding_check_matches(finding_check: str, case_check: str) -> bool:
    """finding の check_type が case の check ファミリに属するか（Codex #134 P2）。

    engine の ``_check_type_in_scope`` と同型: 完全一致・``"<check>_"`` 前置（graphql_*/jwt_*/
    privesc_* 等のサブタイプ）・エイリアス表（cache_poisoning→cache_deception 等）で判定する。
    サブタイプを exact 一致で捨てると exercised な vulnerable case が FN になる。エイリアス表は
    engine の ``_CHECK_EXTRA_TYPES`` を lazy import して再利用し重複ドリフトを避ける（前置一致だけ
    なら import しない）。
    """
    if finding_check == case_check or finding_check.startswith(case_check + "_"):
        return True
    try:
        from wscan.engine import _CHECK_EXTRA_TYPES
    except Exception:
        return False
    return finding_check in _CHECK_EXTRA_TYPES.get(case_check, ())


def score_cases(
    suite: BenchmarkSuite, outcome: ScanOutcome, *, ran_checks: set[str],
) -> list[CaseResult]:
    """実 findings の候補/確証を照合する。期待値との比較は scorecard 側に委ねる。

    注入点が実際に突かれていない（exercised に無い）case は NOT_REACHED にし、TN/FN へ
    混ぜない（未実行を陰性に計上しない・Codex #134 P1）。location が宣言されている場合は
    finding.injection_location とも一致を要求し、同名 query/form の取り違えを防ぐ（P2）。
    """
    exercised = outcome.exercised
    fulfilled = outcome.fulfilled_prerequisites
    results = []
    for case in suite.cases:
        carrier = getattr(_attribute(case, "injection", None), "carrier", None)
        carrier_value = getattr(carrier, "value", carrier)
        prereqs = tuple(_attribute(case, "prerequisites", ()) or ())
        # passive/page 観測系（security_headers・clickjacking・cors・sri・secret_leak・
        # info_disclosure 等）＝注入点を持たずページ/レスポンス自体を観測する check。field/location
        # （注入概念）で照合せず (check, path) で採点する。exercised は scan_page が記録する page-level
        # 行（field="(page)"/location="page-level"）を要求するので、「page-level スキャナが実際に
        # そのページで走った」genuine な証拠に基づく（プレースホルダ誤マッチではない＝#141 の XML
        # carrier 偽陽性とは別物）。passive 判定は injection 省略だけでなく **canonical な page identity**
        # （match.field="(page)" かつ location="page-level"）も要求する。injection を偶発的に省いた
        # field carrier case を passive 化して field/location 照合を bypass し TP/FP を汚さない（そうした
        # case は field≠"(page)" で passive にならず carrier ゲートで UNSUPPORTED になる・Codex #142 P2）。
        _m = _attribute(case, "match", None)
        is_passive = (
            _attribute(case, "injection", None) is None
            and _attribute(_m, "field", None) == _PAGE_FIELD
            and str(_attribute(_m, "location", "")).strip().lower() == _PAGE_LOCATION
        )
        if (
            case.check not in ran_checks
            or case.match is None
            # 注入系は field carrier（query/form）だけ忠実採点。json/xml/header 等 *注入を宣言する*
            # carrier は scan_matrix の実行 identity がプレースホルダで finding と一致せず未対応。
            # passive（無注入）はこのゲートを免れ、下記の (check, path) 採点を使う。
            or (not is_passive and carrier_value not in _SCOREABLE_CARRIERS)
            # 前提を宣言した case は、スキャンがその前提を実際に用意した場合のみ採点する。
            # 未充足の前提で反射だけ見て TP/FN/FP/TN を作らない（HttpxCaseExecutor と同思想）。
            or any(p not in fulfilled for p in prereqs)
        ):
            results.append(CaseResult(case.case_id, CaseExecutionState.UNSUPPORTED))
            continue
        path = _attribute(case.match, "path")
        field = _attribute(case.match, "field")
        location = _attribute(case.match, "location", "") or ""
        if not _case_exercised(exercised, case.check, path, field, location):
            # 宣言された注入点/ページをスキャンが（成功して）突いていない＝未計測。空マッチを
            # TN/FN にしない。location も含め、同名の別 carrier を突いただけでは exercised にしない。
            results.append(CaseResult(case.case_id, CaseExecutionState.NOT_REACHED))
            continue
        matches = [
            finding for finding in outcome.findings
            if _finding_check_matches(_attribute(finding, "check_type", ""), case.check)
            and urlparse(_attribute(finding, "url", "")).path == path
            # passive は field/location（注入概念）を持たない header 固有 finding なので (check, path)
            # のみで採る。注入系は field 一致 ＋ location 弁別で同名 query/form の取り違えを防ぐ。
            and (
                is_passive
                or (
                    _attribute(finding, "field_name") == field
                    # location は「宣言側 *と* finding 側の両方が populated のときだけ」照合して carrier
                    # を弁別する。finding が空のときは 3 キー一致で採る（Codex #134 P2）。
                    and _location_compatible(location, _attribute(finding, "injection_location", ""))
                )
            )
        ]
        results.append(CaseResult(
            case.case_id, CaseExecutionState.COMPLETED, bool(matches),
            any(bool(_attribute(finding, "verified", False)) for finding in matches),
        ))
    return results


def run_scanned_suite(
    suite: BenchmarkSuite, *, launcher: FixtureLauncher, scan_runner: ScanRunner,
    run_id: str, source_sha: str, manifest_digest: str, registry_digest: str,
    environment: Mapping[str, Any] | None = None, scan_timeout: float = 900.0,
) -> dict[str, Any]:
    """suite ごとに一度スキャンする。失敗/期限切れ時の部分 findings は採用しない。

    強制停止できない worker は R1 と共有する予約枠に残る。実 runner 自身にも
    cooperative timeout が必要で、この期限は待機を打ち切る backstop とする。
    """
    if not math.isfinite(scan_timeout) or scan_timeout <= 0:
        raise ValueError("scan_timeout must be finite and positive")
    # R1 が設定済みならその共有 limit を尊重し、未設定時のみ既定値を確立する。
    global _worker_limit
    with _lingering_lock:
        if _worker_limit is None:
            _worker_limit = 4

    def scorecard(results: list[CaseResult], error: str | None = None) -> dict[str, Any]:
        out = build_scorecard(
            suite, results, run_id=run_id, source_sha=source_sha,
            manifest_digest=manifest_digest, registry_digest=registry_digest,
            environment=environment,
        )
        if error is not None:
            out["run_error"] = error
        return out

    def failed(state: CaseExecutionState, error: str) -> dict[str, Any]:
        return scorecard([CaseResult(case.case_id, state) for case in suite.cases], error)

    if not suite.cases:
        return scorecard([], "empty_suite")
    ran_checks = sorted({case.check for case in suite.cases})
    with ExitStack() as stack:
        try:
            base_url = stack.enter_context(launcher.launch(suite.fixture_id))
        except Exception:
            return failed(CaseExecutionState.FIXTURE_UNAVAILABLE, "fixture_unavailable")
        if not _try_reserve_worker():
            return failed(CaseExecutionState.NOT_REACHED, "scan_failed")
        try:
            outcome = _run_with_timeout(
                lambda: scan_runner(base_url, list(ran_checks)),
                name=f"benchmark-scan-{suite.suite_id}", timeout=scan_timeout,
            )
            if not isinstance(outcome, ScanOutcome):
                raise TypeError("scan_runner must return a ScanOutcome")
        except Exception:
            return failed(CaseExecutionState.NOT_REACHED, "scan_failed")
        results = score_cases(suite, outcome, ran_checks=set(ran_checks))
    return scorecard(results)


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
    max_lingering_workers: int = 4,
) -> dict[str, Any]:
    """各 case の実行状態を集め、既存モデルに集計を委ねる。

    timeout は待機を打ち切る。実行中のスレッドは強制停止できないため、注入する
    executor 自身にも I/O timeout が必要。遅れて返った結果は採用しない。

    daemon スレッドは「終了を待たない」だけで worker を止められないので、非協調的な
    executor（自前 I/O timeout 無し）や per_case_timeout が executor の I/O timeout より
    短い設定だと、期限切れ worker が累積してプロセスを枯渇させうる（Codex #133）。よって
    生存中の worker が ``max_lingering_workers`` に達したら新規 case を起動せず、未処理を
    NOT_REACHED として run_error=worker_exhaustion で loud に打ち切る（黙って積み続けない）。
    """
    if not math.isfinite(per_case_timeout) or per_case_timeout <= 0:
        raise ValueError("per_case_timeout must be finite and positive")
    if max_lingering_workers < 1:
        raise ValueError("max_lingering_workers must be >= 1")
    # プロセス横断の単一 limit を確立/検証（不整合な cap は fixture 起動前に loud に拒否）。
    _establish_worker_limit(max_lingering_workers)

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
        aborted = False
        for idx, case in enumerate(suite.cases):
            # spawn 前に atomic にスロットを予約。取れなければ滞留 worker が上限＝これ以上
            # thread を積まず loud に中断（跨ぎ累積・並行呼び出しの両方をここで bound）。
            if not _try_reserve_worker():
                results.extend(
                    CaseResult(remaining.case_id, CaseExecutionState.NOT_REACHED)
                    for remaining in suite.cases[idx:]
                )
                aborted = True
                break
            # case ごとに分離し、前の timeout が次の case を待たせない（daemon スレッド）。
            # 予約は worker 完了時に target の finally で解放される（ハング時は残る）。
            result = _run_case_with_timeout(executor, case, base_url, per_case_timeout)
            if not isinstance(result, CaseResult):
                raise TypeError("executor must return CaseResult")
            if result.case_id != case.case_id:
                raise ValueError(f"case_id mismatch: {result.case_id} != {case.case_id}")
            results.append(result)
    out = scorecard(results)
    if aborted:
        out["run_error"] = "worker_exhaustion"
    return out


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
        # このオラクルは「匿名の単発 HTTP で XSS の生タグ反射を見る」だけ。よって:
        #  - check!=xss は他 scanner の結果を汚染するので UNSUPPORTED（別 check に XSS probe を撃たない）。
        #  - carrier は query/form のみ。
        #  - **前提を1つでも持つ case は UNSUPPORTED**。auth_session/multi_account/second_request/
        #    oob_sink/api_spec 等はこのオラクルが一切セットアップしないので、満たされないまま反射だけで
        #    採点すると TP/FN/FP/TN を汚染する。browser だけでなく全前提を弾く（Codex #133 P2）。
        if (
            case.check != "xss"
            or injection is None
            or injection.carrier not in {Carrier.QUERY, Carrier.FORM}
            or bool(case.prerequisites)
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
