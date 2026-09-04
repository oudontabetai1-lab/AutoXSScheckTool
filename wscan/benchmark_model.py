"""E2E benchmark の manifest schema と純粋な scorecard 集計（0034-A）。

runner、HTTP、browser、fixture、evidence 読み取りには依存しない。ファイル読み取りは
``load_manifest_file`` だけに閉じ込め、集計と Markdown 生成は渡された値だけで決まる。
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from os import PathLike
from typing import Any, Iterable, Mapping, Sequence

from wscan.scanner_contract import Carrier, ValueKind


class ExpectedOutcome(str, Enum):
    VULNERABLE = "vulnerable"
    SAFE = "safe"


class GateKind(str, Enum):
    REQUIRED = "required"
    OBSERVED = "observed"
    GAP = "gap"


class SourceKind(str, Enum):
    FIRST_PARTY = "first_party"
    INDEPENDENT = "independent"
    EXTERNAL = "external"


class CaseExecutionState(str, Enum):
    COMPLETED = "completed"
    NOT_REACHED = "not_reached"
    UNSUPPORTED = "unsupported"
    BLOCKED = "blocked"
    TIMEOUT = "timeout"
    TRANSPORT_ERROR = "transport_error"
    FIXTURE_UNAVAILABLE = "fixture_unavailable"
    EVIDENCE_INCOMPLETE = "evidence_incomplete"
    INVALID_MANIFEST = "invalid_manifest"


class Classification(str, Enum):
    TP = "tp"
    FN = "fn"
    FP = "fp"
    TN = "tn"


class OverallStatus(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    INCOMPLETE = "INCOMPLETE"
    FAILED = "FAILED"


# completed 以外で、混同行列の分母に入れてはならない実行状態。
INCOMPLETE_STATES: frozenset[CaseExecutionState] = frozenset(
    {
        CaseExecutionState.NOT_REACHED,
        CaseExecutionState.UNSUPPORTED,
        CaseExecutionState.BLOCKED,
        CaseExecutionState.TIMEOUT,
        CaseExecutionState.TRANSPORT_ERROR,
        CaseExecutionState.FIXTURE_UNAVAILABLE,
        CaseExecutionState.EVIDENCE_INCOMPLETE,
    }
)


@dataclass(frozen=True)
class RequestSpec:
    method: str
    path: str


@dataclass(frozen=True)
class InjectionSpec:
    carrier: Carrier
    parameter_id: str
    value_kind: ValueKind = ValueKind.UNKNOWN


@dataclass(frozen=True)
class MatchSpec:
    path: str = ""
    field: str = ""
    location: str = ""


@dataclass(frozen=True)
class GapInfo:
    reason: str
    owner_task: str
    deadline: str


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    expected: ExpectedOutcome
    check: str
    request: RequestSpec
    injection: InjectionSpec | None = None
    twin_id: str = ""
    taxonomy: tuple[str, ...] = ()
    difficulty: str = ""
    prerequisites: tuple[str, ...] = ()
    gate: GateKind = GateKind.OBSERVED
    match: MatchSpec | None = None
    gap: GapInfo | None = None


@dataclass(frozen=True)
class BenchmarkSuite:
    schema_version: int
    suite_id: str
    fixture_id: str
    runner_profile: str
    mode: str
    source_kind: SourceKind
    cases: tuple[BenchmarkCase, ...]


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    state: CaseExecutionState
    candidate_match: bool = False
    confirmed_match: bool = False


class ManifestError(ValueError):
    """benchmark manifest が schema または不変条件に違反している。"""


def classify(expected: ExpectedOutcome, matched: bool) -> Classification:
    """期待値と一致有無を混同行列の4象限へ分類する。"""
    if expected == ExpectedOutcome.VULNERABLE:
        return Classification.TP if matched else Classification.FN
    return Classification.FP if matched else Classification.TN


def case_classification(
    case: BenchmarkCase,
    result: CaseResult,
    *,
    tier: str,
) -> Classification | None:
    """completed case だけを candidate/confirmed の混同行列へ入れる。"""
    if tier not in {"candidate", "confirmed"}:
        raise ValueError("tier must be 'candidate' or 'confirmed'")
    if result.state != CaseExecutionState.COMPLETED:
        return None
    matched = result.candidate_match if tier == "candidate" else result.confirmed_match
    return classify(case.expected, matched)


def _result_index(results: Iterable[CaseResult]) -> dict[str, CaseResult]:
    """case_id ごとに最初の result を採用し、重複による二重計上を防ぐ。"""
    indexed: dict[str, CaseResult] = {}
    for result in results:
        indexed.setdefault(result.case_id, result)
    return indexed


def _empty_metric_counts() -> dict[str, int]:
    return {classification.value: 0 for classification in Classification}


def _finish_metrics(counts: Mapping[str, int]) -> dict[str, int | float | None]:
    tp = counts[Classification.TP.value]
    fn = counts[Classification.FN.value]
    fp = counts[Classification.FP.value]
    recall_denominator = tp + fn
    precision_denominator = tp + fp
    return {
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": counts[Classification.TN.value],
        "recall": tp / recall_denominator if recall_denominator else None,
        "precision": tp / precision_denominator if precision_denominator else None,
        "recall_denominator": recall_denominator,
        "precision_denominator": precision_denominator,
    }


def compute_metrics(
    cases: Iterable[BenchmarkCase],
    results: Iterable[CaseResult],
) -> dict[str, dict[str, int | float | None]]:
    """candidate/confirmed の件数、recall、precision を一度の case 会計から返す。"""
    result_by_id = _result_index(results)
    counts = {
        "candidate": _empty_metric_counts(),
        "confirmed": _empty_metric_counts(),
    }
    for case in cases:
        result = result_by_id.get(case.case_id)
        if result is None:
            continue
        for tier in ("candidate", "confirmed"):
            classification = case_classification(case, result, tier=tier)
            if classification is not None:
                counts[tier][classification.value] += 1
    return {tier: _finish_metrics(tier_counts) for tier, tier_counts in counts.items()}


def overall_status(
    cases: Iterable[BenchmarkCase],
    results: Iterable[CaseResult],
) -> OverallStatus:
    """manifest failure、実行完了性、required confirmed gate の順に判定する。"""
    case_tuple = tuple(cases)
    result_tuple = tuple(results)
    if any(r.state == CaseExecutionState.INVALID_MANIFEST for r in result_tuple):
        return OverallStatus.FAILED

    result_by_id = _result_index(result_tuple)
    if any(
        case.case_id not in result_by_id
        or result_by_id[case.case_id].state != CaseExecutionState.COMPLETED
        for case in case_tuple
    ):
        return OverallStatus.INCOMPLETE

    # gap は既知の未充足契約なので、実行自体が completed でも完全達成にはしない。
    if any(case.gate == GateKind.GAP for case in case_tuple):
        return OverallStatus.PARTIAL

    required_cases = tuple(case for case in case_tuple if case.gate == GateKind.REQUIRED)
    required_metrics = compute_metrics(required_cases, result_tuple)["confirmed"]
    all_metrics = compute_metrics(case_tuple, result_tuple)["confirmed"]
    required_gate_passed = (
        required_metrics["recall_denominator"] > 0
        and required_metrics["recall"] == 1.0
        and required_metrics["fp"] == 0
    )
    if required_gate_passed and all_metrics["fp"] == 0:
        return OverallStatus.COMPLETE
    return OverallStatus.PARTIAL


def _grouped_metrics(
    results: Sequence[CaseResult],
    groups: Mapping[str, Iterable[BenchmarkCase]],
) -> dict[str, dict[str, dict[str, int | float | None]]]:
    return {
        key: compute_metrics(tuple(group_cases), results)
        for key, group_cases in sorted(groups.items())
    }


def _append_group(
    groups: dict[str, list[BenchmarkCase]],
    key: str,
    case: BenchmarkCase,
) -> None:
    groups.setdefault(key, []).append(case)


def _breakdowns(
    suite: BenchmarkSuite,
    results: Sequence[CaseResult],
) -> dict[str, dict[str, dict[str, dict[str, int | float | None]]]]:
    check_groups: dict[str, list[BenchmarkCase]] = {}
    carrier_groups: dict[str, list[BenchmarkCase]] = {}
    taxonomy_groups: dict[str, list[BenchmarkCase]] = {}
    mode_groups: dict[str, list[BenchmarkCase]] = {}

    for case in suite.cases:
        _append_group(check_groups, case.check, case)
        carrier = case.injection.carrier.value if case.injection else "none"
        _append_group(carrier_groups, carrier, case)
        for taxonomy in case.taxonomy or ("untagged",):
            _append_group(taxonomy_groups, taxonomy, case)
        _append_group(mode_groups, suite.mode, case)

    return {
        "check": _grouped_metrics(results, check_groups),
        "carrier": _grouped_metrics(results, carrier_groups),
        "taxonomy": _grouped_metrics(results, taxonomy_groups),
        "mode": _grouped_metrics(results, mode_groups),
    }


def _json_value(value: Any) -> Any:
    """scorecard 境界で Enum/immutable collection を JSON の基本型へ落とす。"""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_json_value(item) for item in value), key=str)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"scorecard value is not JSON serializable: {type(value).__name__}")


def build_scorecard(
    suite: BenchmarkSuite,
    results: Iterable[CaseResult],
    *,
    run_id: str,
    source_sha: str,
    manifest_digest: str,
    registry_digest: str,
    environment: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """設計 §9 の最小契約を満たす JSON 直列化可能な scorecard を構築する。"""
    result_tuple = tuple(results)
    result_by_id = _result_index(result_tuple)
    case_rows: list[dict[str, Any]] = []
    completed = 0

    for case in suite.cases:
        result = result_by_id.get(case.case_id)
        if result is not None and result.state == CaseExecutionState.COMPLETED:
            completed += 1
        candidate = case_classification(case, result, tier="candidate") if result else None
        confirmed = case_classification(case, result, tier="confirmed") if result else None
        case_rows.append(
            {
                "case_id": case.case_id,
                "expected": case.expected.value,
                "check": case.check,
                "carrier": case.injection.carrier.value if case.injection else None,
                "value_kind": case.injection.value_kind.value if case.injection else None,
                "taxonomy": list(case.taxonomy),
                "gate": case.gate.value,
                "state": result.state.value if result else None,
                "candidate_match": result.candidate_match if result else None,
                "confirmed_match": result.confirmed_match if result else None,
                "classification": {
                    "candidate": candidate.value if candidate else None,
                    "confirmed": confirmed.value if confirmed else None,
                },
            }
        )

    planned = len(suite.cases)
    scorecard = {
        "schema_version": 1,
        "run_id": run_id,
        "source_sha": source_sha,
        "manifest_digest": manifest_digest,
        "registry_digest": registry_digest,
        "overall_status": overall_status(suite.cases, result_tuple).value,
        "suite": {
            "suite_id": suite.suite_id,
            "fixture_id": suite.fixture_id,
            "runner_profile": suite.runner_profile,
            "mode": suite.mode,
            "source_kind": suite.source_kind.value,
        },
        "case_counts": {
            "planned": planned,
            "completed": completed,
            "incomplete": planned - completed,
        },
        "metrics": compute_metrics(suite.cases, result_tuple),
        "breakdowns": _breakdowns(suite, result_tuple),
        "cases": case_rows,
        "baseline_diff": {"new": [], "removed": [], "regressed": [], "improved": []},
        "environment": _json_value(environment or {}),
        "artifacts": [],
    }
    return _json_value(scorecard)


def _display(value: Any) -> str:
    return "null" if value is None else str(value)


def scorecard_to_markdown(scorecard: dict[str, Any]) -> str:
    """既に集計済みの JSON dict だけを読み、人間向け Markdown を生成する。"""
    counts = scorecard["case_counts"]
    lines = [
        "# E2E benchmark scorecard",
        "",
        f"- Overall status: **{scorecard['overall_status']}**",
        f"- Run ID: `{scorecard['run_id']}`",
        f"- Cases: planned={counts['planned']}, completed={counts['completed']}, "
        f"incomplete={counts['incomplete']}",
        "",
        "## Metrics",
        "",
        "| Tier | TP | FN | FP | TN | Recall | Recall denominator | Precision | Precision denominator |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for tier in ("candidate", "confirmed"):
        metric = scorecard["metrics"][tier]
        lines.append(
            f"| {tier} | {metric['tp']} | {metric['fn']} | {metric['fp']} | {metric['tn']} "
            f"| {_display(metric['recall'])} | {metric['recall_denominator']} "
            f"| {_display(metric['precision'])} | {metric['precision_denominator']} |"
        )

    lines.extend(
        [
            "",
            "## Breakdowns",
            "",
            "| Dimension | Value | Tier | TP | FN | FP | TN | Recall | Precision |",
            "|---|---|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for dimension in ("check", "carrier", "taxonomy", "mode"):
        for key, tier_metrics in sorted(scorecard["breakdowns"][dimension].items()):
            for tier in ("candidate", "confirmed"):
                metric = tier_metrics[tier]
                lines.append(
                    f"| {dimension} | {key} | {tier} | {metric['tp']} | {metric['fn']} "
                    f"| {metric['fp']} | {metric['tn']} | {_display(metric['recall'])} "
                    f"| {_display(metric['precision'])} |"
                )
    return "\n".join(lines) + "\n"


_TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "suite_id",
        "fixture_id",
        "runner_profile",
        "mode",
        "source_kind",
        "cases",
    }
)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ManifestError(f"{label} must be a mapping")
    if any(not isinstance(key, str) for key in value):
        raise ManifestError(f"{label} keys must be strings")
    return value


def _known_keys(data: Mapping[str, Any], allowed: frozenset[str], label: str) -> None:
    unknown = set(data) - allowed
    if unknown:
        raise ManifestError(f"{label} has unknown keys: {', '.join(sorted(unknown))}")


def _required_string(data: Mapping[str, Any], key: str, label: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ManifestError(f"{label}.{key} must be a non-empty string")
    return value


def _optional_string(data: Mapping[str, Any], key: str, label: str) -> str:
    value = data.get(key, "")
    if not isinstance(value, str):
        raise ManifestError(f"{label}.{key} must be a string")
    return value


def _string_tuple(data: Mapping[str, Any], key: str, label: str) -> tuple[str, ...]:
    value = data.get(key, [])
    if not isinstance(value, (list, tuple)) or any(not isinstance(item, str) for item in value):
        raise ManifestError(f"{label}.{key} must be a list of strings")
    # 重複ラベルは breakdown を二重計上させ分母を suite 総数超過にするため拒否する。
    seen: set[str] = set()
    for item in value:
        if item in seen:
            raise ManifestError(f"{label}.{key} has duplicate label: {item}")
        seen.add(item)
    return tuple(value)


def _enum_value(enum_type: type[Enum], value: Any, label: str) -> Any:
    if not isinstance(value, str):
        raise ManifestError(f"{label} must be a string")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ManifestError(f"{label} has unknown value: {value}") from exc


def _load_request(value: Any, label: str) -> RequestSpec:
    data = _mapping(value, label)
    _known_keys(data, frozenset({"method", "path"}), label)
    return RequestSpec(
        method=_required_string(data, "method", label),
        path=_required_string(data, "path", label),
    )


def _load_injection(value: Any, label: str) -> InjectionSpec | None:
    if value is None:
        return None
    data = _mapping(value, label)
    _known_keys(data, frozenset({"carrier", "parameter_id", "value_kind"}), label)
    return InjectionSpec(
        carrier=_enum_value(Carrier, data.get("carrier"), f"{label}.carrier"),
        parameter_id=_required_string(data, "parameter_id", label),
        value_kind=_enum_value(
            ValueKind,
            data.get("value_kind", ValueKind.UNKNOWN.value),
            f"{label}.value_kind",
        ),
    )


def _load_match(value: Any, label: str) -> MatchSpec | None:
    if value is None:
        return None
    data = _mapping(value, label)
    _known_keys(data, frozenset({"path", "field", "location"}), label)
    return MatchSpec(
        path=_optional_string(data, "path", label),
        field=_optional_string(data, "field", label),
        location=_optional_string(data, "location", label),
    )


def _load_gap(value: Any, label: str) -> GapInfo | None:
    if value is None:
        return None
    data = _mapping(value, label)
    _known_keys(data, frozenset({"reason", "owner_task", "deadline"}), label)
    return GapInfo(
        reason=_required_string(data, "reason", label),
        owner_task=_required_string(data, "owner_task", label),
        deadline=_required_string(data, "deadline", label),
    )


def _load_case(value: Any, index: int, registry_keys: frozenset[str]) -> BenchmarkCase:
    label = f"cases[{index}]"
    data = _mapping(value, label)
    _known_keys(
        data,
        frozenset(
            {
                "case_id",
                "expected",
                "check",
                "request",
                "injection",
                "twin_id",
                "taxonomy",
                "difficulty",
                "prerequisites",
                "gate",
                "match",
                "gap",
            }
        ),
        label,
    )
    check = _required_string(data, "check", label)
    if check not in registry_keys:
        raise ManifestError(f"{label}.check is not a scanner registry key: {check}")
    gate = _enum_value(GateKind, data.get("gate", GateKind.OBSERVED.value), f"{label}.gate")
    gap = _load_gap(data.get("gap"), f"{label}.gap")
    if gate == GateKind.GAP and gap is None:
        raise ManifestError(f"{label}.gap is required when gate=gap")
    # gap メタデータがあるのに gate!=gap だと overall_status が gap を無視し
    # 完了 suite を誤って COMPLETE と報告するため、不整合な manifest を拒否する。
    if gap is not None and gate != GateKind.GAP:
        raise ManifestError(f"{label}.gap requires gate=gap")
    return BenchmarkCase(
        case_id=_required_string(data, "case_id", label),
        expected=_enum_value(ExpectedOutcome, data.get("expected"), f"{label}.expected"),
        check=check,
        request=_load_request(data.get("request"), f"{label}.request"),
        injection=_load_injection(data.get("injection"), f"{label}.injection"),
        twin_id=_optional_string(data, "twin_id", label),
        taxonomy=_string_tuple(data, "taxonomy", label),
        difficulty=_optional_string(data, "difficulty", label),
        prerequisites=_string_tuple(data, "prerequisites", label),
        gate=gate,
        match=_load_match(data.get("match"), f"{label}.match"),
        gap=gap,
    )


def _validate_twins(cases: Sequence[BenchmarkCase]) -> None:
    by_id = {case.case_id: case for case in cases}
    for case in cases:
        if case.expected == ExpectedOutcome.VULNERABLE:
            if not case.twin_id:
                raise ManifestError(f"vulnerable case {case.case_id} requires twin_id")
            twin = by_id.get(case.twin_id)
            if twin is None:
                raise ManifestError(f"case {case.case_id} twin does not exist: {case.twin_id}")
            if twin.expected != ExpectedOutcome.SAFE:
                raise ManifestError(f"case {case.case_id} twin must be expected=safe")
            if twin.twin_id != case.case_id:
                raise ManifestError(f"case {case.case_id} twin must reference it back")
            if twin.check != case.check:
                raise ManifestError(
                    f"case {case.case_id} twin must target the same check: "
                    f"{case.check} vs {twin.check}"
                )
        elif case.twin_id:
            twin = by_id.get(case.twin_id)
            if twin is None or twin.expected != ExpectedOutcome.VULNERABLE:
                raise ManifestError(f"safe case {case.case_id} twin must be expected=vulnerable")
            if twin.twin_id != case.case_id:
                raise ManifestError(f"safe case {case.case_id} twin must reference it back")
            if twin.check != case.check:
                raise ManifestError(
                    f"safe case {case.case_id} twin must target the same check: "
                    f"{case.check} vs {twin.check}"
                )


def load_manifest(data: dict[str, Any], *, registry_keys: frozenset[str]) -> BenchmarkSuite:
    """YAML 等から得た dict を検証し、immutable な suite schema へ変換する。"""
    manifest = _mapping(data, "manifest")
    _known_keys(manifest, _TOP_LEVEL_KEYS, "manifest")
    schema_version = manifest.get("schema_version")
    if type(schema_version) is not int or schema_version != 1:
        raise ManifestError("manifest.schema_version must be 1")

    raw_cases = manifest.get("cases")
    if not isinstance(raw_cases, (list, tuple)):
        raise ManifestError("manifest.cases must be a list")
    cases = tuple(_load_case(raw, index, registry_keys) for index, raw in enumerate(raw_cases))
    case_ids = [case.case_id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise ManifestError("manifest case_id values must be unique")
    _validate_twins(cases)

    return BenchmarkSuite(
        schema_version=schema_version,
        suite_id=_required_string(manifest, "suite_id", "manifest"),
        fixture_id=_required_string(manifest, "fixture_id", "manifest"),
        runner_profile=_required_string(manifest, "runner_profile", "manifest"),
        mode=_required_string(manifest, "mode", "manifest"),
        source_kind=_enum_value(
            SourceKind,
            manifest.get("source_kind"),
            "manifest.source_kind",
        ),
        cases=cases,
    )


def load_manifest_file(
    path: str | PathLike[str],
    *,
    registry_keys: frozenset[str],
) -> BenchmarkSuite:
    """YAML ファイルを読むだけの薄い I/O wrapper。検証は ``load_manifest`` に委譲する。"""
    import yaml

    try:
        with open(path, encoding="utf-8") as stream:
            data = yaml.safe_load(stream)
    except (OSError, yaml.YAMLError) as exc:
        raise ManifestError(f"could not load manifest file: {exc}") from exc
    return load_manifest(data, registry_keys=registry_keys)
