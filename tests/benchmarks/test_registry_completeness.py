"""registry 完全性ゲート（0034-B）のテスト。

registry の全 scanner が benchmark で採点可能（covered）か、明示 gap として承認されているかを
検証する。新しい scanner を registry へ足しただけで benchmark から漏れる状態を回帰で検出する
（受け入れ条件「scanner 追加時に manifest/safe twin/期待結果が無ければ検出する回帰テスト」）。
"""
from pathlib import Path

import pytest

from wscan.benchmark_model import (
    BenchmarkCase,
    BenchmarkSuite,
    ExpectedOutcome,
    ManifestError,
    RegistryGap,
    RequestSpec,
    SourceKind,
    checks_covered_by_suites,
    compute_registry_completeness,
    load_registry_gaps,
    load_registry_gaps_file,
)
from wscan.scanners import SCANNERS

_GAPS_FILE = Path(__file__).resolve().parents[2] / "config" / "benchmark_gaps.yaml"


# ── 純粋関数 ────────────────────────────────────────────────────────────────
def test_completeness_complete_when_all_covered_or_gapped():
    gaps = {"b": RegistryGap("b", "未整備", "0034", "2026-12-31")}
    out = compute_registry_completeness(["a", "b"], ["a"], acknowledged_gaps=gaps)
    assert out["completeness_status"] == "COMPLETE"
    assert out["uncovered"] == []
    assert out["covered"] == ["a"]
    assert out["acknowledged_gaps"] == ["b"]


def test_completeness_incomplete_when_check_neither_covered_nor_gapped():
    out = compute_registry_completeness(["a", "b", "c"], ["a"], acknowledged_gaps={})
    # b, c は covered でも gap でもない＝黙って未計測
    assert out["completeness_status"] == "INCOMPLETE"
    assert out["uncovered"] == ["b", "c"]


def test_completeness_flags_redundant_and_unknown_gaps():
    gaps = {
        "a": RegistryGap("a", "r", "0034", "d"),   # a は covered なのに gap 残存＝redundant
        "zzz": RegistryGap("zzz", "r", "0034", "d"),  # registry に無い＝unknown（削除漏れ）
    }
    out = compute_registry_completeness(["a", "b"], ["a"], acknowledged_gaps=gaps)
    assert out["redundant_gaps"] == ["a"]
    assert out["unknown_gaps"] == ["zzz"]
    # b は covered でも（有効な）gap でもない → INCOMPLETE
    assert out["uncovered"] == ["b"]


def test_completeness_reports_missing_safe_twin():
    out = compute_registry_completeness(
        ["a"], ["a"], safe_twin_checks=[], acknowledged_gaps={}
    )
    # vulnerable はあるが safe twin が無い → FP を測れない
    assert out["missing_safe_twin"] == ["a"]
    out2 = compute_registry_completeness(["a"], ["a"], safe_twin_checks=["a"])
    assert out2["missing_safe_twin"] == []


def test_checks_covered_by_suites_splits_vulnerable_and_safe():
    def _case(cid, expected, check):
        return BenchmarkCase(
            case_id=cid, expected=expected, check=check,
            request=RequestSpec(method="GET", path="/"),
        )
    suite = BenchmarkSuite(
        schema_version=1, suite_id="s", fixture_id="f", runner_profile="browser",
        mode="normal-deterministic", source_kind=SourceKind.FIRST_PARTY,
        cases=(
            _case("v", ExpectedOutcome.VULNERABLE, "xss"),
            _case("s", ExpectedOutcome.SAFE, "xss"),
            _case("v2", ExpectedOutcome.VULNERABLE, "sqli"),  # safe twin 無し
        ),
    )
    vuln, safe = checks_covered_by_suites([suite])
    assert vuln == frozenset({"xss", "sqli"})
    assert safe == frozenset({"xss"})


def test_load_registry_gaps_requires_owner_and_deadline():
    good = {"gaps": {"xss": {"reason": "r", "owner_task": "0034", "deadline": "2026-12-31"}}}
    parsed = load_registry_gaps(good)
    assert parsed["xss"].owner_task == "0034"
    # owner_task 欠落は拒否（黙殺防止＝誰がいつまでに、を必須化）
    with pytest.raises(ManifestError):
        load_registry_gaps({"gaps": {"xss": {"reason": "r", "deadline": "d"}}})
    # 未知キーは拒否
    with pytest.raises(ManifestError):
        load_registry_gaps({"gaps": {"xss": {"reason": "r", "owner_task": "0034",
                                             "deadline": "d", "junk": 1}}})


# ── 実 gaps ファイル × registry の回帰ゲート ─────────────────────────────────
def test_shipped_gaps_file_covers_every_registered_scanner():
    """config/benchmark_gaps.yaml が現 registry を過不足なく承認する（新 scanner 検出ゲート）。

    新しい scanner を registry へ足すと covered でも gap でもなくなり uncovered に出て失敗する。
    scanner を消すと unknown_gaps（削除漏れ）に出て失敗する。
    """
    gaps = load_registry_gaps_file(_GAPS_FILE)
    # 現状 benchmark manifest は未整備＝covered は空（全て明示 gap で承認されているはず）。
    out = compute_registry_completeness(SCANNERS.keys(), covered_checks=[], acknowledged_gaps=gaps)
    assert out["uncovered"] == [], f"benchmark 未承認の scanner: {out['uncovered']}"
    assert out["unknown_gaps"] == [], f"registry に無い gap（削除漏れ）: {out['unknown_gaps']}"
    assert out["completeness_status"] == "COMPLETE"
    assert out["registry_total"] == len(SCANNERS)


def test_gate_fails_when_new_scanner_missing_from_gaps():
    """gaps に無い新規 check を registry に混ぜると INCOMPLETE になる（ゲートが機能する）。"""
    gaps = load_registry_gaps_file(_GAPS_FILE)
    registry_plus_new = list(SCANNERS.keys()) + ["brand_new_scanner_xyz"]
    out = compute_registry_completeness(registry_plus_new, covered_checks=[], acknowledged_gaps=gaps)
    assert "brand_new_scanner_xyz" in out["uncovered"]
    assert out["completeness_status"] == "INCOMPLETE"
