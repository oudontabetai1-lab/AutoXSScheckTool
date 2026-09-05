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
    discover_benchmark_suites,
    load_registry_gaps,
    load_registry_gaps_file,
)
from wscan.scanners import SCANNERS

_REPO_ROOT = Path(__file__).resolve().parents[2]
_GAPS_FILE = _REPO_ROOT / "config" / "benchmark_gaps.yaml"
_MANIFESTS_DIR = _REPO_ROOT / "benchmarks" / "manifests"


# ── 純粋関数 ────────────────────────────────────────────────────────────────
def test_completeness_complete_only_when_all_covered_and_no_gaps():
    # 全 check が実測 covered で gap ゼロ → COMPLETE
    out = compute_registry_completeness(["a", "b"], ["a", "b"], acknowledged_gaps={})
    assert out["completeness_status"] == "COMPLETE"


def test_completeness_partial_when_all_accounted_but_gaps_remain():
    # covered か gap で全て説明できるが gap が残る → PARTIAL（COMPLETE にしない・Codex P1）
    gaps = {"b": RegistryGap("b", "未整備", "0034", "2026-12-31")}
    out = compute_registry_completeness(["a", "b"], ["a"], acknowledged_gaps=gaps)
    assert out["completeness_status"] == "PARTIAL"
    assert out["uncovered"] == []
    assert out["covered"] == ["a"]
    assert out["acknowledged_gaps"] == ["b"]


def test_completeness_all_gaps_is_partial_not_complete():
    # 全 scanner が gap（covered_count==0）でも COMPLETE にしない（Codex P1 の核）
    gaps = {"a": RegistryGap("a", "r", "0034", "d"), "b": RegistryGap("b", "r", "0034", "d")}
    out = compute_registry_completeness(["a", "b"], [], acknowledged_gaps=gaps)
    assert out["completeness_status"] == "PARTIAL"
    assert out["covered_count"] == 0


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


def test_checks_covered_by_suites_excludes_gap_gated_cases():
    """gate=GAP のプレースホルダ case は covered/safe に数えない（Codex P2）。"""
    from wscan.benchmark_model import GateKind, GapInfo

    def _case(cid, expected, check, gate):
        return BenchmarkCase(
            case_id=cid, expected=expected, check=check,
            request=RequestSpec(method="GET", path="/"), gate=gate,
            gap=GapInfo("未整備", "0034", "d") if gate == GateKind.GAP else None,
        )
    suite = BenchmarkSuite(
        schema_version=1, suite_id="s", fixture_id="f", runner_profile="browser",
        mode="normal-deterministic", source_kind=SourceKind.FIRST_PARTY,
        cases=(
            _case("v", ExpectedOutcome.VULNERABLE, "xss", GateKind.OBSERVED),  # 実測
            _case("s", ExpectedOutcome.SAFE, "xss", GateKind.OBSERVED),
            _case("gv", ExpectedOutcome.VULNERABLE, "sqli", GateKind.GAP),  # プレースホルダ
            _case("gs", ExpectedOutcome.SAFE, "sqli", GateKind.GAP),
        ),
    )
    vuln, safe = checks_covered_by_suites([suite])
    assert vuln == frozenset({"xss"})  # sqli は GAP のみ → covered にしない
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


# ── 実 manifest + gaps × registry の回帰ゲート ───────────────────────────────
def _shipped_completeness():
    """canonical manifest から covered/safe を導き、gaps と併せて完全性を会計する（正本経路）。

    covered を空固定にせず manifest から導出することで、後日 manifest を足して gaps から
    外すワークフローが実際に機能する（Codex P2）。
    """
    suites = discover_benchmark_suites(_MANIFESTS_DIR, registry_keys=frozenset(SCANNERS))
    covered, safe = checks_covered_by_suites(suites)
    gaps = load_registry_gaps_file(_GAPS_FILE)
    return compute_registry_completeness(
        SCANNERS.keys(), covered, safe_twin_checks=safe, acknowledged_gaps=gaps
    )


def test_shipped_config_accounts_for_every_registered_scanner():
    """全 registry scanner が manifest covered か明示 gap のいずれかで説明される（新 scanner 検出）。

    新しい scanner を registry へ足すと covered でも gap でもなくなり uncovered に出て失敗する。
    manifest を足して gap を外し忘れると redundant_gaps に出て失敗する。scanner を消すと
    unknown_gaps（削除漏れ）に出て失敗する。
    """
    out = _shipped_completeness()
    assert out["uncovered"] == [], f"benchmark 未承認の scanner: {out['uncovered']}"
    assert out["redundant_gaps"] == [], f"covered 済みなのに gap 残存: {out['redundant_gaps']}"
    assert out["unknown_gaps"] == [], f"registry に無い gap（削除漏れ）: {out['unknown_gaps']}"
    # gap が残る間は COMPLETE ではなく PARTIAL（黙って全未計測を complete にしない）。
    assert out["completeness_status"] in ("COMPLETE", "PARTIAL")
    assert out["registry_total"] == len(SCANNERS)


def test_shipped_covered_checks_have_safe_twin():
    """manifest で covered な check は必ず safe twin を持つ（FP を測れる・空 manifest では自明成立）。"""
    out = _shipped_completeness()
    assert out["missing_safe_twin"] == [], (
        f"vulnerable case はあるが safe twin が無い: {out['missing_safe_twin']}"
    )


def test_gate_fails_when_new_scanner_missing_from_gaps():
    """gaps にも manifest にも無い新規 check を registry に混ぜると INCOMPLETE になる（ゲート機能）。"""
    gaps = load_registry_gaps_file(_GAPS_FILE)
    registry_plus_new = list(SCANNERS.keys()) + ["brand_new_scanner_xyz"]
    out = compute_registry_completeness(registry_plus_new, covered_checks=[], acknowledged_gaps=gaps)
    assert "brand_new_scanner_xyz" in out["uncovered"]
    assert out["completeness_status"] == "INCOMPLETE"


def test_discover_benchmark_suites_empty_when_no_manifests(tmp_path):
    # manifest ディレクトリが空/無い場合は covered 空（例外にしない）
    assert discover_benchmark_suites(tmp_path, registry_keys=frozenset(SCANNERS)) == []
    assert discover_benchmark_suites(tmp_path / "nope", registry_keys=frozenset(SCANNERS)) == []
