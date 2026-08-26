"""見逃し0（recall）ゲートの純粋ロジック（0015 PRINCIPLE-001 / ADR-0016）。

ADR-0016 は「見逃し（false negative）最小化・製品目標0」を第一目的とし、固定 ground truth に
対する **recall 100% をリリースゲート**にすると定めた。本モジュールは、フィクスチャの
`EXPECTED_FINDINGS`（各 spec は `check`/`path`/`field`/`note`）と、実スキャンが報告した
`(check, path, field)` の集合から recall を算出する純粋関数群。

ブラウザ・エンジン非依存＝ユニットテスト可能に保つ（判定ロジックを I/O から分離する規約）。
E2E 側はこの `RecallReport` を使って `recall == 1.0` を単一ゲートとして assert する。

過検知（false positive）はここでは扱わない（recall のみ）。ADR-0016 の通り過検知低減は
検知後の証拠強化・隔離再現で行い、候補削減で recall を犠牲にしないため、関心を分離する。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping, Optional, Sequence

# spec の一意キー（E2E の突合と同一：check_type × path × field）
FindingKey = tuple[str, str, str]


def spec_key(spec: Mapping[str, str]) -> FindingKey:
    """EXPECTED_FINDINGS の1 spec を突合キーへ（欠損は空文字で正規化）。"""
    return (
        str(spec.get("check", "")),
        str(spec.get("path", "")),
        str(spec.get("field", "")),
    )


@dataclass(frozen=True)
class RecallReport:
    """target check 群に対する recall（見逃し）測定結果。純粋・シリアライズ可能。"""

    expected_total: int
    matched_total: int
    missed: tuple[Mapping[str, str], ...] = ()
    by_check: Mapping[str, tuple[int, int]] = field(default_factory=dict)  # check -> (matched, total)

    @property
    def recall(self) -> float:
        """expected が空なら vacuously 1.0（測る対象が無い＝見逃しも無い）。"""
        if self.expected_total == 0:
            return 1.0
        return self.matched_total / self.expected_total

    @property
    def is_complete(self) -> bool:
        """recall 100%（見逃し0）か。リリースゲートの合否。"""
        return self.matched_total >= self.expected_total

    def describe(self) -> str:
        """ゲート失敗メッセージ／ログ用の人間可読サマリ。"""
        pct = self.recall * 100.0
        lines = [
            f"recall {self.matched_total}/{self.expected_total} = {pct:.1f}%"
            + ("" if self.is_complete else "  ← FALSE NEGATIVE(S)"),
        ]
        for check in sorted(self.by_check):
            m, t = self.by_check[check]
            flag = "" if m >= t else "  ← 見逃し"
            lines.append(f"  {check}: {m}/{t}{flag}")
        for spec in self.missed:
            lines.append(
                f"  MISS [{spec.get('check','')}] {spec.get('path','')} "
                f"(field '{spec.get('field','')}') — {spec.get('note','')}"
            )
        return "\n".join(lines)


def compute_recall(
    expected: Sequence[Mapping[str, str]],
    reported: Iterable[FindingKey],
    target_checks: Optional[Iterable[str]] = None,
) -> RecallReport:
    """expected spec 群と実報告キー集合から recall を算出（純粋）。

    - `target_checks` 指定時は、その check 群の spec だけを分母にする（＝当該スキャンで
      有効化した check だけを recall 対象にする。無効 check の未検出を見逃し扱いしない）。
    - 同一キーの spec は重複排除して分母を数える（note 違いの二重計上を防ぐ）。
    - `reported` に expected 外のキーが混ざっても無視（それは precision の話で recall では無関係）。
    """
    reported_set = {(str(c), str(p), str(f)) for (c, p, f) in reported}
    targets = set(target_checks) if target_checks is not None else None

    seen: set[FindingKey] = set()
    matched_total = 0
    missed: list[Mapping[str, str]] = []
    by_check: dict[str, list[int]] = {}  # check -> [matched, total]

    for spec in expected:
        key = spec_key(spec)
        check = key[0]
        if targets is not None and check not in targets:
            continue
        if key in seen:
            continue  # 重複キーは分母1回だけ
        seen.add(key)

        slot = by_check.setdefault(check, [0, 0])
        slot[1] += 1
        if key in reported_set:
            matched_total += 1
            slot[0] += 1
        else:
            missed.append(spec)

    return RecallReport(
        expected_total=len(seen),
        matched_total=matched_total,
        missed=tuple(missed),
        by_check={c: (m, t) for c, (m, t) in by_check.items()},
    )
