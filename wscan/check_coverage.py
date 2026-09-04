"""check レベルの coverage 集計（0016）。純粋・副作用なし。

registry の全 scanner のうちどれが scan 対象（selected）で、どれが未実行かを可視化する。
既定 scan は少数の check だけ動く（例: sqli/xss/os）ため、残りの scanner が「実行されて
いない＝未検査」であることを明示し、「0 findings＝安全」の誤解を防ぐ（CLAUDE.md 観測性）。

実行時の成否（error/skip）は engine の scan_matrix が別途持つ。本モジュールは *選択* の
会計（in-scope か否か）に限定する。
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping


def compute_check_coverage(
    registry_checks: Iterable[str],
    selected_checks: Iterable[str],
    *,
    contracts: Mapping[str, Any] | None = None,
) -> dict:
    """registry の各 check の選択状態を集計して返す（純粋）。

    - ``registry_checks``: 利用可能な全 check 名（SCANNERS のキー）。
    - ``selected_checks``: 今回の scan で選択された check 名（engine.checks）。
    - ``contracts``: 任意。check -> ScannerContract。あれば state_change/prerequisites を文脈へ。

    返り値の ``coverage_status``:
      - ``COMPLETE``  … registry の全 check が選択された
      - ``INCOMPLETE``… 1つも選択されていない
      - ``PARTIAL``   … 一部のみ選択（既定 scan は通常これ）
    selected に registry 外の check があれば ``unknown_selected`` に出す（誤設定の可視化）。
    """
    registry = sorted({str(c) for c in registry_checks})
    registry_set = set(registry)
    selected = sorted({str(c) for c in selected_checks})
    selected_set = set(selected)

    in_scope = sorted(selected_set & registry_set)
    not_selected = sorted(registry_set - selected_set)
    unknown_selected = sorted(selected_set - registry_set)

    if not in_scope:
        status = "INCOMPLETE"
    elif set(in_scope) == registry_set:
        status = "COMPLETE"
    else:
        status = "PARTIAL"

    checks: dict[str, dict] = {}
    for check in registry:
        entry: dict[str, Any] = {"selected": check in selected_set}
        contract = (contracts or {}).get(check)
        if contract is not None:
            entry["state_change"] = getattr(
                getattr(contract, "state_change", None), "value", ""
            )
            entry["prerequisites"] = sorted(
                getattr(p, "value", str(p))
                for p in getattr(contract, "prerequisites", set()) or set()
            )
        checks[check] = entry

    return {
        "registry_total": len(registry),
        "selected": in_scope,
        "selected_count": len(in_scope),
        "not_selected": not_selected,
        "not_selected_count": len(not_selected),
        "unknown_selected": unknown_selected,
        "coverage_status": status,
        "checks": checks,
    }
