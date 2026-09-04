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


# Prerequisite 値 → 未充足時の理由（利用者向け・どう設定すれば動くか）。
_PREREQUISITE_REASONS = {
    "auth_session": "認証セッション未設定（--login-url / --auth-user / cookie 等）",
    "oob_sink": "OOB メール受信シンク未設定（WSCAN_OOB_*）",
    "multi_account": "複数アカウント未設定（--accounts に 2 件以上）",
    "api_spec": "API 仕様シード未設定（--api-spec の OpenAPI/Postman）",
    "second_request": "複数リクエスト前提（通常スキャンでは自動的に満たされる）",
    "browser": "実ブラウザ必須（通常スキャンでは常時利用可能）",
}


def compute_prerequisite_coverage(
    selected_checks: Iterable[str],
    contracts: Mapping[str, Any] | None,
    available_prerequisites: Iterable[str],
) -> dict:
    """in-scope の各 scanner の前提充足を会計する（純粋・0016）。

    選択されていても前提（OOB シンク・API 仕様・認証・複数アカウント等）が無ければ
    実質検査できない。これを「前提不足」として *理由付きで* 残し、0 findings＝安全 の
    誤解を防ぐ（選択の会計＝compute_check_coverage とは別軸）。

    - ``selected_checks``: 今回 in-scope の check 名。
    - ``contracts``: check -> ScannerContract。CONTRACT 無し check は判定不能として除外。
    - ``available_prerequisites``: engine 環境が満たす Prerequisite 値の集合
      （通常スキャンでは browser/second_request を常に含める）。

    返り値: ``runnable``（前提充足）と ``prerequisite_missing``（欠落 check と理由）。
    """
    available = {str(p) for p in (available_prerequisites or set())}
    runnable: list[str] = []
    missing: list[dict] = []
    for check in sorted({str(c) for c in selected_checks}):
        contract = (contracts or {}).get(check)
        if contract is None:
            continue
        prereqs = sorted(
            getattr(p, "value", str(p))
            for p in getattr(contract, "prerequisites", set()) or set()
        )
        need = [p for p in prereqs if p not in available]
        if need:
            missing.append(
                {
                    "check": check,
                    "missing_prerequisites": need,
                    "reasons": [_PREREQUISITE_REASONS.get(p, p) for p in need],
                }
            )
        else:
            runnable.append(check)
    return {
        "runnable": runnable,
        "runnable_count": len(runnable),
        "prerequisite_missing": missing,
        "prerequisite_missing_count": len(missing),
    }
