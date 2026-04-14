"""
Diff Scan
=========
前回スキャン結果との差分を計算する。

使い方:
    from wscan.diff_scan import load_previous, diff, DiffResult

    old = load_previous("/path/to/previous/output/evidence.json")
    result = diff(old, new_findings_dicts)
    # result.new_findings      — 今回新規
    # result.fixed_findings    — 前回あり今回なし (修正済み)
    # result.persistent_findings — 両スキャンに存在
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DiffResult:
    """スキャン差分の結果。"""
    new_findings: list[dict] = field(default_factory=list)         # 今回新規
    fixed_findings: list[dict] = field(default_factory=list)       # 前回あり今回なし (修正済み)
    persistent_findings: list[dict] = field(default_factory=list)  # 両スキャンに存在

    def summary(self) -> str:
        return (
            f"差分サマリー: 新規 {len(self.new_findings)} 件 / "
            f"修正済み {len(self.fixed_findings)} 件 / "
            f"継続 {len(self.persistent_findings)} 件"
        )

    def to_dict(self) -> dict:
        return {
            "new": self.new_findings,
            "fixed": self.fixed_findings,
            "persistent": self.persistent_findings,
            "summary": {
                "new_count": len(self.new_findings),
                "fixed_count": len(self.fixed_findings),
                "persistent_count": len(self.persistent_findings),
            },
        }


def load_previous(evidence_path: str) -> list[dict]:
    """
    前回スキャンの evidence.json から findings を読み込む。

    Parameters
    ----------
    evidence_path : evidence.json のパス、またはそれを含むディレクトリのパス

    Returns
    -------
    list[dict] — findings のリスト。ファイルが見つからない場合は空リスト。
    """
    p = Path(evidence_path)
    if p.is_dir():
        p = p / "evidence.json"
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data.get("findings", [])
    except Exception:
        return []


def _finding_key(f: dict) -> tuple:
    """(url, field_name, check_type) を正規化したキーを返す。"""
    return (
        (f.get("url") or "").rstrip("/"),
        (f.get("field_name") or ""),
        (f.get("check_type") or ""),
    )


def diff(old: list[dict], new: list[dict]) -> DiffResult:
    """
    old と new の findings を (url, field_name, check_type) で比較する。

    Parameters
    ----------
    old : 前回スキャンの findings (dict のリスト)
    new : 今回スキャンの findings (dict のリスト)

    Returns
    -------
    DiffResult
    """
    old_map: dict[tuple, dict] = {_finding_key(f): f for f in old}
    new_map: dict[tuple, dict] = {_finding_key(f): f for f in new}

    old_keys = set(old_map.keys())
    new_keys = set(new_map.keys())

    new_only_keys = new_keys - old_keys
    fixed_keys = old_keys - new_keys
    persistent_keys = old_keys & new_keys

    # 新規・修正済み・継続に分類
    new_findings = [new_map[k] for k in new_only_keys]
    fixed_findings = [old_map[k] for k in fixed_keys]
    persistent_findings = []
    for k in persistent_keys:
        entry = dict(new_map[k])
        entry["_diff_status"] = "persistent"
        persistent_findings.append(entry)

    # 新規に diff ステータスを付与
    for f in new_findings:
        f["_diff_status"] = "new"
    for f in fixed_findings:
        f["_diff_status"] = "fixed"

    return DiffResult(
        new_findings=new_findings,
        fixed_findings=fixed_findings,
        persistent_findings=persistent_findings,
    )
