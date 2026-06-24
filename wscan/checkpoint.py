"""
再開可能スキャン（チェックポイント）
====================================
長時間スキャンの中断（時間帯ゲートでの停止・ネットワーク断・手動 Abort・
クラッシュ）から、攻撃済みの作業単位を飛ばして再開するための状態管理。

設計方針:
  - 作業単位 = ``(url, field_name, form_index, check_type)``。``_scan_field`` が
    フィールド×チェックの二重ループで進むので、この粒度で「済み」を記録すれば
    再開時に重複攻撃を避けられる。
  - 既出 Finding も保存し、再開後のレポートに引き継ぐ（dedup キーも復元）。
  - クロールは冪等で比較的安価なため再実行する（ページ構造の永続化はしない）。
    再クロール後、本モジュールが「済み」単位を弾くことで攻撃フェーズを短縮する。

純粋ロジック（キー生成・済み判定・dict 変換・マージ）はブラウザ/IO 非依存で
テストできるよう副作用を持たない。``save`` / ``load`` のみ薄い IO を行う。
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

CHECKPOINT_VERSION = 1
CHECKPOINT_FILENAME = "checkpoint.json"


def unit_key(url: str, field_name: str, form_index: int, check_type: str) -> str:
    """攻撃の作業単位を一意な文字列キーにする（純粋関数）。

    URL は末尾スラッシュを ``rstrip`` してスコープ照合と同じ前提に揃える
    （``engine`` の正規化規約に従う）。区切りは衝突しにくい ``\\x1f``。
    """
    norm_url = (url or "").rstrip("/")
    return "\x1f".join([norm_url, field_name or "", str(form_index), check_type or ""])


@dataclass
class CheckpointState:
    """スキャン進捗のスナップショット。"""
    target_url: str = ""
    checks: list[str] = field(default_factory=list)
    completed_units: set[str] = field(default_factory=set)
    findings: list[dict] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    # ── 進捗操作（純粋） ────────────────────────────────────────────
    def is_done(self, url: str, field_name: str, form_index: int, check_type: str) -> bool:
        return unit_key(url, field_name, form_index, check_type) in self.completed_units

    def mark_done(self, url: str, field_name: str, form_index: int, check_type: str) -> None:
        self.completed_units.add(unit_key(url, field_name, form_index, check_type))
        self.updated_at = time.time()

    def add_finding(self, finding_dict: dict) -> None:
        self.findings.append(finding_dict)

    # ── シリアライズ（純粋） ────────────────────────────────────────
    def to_dict(self) -> dict:
        return {
            "version": CHECKPOINT_VERSION,
            "target_url": self.target_url,
            "checks": list(self.checks),
            "completed_units": sorted(self.completed_units),
            "findings": self.findings,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CheckpointState":
        return cls(
            target_url=data.get("target_url", ""),
            checks=list(data.get("checks", []) or []),
            completed_units=set(data.get("completed_units", []) or []),
            findings=list(data.get("findings", []) or []),
            created_at=data.get("created_at", time.time()),
            updated_at=data.get("updated_at", time.time()),
        )

    def is_compatible_with(self, target_url: str, checks: list[str]) -> bool:
        """再開先のターゲット/チェック集合が、保存時と整合するか（純粋）。

        ターゲット URL が一致し、要求チェックが保存時チェックの部分集合なら互換。
        新しいチェックを足した再開では「済み」が信用できないので非互換扱いにする。
        """
        if (self.target_url or "").rstrip("/") != (target_url or "").rstrip("/"):
            return False
        return set(checks or []).issubset(set(self.checks or []))


def checkpoint_path(output_dir: str | Path) -> Path:
    return Path(output_dir) / CHECKPOINT_FILENAME


def save_checkpoint(output_dir: str | Path, state: CheckpointState) -> Path:
    """チェックポイントを ``output_dir/checkpoint.json`` に原子的に書き出す。"""
    path = checkpoint_path(output_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state.to_dict(), ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)  # 同一ディレクトリ内 rename は原子的
    return path


def load_checkpoint(path: str | Path) -> Optional[CheckpointState]:
    """チェックポイントを読み込む。ファイルや JSON が壊れていれば None。

    ``path`` はファイルでもディレクトリでも受け付ける（ディレクトリなら
    ``checkpoint.json`` を探す）。
    """
    p = Path(path)
    if p.is_dir():
        p = checkpoint_path(p)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    return CheckpointState.from_dict(data)
