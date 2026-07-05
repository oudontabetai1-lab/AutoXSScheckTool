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

# v2: per-field の "(adaptive)" 完了単位を導入（abort→resume で adaptive を
# 取りこぼさないため）。v1（legacy）由来の checkpoint は "(adaptive)" 単位を
# 持たないので、engine の adaptive ゲートは source_version でこれを判別する。
CHECKPOINT_VERSION = 2
CHECKPOINT_FILENAME = "checkpoint.json"


def unit_key(
    url: str,
    field_name: str,
    form_index: int,
    check_type: str,
    is_url_param: bool = False,
) -> str:
    """攻撃の作業単位を一意な文字列キーにする（純粋関数）。

    URL は末尾スラッシュを ``rstrip`` してスコープ照合と同じ前提に揃える
    （``engine`` の正規化規約に従う）。区切りは衝突しにくい ``\\x1f``。

    同名の URL パラメータとフォームフィールド（例: どちらも ``id`` で
    ``form_index=0``）が同じキーに潰れて一方が未検査のまま resume にスキップ
    されるのを防ぐため、入力種別（URL param / form）もキーに含める。
    """
    norm_url = (url or "").rstrip("/")
    location = "u" if is_url_param else "f"
    return "\x1f".join([norm_url, field_name or "", str(form_index), location, check_type or ""])


@dataclass
class CheckpointState:
    """スキャン進捗のスナップショット。"""
    target_url: str = ""
    checks: list[str] = field(default_factory=list)
    completed_units: set[str] = field(default_factory=set)
    findings: list[dict] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    # 読み込んだデータのスキーマ版（新規作成は現行版）。情報用。v1→v2 の差分
    # （per-field "(adaptive)" 単位）は from_dict の load 時マイグレーションで吸収
    # するため、engine の判定はこの版に依存しない（marker のみで per-field 判定する）。
    source_version: int = CHECKPOINT_VERSION

    # ── 進捗操作（純粋） ────────────────────────────────────────────
    def is_done(
        self, url: str, field_name: str, form_index: int, check_type: str,
        is_url_param: bool = False,
    ) -> bool:
        return unit_key(url, field_name, form_index, check_type, is_url_param) in self.completed_units

    def mark_done(
        self, url: str, field_name: str, form_index: int, check_type: str,
        is_url_param: bool = False,
    ) -> None:
        self.completed_units.add(unit_key(url, field_name, form_index, check_type, is_url_param))
        self.updated_at = time.time()

    def add_finding(self, finding_dict: dict) -> None:
        self.findings.append(finding_dict)

    # ── シリアライズ（純粋） ────────────────────────────────────────
    def to_dict(self) -> dict:
        # 現行版で書き出す。v1 由来でも from_dict の load 時マイグレーションで
        # per-field "(adaptive)" 単位を補完済み（＝実質 v2）なので、v2 として保存して
        # 問題ない。次回 resume は追加マイグレーション不要で marker をそのまま使える。
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
        # 版キー欠落/破損の古い checkpoint は v1（legacy）とみなす（情報用）。
        # 非数値の version でも resume を落とさないよう安全にパースする。
        try:
            source_version = int(data.get("version", 1) or 1)
        except (TypeError, ValueError):
            source_version = 1
        state = cls(
            target_url=data.get("target_url", ""),
            checks=list(data.get("checks", []) or []),
            completed_units=set(data.get("completed_units", []) or []),
            findings=list(data.get("findings", []) or []),
            created_at=data.get("created_at", time.time()),
            updated_at=data.get("updated_at", time.time()),
            source_version=source_version,
        )
        if state.source_version < 2:
            state._migrate_v1_adaptive_units()
        return state

    def _migrate_v1_adaptive_units(self) -> None:
        """v1→v2 マイグレーション: 完了フィールドに "(adaptive)" 単位を補完する（純粋）。

        v1 は per-field の "(adaptive)" 単位を持たない。first-pass の全 configured
        check が done のフィールドは v1 の attack で adaptive 実行済み（v1 は first-pass
        後に adaptive を走らせてから完了記録する）なので、"(adaptive)" を補完して
        次回 resume で完了済みフィールドへ adaptive を再送（重複攻撃・状態変更系の
        再実行）しないようにする。部分完了フィールドは補完せず、resume で残り check と
        ともに adaptive が走る（v1 挙動と一致）。

        version フラグでの一括判定と違い per-field 粒度なので、v1 由来 checkpoint を
        resume 中に新規完了したフィールド（正しく marker を持つ/持たない）と、v1 era の
        完了フィールドを取り違えない。
        """
        checks = [c for c in (self.checks or []) if c]
        if not checks:
            return
        # completed_units を (url, field, form, location) ごとの check 集合へ束ねる。
        done_by_field: dict[tuple, set] = {}
        for key in self.completed_units:
            parts = key.split("\x1f")
            if len(parts) != 5:
                continue
            url, field_name, form_s, location, check = parts
            done_by_field.setdefault((url, field_name, form_s, location), set()).add(check)
        # configured check を全て満たすフィールドだけ adaptive 完了とみなす。
        for (url, field_name, form_s, location), got in done_by_field.items():
            if all(c in got for c in checks):
                adaptive_key = "\x1f".join([url, field_name, form_s, location, "(adaptive)"])
                self.completed_units.add(adaptive_key)

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
    try:
        return CheckpointState.from_dict(data)
    except Exception:
        # メタデータ破損（型不整合など）で from_dict が落ちても resume を
        # クラッシュさせず、「壊れた checkpoint = 使えない」として None を返す。
        return None
