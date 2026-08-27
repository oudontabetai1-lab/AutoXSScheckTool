"""probe 証跡台帳の recorder（0032-B・append-only・I/O 分離）。

[0032-A (#118)](probe_ledger.py) の純粋 schema を使い、実際の試行を **append-only な正本**
`probe_attempts.jsonl` へ記録する recorder を提供する。scan 内で単調増加する attempt_id を
払い出し、outcome/role 別の件数と **書込み失敗** を manifest に残す。

最上位契約（Task 0032）:
- **No evidence, no COMPLETE**: 証跡の書込みに失敗したら握りつぶさず manifest に残す。scan 完了
  判定は `evidence_incomplete` を見る。
- **Evidence for every outcome**: matched だけでなく no-match/blocked/skipped/timeout/error も
  記録する（呼び出し側が outcome を付けて append する）。

**durability モデル（0032-B, DECISION: 簡素化＝単一 source-of-truth）**:
台帳の write 失敗は稀（disk 異常）で、その試行の証跡は失われる。二源（成功=jsonl / 失敗=manifest）を
突合する複雑さを避け、次の単純な規律にする:
- **jsonl が唯一の正本**（成功試行の source of truth）。
- **write 失敗＝即 quarantine**: 以後の append を拒否し、run を evidence-incomplete とする
  （書けない＝EVIDENCE_INCOMPLETE と整合）。部分 tail への追記・継続はしない。
- **resume**: 成功件数は jsonl から再構築（単一 source）。前 run の不完全さ（write 失敗/欠落）は
  **1 個の欠落マーカー**として持ち越し `evidence_incomplete` を維持する（失敗試行の厳密な内訳を
  跨 run で再構成しない＝reconciliation を持たない）。新規 append は許可（disk が回復していれば継続）。
- crash 対策: 末尾の不完全行は parse-aware に修復（完全 JSON は delimiter を補い保持、断片は truncate）。
  manifest は temp+os.replace で原子的に置換。

I/O はここに閉じ、集計は純粋 `LedgerManifest` へ分離する（I/O と判定の分離規約）。全 transport
送信経路への配線は後続増分（0032-C）。
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from wscan.probe_ledger import (
    ProbeAttemptRecord,
    ProbeOutcome,
    ProbeRole,
    derive_attempt_id,
    to_jsonl_line,
)

LEDGER_FILENAME = "probe_attempts.jsonl"
MANIFEST_FILENAME = "probe_attempts_manifest.json"

_VALID_ROLES = frozenset(r.value for r in ProbeRole)


def _role_key(role) -> str:
    return role.value if isinstance(role, ProbeRole) else str(role)


def _outcome_key(outcome) -> str:
    if isinstance(outcome, ProbeOutcome):
        return outcome.value
    return str(outcome) if outcome else "unrecorded"


@dataclass
class LedgerManifest:
    """台帳の集計（純粋・I/O 非依存）。件数・欠落・書込み失敗を保持し 0 Finding を安全へ丸めない。"""

    total: int = 0
    by_role: dict = field(default_factory=dict)
    by_outcome: dict = field(default_factory=dict)
    write_errors: list = field(default_factory=list)  # list[dict]: {error, role, outcome}

    def record(self, role, outcome, *, write_ok: bool, error: str = "") -> None:
        """1 試行を集計へ反映する（純粋）。成功/失敗いずれも件数内訳へ加算し、失敗は error も残す。"""
        self.total += 1
        rk = _role_key(role)
        ok = _outcome_key(outcome)
        self.by_role[rk] = self.by_role.get(rk, 0) + 1
        self.by_outcome[ok] = self.by_outcome.get(ok, 0) + 1
        if not write_ok:
            self.write_errors.append({"error": error or "write_failed", "role": rk, "outcome": ok})

    def note_gap(self, reason: str) -> None:
        """resume で検出した欠落（件数内訳は不明）を 1 マーカーとして残す。

        跨 run で失敗試行の厳密な内訳は再構成せず、`had_write_error` を維持する目的（No evidence,
        no COMPLETE のゲートを前 run の不完全さで倒し続ける）。件数（total 等）は動かさない。"""
        self.write_errors.append({"error": reason, "role": "", "outcome": "gap"})

    @property
    def had_write_error(self) -> bool:
        """証跡の欠落/書込み失敗があったか（No evidence, no COMPLETE の判定に使う）。"""
        return bool(self.write_errors)

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "by_role": dict(self.by_role),
            "by_outcome": dict(self.by_outcome),
            "write_errors": list(self.write_errors),
            "had_write_error": self.had_write_error,
        }


class ProbeLedger:
    """append-only な probe 台帳 writer。scan 単位。thread-safe（並列ワーカー対応）。

    attempt_id は `derive_attempt_id(scan_id, seq)` で決定論的に払い出す（resume 安定）。
    台帳 write に失敗すると **quarantine** し（`quarantined=True`）、以後の append を拒否する。
    `evidence_incomplete` は run が証跡を取り切れなかったか（＝No evidence, no COMPLETE のゲート）。
    """

    def __init__(self, output_dir, scan_id: str, *, enabled: bool = True) -> None:
        self.scan_id = scan_id
        self.enabled = enabled
        self._seq = 0
        self._lock = threading.Lock()
        self.manifest = LedgerManifest()
        self._quarantined = False
        self._manifest_write_failed = False
        self._path: Optional[Path] = None
        if enabled and output_dir:
            self._path = Path(output_dir) / LEDGER_FILENAME
            self._restore_from_existing()

    @property
    def path(self) -> Optional[Path]:
        return self._path

    @property
    def quarantined(self) -> bool:
        """台帳 write に失敗して隔離中か（True の間 append は拒否）。"""
        return self._quarantined

    @property
    def evidence_incomplete(self) -> bool:
        """証跡を取り切れなかったか（write 失敗 or 前 run の欠落 or resume 検出の行欠落 or
        manifest 書出し失敗）。No evidence, no COMPLETE のリリースゲート。"""
        return (self._quarantined or self._manifest_write_failed
                or self.manifest.had_write_error)

    # ── restore ──────────────────────────────────────────────────────────
    def _repair_unterminated_tail(self, data: bytes) -> bool:
        """末尾が改行で終わらない場合、末尾行を parse して完全な object なら delimiter を補い、
        壊れた断片だけ truncate する。修復 I/O に失敗したら False（quarantine 側で扱う）。"""
        if not data or data.endswith(b"\n"):
            return True
        nl = data.rfind(b"\n")
        tail = data[nl + 1:]
        try:
            keep = isinstance(json.loads(tail.decode("utf-8")), dict)
        except (ValueError, UnicodeDecodeError):
            keep = False
        try:
            if keep:
                with open(self._path, "ab") as fh:
                    fh.write(b"\n")
            else:
                with open(self._path, "rb+") as fh:
                    fh.truncate(nl + 1)  # nl==-1 なら 0
                # 実行済み probe の不完全な証跡を捨てた＝欠落として gate を倒す。
                self.manifest.note_gap("ledger_tail_truncated")
        except OSError:
            return False
        return True

    def _valid_row(self, rec) -> bool:
        """復元行が正本レコードとして妥当か（identity と語彙）。破損行を成功に数えないための門番。"""
        if not isinstance(rec, dict):
            return False
        if rec.get("scan_id") != self.scan_id:
            return False  # foreign/missing scan_id＝別ファイル or 破損
        aid = str(rec.get("attempt_id", ""))
        head, sep, seq = aid.rpartition(":")
        if not sep or head != self.scan_id or not seq.isdigit():
            return False  # attempt_id が `<scan_id>:<seq>` 形でない（foreign prefix/壊れ連番）
        if rec.get("role") not in _VALID_ROLES:
            return False  # 語彙外の role
        return True

    def _restore_from_existing(self) -> None:
        """既存台帳から seq/manifest を復元する（単一 source＝jsonl）。前 run の不完全さは 1 マーカーで継承。"""
        if self._path is None:
            return
        max_seq = 0
        restored_rows = 0
        if self._path.exists():
            try:
                data = self._path.read_bytes()
            except OSError:
                # 既存正本を読めない＝以後の append を止める（ID 再発行/欠落を防ぐ）
                self._quarantined = True
                self.manifest.note_gap("ledger_unreadable_on_resume")
                return
            if not self._repair_unterminated_tail(data):
                self._quarantined = True
                self.manifest.note_gap("ledger_tail_repair_failed")
                return
            skipped = 0
            try:
                with open(self._path, encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                        except ValueError:
                            skipped += 1
                            continue  # 壊れた行はスキップ（＝正本の破損＝証跡欠落）
                        if not self._valid_row(rec):
                            skipped += 1
                            continue  # schema 不正（非 object/foreign scan_id/壊れ id/語彙外 role）
                        max_seq = max(max_seq, int(str(rec["attempt_id"]).rpartition(":")[2]))
                        restored_rows += 1
                        self.manifest.record(rec.get("role", ""), rec.get("outcome"), write_ok=True)
            except (OSError, UnicodeDecodeError):
                # 読取り不能/不正バイト列＝正本を信頼できない。以後の append を止める。
                self._quarantined = True
                self.manifest.note_gap("ledger_read_failed_on_resume")
                return
            if skipped:
                # 破損/非 object 行が正本にある＝証跡欠落。gate を倒す（No evidence, no COMPLETE）。
                self.manifest.note_gap("ledger_rows_skipped_on_resume")
        self._seq = max_seq
        # 前 run の manifest から「不完全だった事実」だけを継承する（内訳の再構成はしない）。
        manifest_path = self._path.with_name(MANIFEST_FILENAME)
        if manifest_path.exists():
            try:
                prior = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                # 既存 manifest が読めない/壊れている＝欠落状態を復元できない
                self.manifest.note_gap("prior_manifest_unreadable")
                return
            if not isinstance(prior, dict):
                # 非 object の manifest は破損とみなす
                self.manifest.note_gap("prior_manifest_not_object")
                return
            # seq は前 run の発行 ID 総数（=max seq）も考慮（trailing failure/stale jsonl 対策）
            try:
                prior_total = int(prior.get("total") or 0)
            except (ValueError, TypeError):
                prior_total = 0
                self.manifest.note_gap("prior_manifest_bad_total")
            self._seq = max(self._seq, prior_total)
            # 前 run が不完全（write 失敗）だった事実を継承（内訳は再構成しない）。
            errs = prior.get("write_errors")
            if errs:  # 非空 list/その他 truthy を「不完全あり」とみなす
                self.manifest.note_gap("prior_run_evidence_incomplete")
            if prior_total > restored_rows:
                # 例: jsonl が外部で削除/truncate されたのに manifest は多い＝行が失われている
                self.manifest.note_gap("ledger_rows_missing_on_resume")

    # ── append / manifest ────────────────────────────────────────────────
    def next_attempt_id(self) -> str:
        """次の attempt_id を払い出す（単調増加・決定論・thread-safe）。"""
        with self._lock:
            self._seq += 1
            return derive_attempt_id(self.scan_id, self._seq)

    def append(self, record: ProbeAttemptRecord) -> bool:
        """試行レコードを台帳へ追記する。成功で True。

        無効（enabled=False / 出力先なし）は no-op で True。quarantine 中（過去の write 失敗）は
        書込まず失敗として記録し False。write 失敗時は quarantine して以後の append を拒否する
        （部分 tail への連結を構造的に防ぐ）。判定・write・集計は同一 critical section で行う。
        """
        if not (self.enabled and self._path is not None):
            return True
        with self._lock:
            if self._quarantined:
                self.manifest.record(record.role, record.outcome, write_ok=False,
                                     error="ledger_quarantined")
                return False
            try:
                line = to_jsonl_line(record)
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except (OSError, ValueError, UnicodeError) as exc:
                # write/直列化/エンコード失敗（不正 UTF-8・lone surrogate 等）＝証跡は失われた。
                # 以後の append を止める（quarantine）。
                self._quarantined = True
                self.manifest.record(record.role, record.outcome, write_ok=False,
                                     error=f"{type(exc).__name__}: {exc}")
                return False
            self.manifest.record(record.role, record.outcome, write_ok=True)
            return True

    def write_manifest(self) -> bool:
        """manifest を JSON で原子的に書き出す（temp+os.replace）。scan 完了時に件数・欠落を残す。"""
        if not (self.enabled and self._path is not None):
            return False
        manifest_path = self._path.with_name(MANIFEST_FILENAME)
        tmp_path = manifest_path.with_name(MANIFEST_FILENAME + ".tmp")
        try:
            with self._lock:
                data = self.manifest.to_dict()
                data["scan_id"] = self.scan_id
                data["ledger"] = LEDGER_FILENAME
                data["quarantined"] = self._quarantined
                data["evidence_incomplete"] = self.evidence_incomplete
            tmp_path.write_text(
                json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            os.replace(tmp_path, manifest_path)
            # 一過性の書出し失敗から回復＝完全な manifest が永続化された。sticky flag を解除。
            self._manifest_write_failed = False
            return True
        except OSError:
            # manifest を永続化できない＝完了証跡が残らない。gate を倒す（caller が返り値を見落として
            # も evidence_incomplete で COMPLETE を防ぐ）。
            self._manifest_write_failed = True
            return False
