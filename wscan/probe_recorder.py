"""probe 証跡台帳の recorder（0032-B・append-only・I/O 分離）。

[0032-A (#118)](probe_ledger.py) の純粋 schema を使い、実際の試行を **append-only な正本**
`probe_attempts.jsonl` へ記録する recorder を提供する。scan 内で単調増加する attempt_id を
払い出し、outcome/role 別の件数と **書込み失敗** を manifest に残す。

最上位契約（Task 0032）:
- **No evidence, no COMPLETE**: 必須証跡の書込みに失敗したら握りつぶさず manifest に error を
  残す（`append` は False を返し、`had_write_error` が立つ）。scan 完了判定はこれを見る。
- **Evidence for every outcome**: matched だけでなく no-match/blocked/skipped/timeout/error も
  記録する（呼び出し側が outcome を付けて append する）。

resume 耐久性（crash/interrupt に耐える append-only 正本）:
- 不完全な末尾行は **parse して**、完全な JSON なら delimiter を補い保持、壊れた断片だけ truncate。
- 既存正本の **復元に失敗したら以後の append を止める**（`_seq=0` のまま ID 再発行/欠落を防ぐ）。
- 失敗試行は role/outcome 付きで manifest に残し、resume で **件数内訳ごと**復元する。

I/O（ファイル追記・manifest 書出し）はここに閉じ、判定・件数ロジックは純粋な `LedgerManifest`
（下）と `probe_ledger` の純粋関数へ委譲する（I/O と判定の分離規約）。recorder を scanner/engine の
全 transport 送信経路へ配線するのは後続増分（0032-C）。
"""
from __future__ import annotations

import json
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


def _role_key(role) -> str:
    return role.value if isinstance(role, ProbeRole) else str(role)


def _outcome_key(outcome) -> str:
    if isinstance(outcome, ProbeOutcome):
        return outcome.value
    return str(outcome) if outcome else "unrecorded"


@dataclass
class LedgerManifest:
    """台帳の集計（純粋・I/O 非依存）。件数・欠落・書込み失敗を保持し 0 Finding を安全へ丸めない。

    `write_errors` は **role/outcome を含む dict のリスト**（失敗試行の内訳を resume で失わないため）。
    """

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

    @property
    def had_write_error(self) -> bool:
        """証跡書込みに失敗があったか（No evidence, no COMPLETE の判定に使う）。"""
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
    `append` は JSONL 1 行を追記し、失敗しても例外を投げず manifest に error を残して False を返す。
    既存正本の復元に失敗した場合は `recovery_failed` が立ち、以後の append を拒否する。
    """

    def __init__(self, output_dir, scan_id: str, *, enabled: bool = True) -> None:
        self.scan_id = scan_id
        self.enabled = enabled
        self._seq = 0
        self._lock = threading.Lock()
        self.manifest = LedgerManifest()
        self._recovery_failed = False
        self._path: Optional[Path] = None
        if enabled and output_dir:
            self._path = Path(output_dir) / LEDGER_FILENAME
            # resume: 既存台帳から seq/manifest を復元してから新規試行を受ける
            self._restore_from_existing()

    @property
    def path(self) -> Optional[Path]:
        return self._path

    @property
    def recovery_failed(self) -> bool:
        """既存正本の復元に失敗したか（True の間 append は拒否＝ID 再発行/欠落を防ぐ）。"""
        return self._recovery_failed

    def _repair_unterminated_tail(self, data: bytes) -> None:
        """末尾が改行で終わらない場合、末尾行を parse して完全なら delimiter を補い、
        壊れた断片だけ truncate する（interrupted write の完全レコードを失わない）。"""
        if not data or data.endswith(b"\n"):
            return
        nl = data.rfind(b"\n")
        tail = data[nl + 1:]
        keep_tail = False
        try:
            json.loads(tail.decode("utf-8"))
            keep_tail = True  # delimiter 欠落だけの完全レコード → 残す
        except (ValueError, UnicodeDecodeError):
            keep_tail = False
        try:
            if keep_tail:
                with open(self._path, "ab") as fh:
                    fh.write(b"\n")
            else:
                with open(self._path, "rb+") as fh:
                    fh.truncate(nl + 1)  # nl==-1 なら 0（全体が partial）
        except OSError:
            self._recovery_failed = True

    def _restore_from_existing(self) -> None:
        """既存台帳から seq/manifest を復元する（resume 安定）。復元不能なら recovery_failed。"""
        if self._path is None:
            return
        max_seq = 0
        if self._path.exists():
            try:
                data = self._path.read_bytes()
            except OSError:
                # 既存正本を読めない＝安全に続けられない。以後の append を止める。
                self._recovery_failed = True
                return
            self._repair_unterminated_tail(data)
            if self._recovery_failed:
                return
            try:
                with open(self._path, encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                        except ValueError:
                            continue  # 壊れた行はスキップ
                        seq_part = str(rec.get("attempt_id", "")).rpartition(":")[2]
                        if seq_part.isdigit():
                            max_seq = max(max_seq, int(seq_part))
                        # 永続化済み＝成功。内訳へ加算。
                        self.manifest.record(rec.get("role", ""), rec.get("outcome"), write_ok=True)
            except OSError:
                self._recovery_failed = True
                return
        # 前 run の manifest から失敗試行を内訳ごと復元（jsonl の有無に関わらず）。
        manifest_path = self._path.with_name(MANIFEST_FILENAME)
        prior_total = 0
        if manifest_path.exists():
            try:
                prior = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                # 既存 manifest が壊れて読めない＝欠落状態を復元できない。止める。
                self._recovery_failed = True
                return
            if isinstance(prior, dict):
                prior_total = int(prior.get("total") or 0)
                for entry in prior.get("write_errors", []) or []:
                    if isinstance(entry, dict):
                        self.manifest.record(entry.get("role", ""), entry.get("outcome"),
                                             write_ok=False, error=str(entry.get("error", "")))
                    else:  # legacy: 文字列のみ
                        self.manifest.record("", None, write_ok=False, error=str(entry))
        # 失敗試行も ID を消費している（trailing failure は jsonl 最大 seq を超える）。
        # prior_total は前 run の発行 ID 総数＝max seq。stale manifest も考慮して max を取る。
        self._seq = max(max_seq, prior_total)

    def next_attempt_id(self) -> str:
        """次の attempt_id を払い出す（単調増加・決定論・thread-safe）。"""
        with self._lock:
            self._seq += 1
            return derive_attempt_id(self.scan_id, self._seq)

    def append(self, record: ProbeAttemptRecord) -> bool:
        """試行レコードを台帳へ追記する。成功で True。失敗は manifest に残し False（例外は投げない）。

        無効（enabled=False / 出力先なし）のときは no-op で True。既存正本の復元に失敗している
        （recovery_failed）ときは、ID 再発行/欠落を避けるため書込まず失敗として記録し False を返す。
        """
        if not (self.enabled and self._path is not None):
            return True
        if self._recovery_failed:
            with self._lock:
                self.manifest.record(record.role, record.outcome, write_ok=False,
                                     error="ledger_recovery_failed")
            return False
        line = to_jsonl_line(record)
        write_ok = True
        error = ""
        try:
            with self._lock:
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
        except OSError as exc:  # 書込み失敗は握りつぶさず可視化
            write_ok = False
            error = f"{type(exc).__name__}: {exc}"
        with self._lock:
            self.manifest.record(record.role, record.outcome, write_ok=write_ok, error=error)
        return write_ok

    def write_manifest(self) -> bool:
        """manifest を JSON で書き出す。scan 完了時に件数・欠落・書込み失敗を残す。"""
        if not (self.enabled and self._path is not None):
            return False
        manifest_path = self._path.with_name(MANIFEST_FILENAME)
        try:
            with self._lock:
                data = self.manifest.to_dict()
                data["scan_id"] = self.scan_id
                data["ledger"] = LEDGER_FILENAME
                data["recovery_failed"] = self._recovery_failed
            manifest_path.write_text(
                json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            return True
        except OSError:
            return False
