"""probe 証跡台帳の recorder（0032-B・append-only・I/O 分離）。

[0032-A (#118)](probe_ledger.py) の純粋 schema を使い、実際の試行を **append-only な正本**
`probe_attempts.jsonl` へ記録する recorder を提供する。scan 内で単調増加する attempt_id を
払い出し、outcome/role 別の件数と **書込み失敗** を manifest に残す。

最上位契約（Task 0032）:
- **No evidence, no COMPLETE**: 必須証跡の書込みに失敗したら握りつぶさず manifest に error を
  残す（`append` は False を返し、`had_write_error` が立つ）。scan 完了判定はこれを見る。
- **Evidence for every outcome**: matched だけでなく no-match/blocked/skipped/timeout/error も
  記録する（呼び出し側が outcome を付けて append する）。

I/O（ファイル追記・manifest 書出し）はここに閉じ、判定・件数ロジックは純粋な
`LedgerManifest`（下）と `probe_ledger` の純粋関数へ委譲する（I/O と判定の分離規約）。
recorder を scanner/engine の全 transport 送信経路へ配線するのは後続増分（0032-C）。
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


@dataclass
class LedgerManifest:
    """台帳の集計（純粋・I/O 非依存）。件数・欠落・書込み失敗を保持し 0 Finding を安全へ丸めない。"""

    total: int = 0
    by_role: dict = field(default_factory=dict)
    by_outcome: dict = field(default_factory=dict)
    write_errors: list = field(default_factory=list)

    def record(self, role: ProbeRole, outcome: Optional[ProbeOutcome], *, write_ok: bool,
               error: str = "") -> None:
        """1 試行を集計へ反映する（純粋）。write_ok=False は欠落として error を残す。"""
        self.total += 1
        role_key = role.value if isinstance(role, ProbeRole) else str(role)
        self.by_role[role_key] = self.by_role.get(role_key, 0) + 1
        out_key = (outcome.value if isinstance(outcome, ProbeOutcome)
                   else (str(outcome) if outcome else "unrecorded"))
        self.by_outcome[out_key] = self.by_outcome.get(out_key, 0) + 1
        if not write_ok:
            self.write_errors.append(error or "write_failed")

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
    `append` は JSONL 1 行を追記し、失敗しても例外を投げず manifest に error を残して False を返す
    （証跡の欠落を可視化するため）。
    """

    def __init__(self, output_dir, scan_id: str, *, enabled: bool = True) -> None:
        self.scan_id = scan_id
        self.enabled = enabled
        self._seq = 0
        self._lock = threading.Lock()
        self.manifest = LedgerManifest()
        self._path: Optional[Path] = None
        if enabled and output_dir:
            self._path = Path(output_dir) / LEDGER_FILENAME
            # resume: 既存台帳から seq と manifest を復元してから新規試行を受ける
            # （attempt_id の重複＝相関 ID 衝突と、post-resume だけの過少 manifest を防ぐ）。
            self._restore_from_existing()

    @property
    def path(self) -> Optional[Path]:
        return self._path

    def _restore_from_existing(self) -> None:
        """既存台帳から seq/manifest を再構築する（resume 安定）。

        3 点を守る:
        - **不完全な末尾行の修復**: 前 append が改行前に中断すると末尾が partial JSON になる。
          次の append がそこへ連結すると 1 行が壊れるため、restore 時に最後の改行以降を truncate
          して行境界を清潔にする（partial な試行は永続化未完＝正本から落として良い）。
        - **seq 継承**: 有効行の attempt_id 最大 seq を継ぐ（相関 ID 重複を防ぐ）。
        - **prior write error の継承**: 前 run の manifest に残る write_errors を merge する。
          jsonl の成功行だけから作ると had_write_error=False になり No-evidence-no-COMPLETE gate を
          すり抜けるため（成功行は file に、失敗行は manifest にしか無い）。
        壊れた行は best-effort でスキップ。"""
        if self._path is None:
            return
        # 1) jsonl が有れば: 不完全な末尾行を truncate して行境界を修復＋seq/manifest 再構築
        if self._path.exists():
            try:
                data = self._path.read_bytes()
            except OSError:
                data = b""
            if data and not data.endswith(b"\n"):
                nl = data.rfind(b"\n")
                try:
                    with open(self._path, "rb+") as fh:
                        fh.truncate(nl + 1)  # nl==-1 なら 0（全体が partial）
                except OSError:
                    pass
            max_seq = 0
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
                        # 既存レコードは永続化済み＝write_ok。role/outcome は文字列のまま集計。
                        self.manifest.record(
                            rec.get("role", ""), rec.get("outcome"), write_ok=True
                        )
                self._seq = max_seq
            except OSError:
                pass
        # 2) 前 run の manifest から write_errors を継承（jsonl の有無に関わらず）。
        #    全 append 失敗で jsonl が無くても、証跡欠落を resume で消さない。
        manifest_path = self._path.with_name(MANIFEST_FILENAME)
        if manifest_path.exists():
            try:
                prior = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                prior = None
            if isinstance(prior, dict):
                for err in prior.get("write_errors", []) or []:
                    self.manifest.write_errors.append(err)
                    self.manifest.total += 1  # 失敗試行も総数へ（file には無い）

    def next_attempt_id(self) -> str:
        """次の attempt_id を払い出す（単調増加・決定論・thread-safe）。"""
        with self._lock:
            self._seq += 1
            return derive_attempt_id(self.scan_id, self._seq)

    def append(self, record: ProbeAttemptRecord) -> bool:
        """試行レコードを台帳へ追記する。成功で True。失敗は manifest に残し False（例外は投げない）。

        無効（enabled=False / 出力先なし）のときは何もしない no-op で True を返す（operator の
        選択であって失敗ではない＝manifest も更新しない）。"""
        if not (self.enabled and self._path is not None):
            return True
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
            manifest_path.write_text(
                json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            return True
        except OSError:
            return False
