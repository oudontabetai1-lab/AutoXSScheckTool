"""検証ライフサイクル型（0015 MODEL-001a・純粋・加算的）。

ADR-0016 / [[Designs/0015-data-model-and-output-contract]] の型分離のうち、**検証ライフサイクル型**
（観測→仮説→検証結果）を純粋な dataclass として定義する。本モジュールは**まだ engine/Finding へ
配線しない**（加算的な第一増分）。既存 `InjectionPoint`（注入点記述子）を土台に、`Finding` を将来
「確証済み出力」専用へ縮退させるための語彙を用意する。

設計思想（モード別品質基準）:
- **Agent/LLM 出力は `Hypothesis` で保持して捨てない**（ADR-0005 の「独自性を殺さない」）。
  `Finding` へは決定論 or 人手で**再現できた時だけ**昇格する（PLAN-002）＝未確証が確証件数を汚さない。
- 検証状態は `VerificationState` を正本にする（`scanners/base.py` の `verification_state` 文字列と一致）。

ブラウザ・HTTP 非依存＝ユニットテスト可能に保つ（判定/構造ロジックを I/O から分離する規約）。
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class VerificationState(str, Enum):
    """検証結果の正本 enum。値は `scanners/base.py` の `verification_state` 文字列と一致させる
    （`str` 継承で既存の文字列比較・JSON 直列化と後方互換：`VerificationState.REPRODUCED == "reproduced"`）。"""

    REPRODUCED = "reproduced"      # 隔離再現で確証（攻撃直後・新規/reset context）
    ASSUMED = "assumed"            # scan 時シグナルのみ・未再検証
    UNREPRODUCED = "unreproduced"  # 再現を試みたが再現せず
    SKIPPED = "skipped"            # 検証不能（unexecutable template 等）。penalize しない


class ProbeKind(str, Enum):
    """送信の種別。baseline/control は比較基準、probe/payload は注入。"""

    BASELINE = "baseline"
    CONTROL = "control"
    PROBE = "probe"
    PAYLOAD = "payload"


class HypothesisSource(str, Enum):
    """仮説の出自。確証の"質"はラベルで示す（決定論/LLM/Agent を視覚分離するため）。"""

    DETERMINISTIC = "deterministic"
    LLM = "llm"
    AGENT = "agent"


@dataclass(frozen=True)
class ProbeAttempt:
    """1回の送信（baseline/control/probe/payload）の記録。純粋・不変。

    `timestamp` は epoch 秒を **caller が注入**する（モジュール内で時刻を読まず純粋性を保つ）。
    transport 失敗時は `status=None`＋`error` に種別を残す（silent 偽陰性を作らない）。"""

    kind: ProbeKind
    url: str
    payload: str = ""
    status: Optional[int] = None      # HTTP status（transport 失敗時 None）
    response_snippet: str = ""        # 判定に使う応答断片（切詰め済み）
    error: str = ""                   # transport error 種別（あれば）
    timestamp: Optional[float] = None  # epoch 秒（caller 注入）

    @property
    def failed(self) -> bool:
        """transport 失敗（応答なし）か。status 無し かつ error あり を失敗とみなす。"""
        return self.status is None and bool(self.error)


@dataclass(frozen=True)
class Observation:
    """`ProbeAttempt` から純粋関数が抽出したシグナル（反射文脈/エラー/差分/dialog 等）。

    `probe_ref` は関連 `ProbeAttempt` の index（弱参照）。型の相互参照を避けて直列化を容易にする。"""

    kind: str                      # 例: "reflection" / "error" / "diff" / "dialog"
    detail: str = ""
    probe_ref: Optional[int] = None


@dataclass(frozen=True)
class Hypothesis:
    """「この注入点に脆弱性がありそう」という仮説。**捨てない**（ADR-0005 の独自性尊重）。

    `Finding` へは決定論 or 人手で再現できた時だけ昇格する（PLAN-002）。未確証でも別チャネルで
    全件提示するための語彙。`confidence` は 0.0–1.0（範囲外は不変条件違反として弾く）。"""

    check_type: str
    source: HypothesisSource
    confidence: float = 0.0
    rationale: str = ""
    observations: tuple[Observation, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0.0, 1.0], got {self.confidence!r}")


@dataclass(frozen=True)
class VerificationResult:
    """隔離再現の結果。`state` を正本にし、使った `ProbeAttempt` を参照する。"""

    state: VerificationState
    reproduced_by: tuple[ProbeAttempt, ...] = ()
    note: str = ""

    @property
    def confirmed(self) -> bool:
        """確証済み（reproduced）か。件数/SARIF/通知はこれを真とみなす。"""
        return self.state == VerificationState.REPRODUCED
