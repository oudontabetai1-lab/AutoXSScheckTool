"""全 probe 証跡台帳の schema と純粋ヘルパ（0032-A・純粋・加算的）。

Task 0032「全 probe 証跡台帳と LLM grounding を検査の正本にする」の第一増分。
`discover → baseline/control → attack → observe → verify` の全実行経路を**一つの試行 ID で
結ぶ append-only な正本**（`probe_attempts.jsonl`）の**データ契約**を定義する。本モジュールは
**まだ scanner/engine へ配線しない**（schema＋直列化＋redaction＋hash の純粋部分のみ）。

最上位契約（Task 0032）のうち本増分が担う土台:
- role/outcome を正規化した語彙（`ProbeRole`/`ProbeOutcome`）＝比較対象と結果を後から監査可能に。
- request/response は **redact 済み excerpt＋body hash＋length** を持つ（Privacy is part of evidence
  integrity：token/Cookie/secret を無制限保存しない）。
- 相関 ID（scan/attempt/parent/hypothesis、baseline/control attempt ids）で因果を結ぶ。
- JSONL 1 行へ決定論的に直列化（正本 `probe_attempts.jsonl`）。

`wscan/verification_model.py`（MODEL-001a）との関係: あちらの軽量な in-flow 型に対し、本モジュールの
`ProbeAttemptRecord` は**永続・相関付きの台帳レコード**。Hypothesis/VerificationResult は将来
この attempt ID を参照して confirmed へ昇格する（No correlation, no confirmed）。

I/O（ファイル追記・実際の redaction ポリシー拡張・recorder 配線）は後続増分。ここは純粋関数のみ。
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from wscan.request_logger import is_sensitive_header, redact_text, redact_url


class ProbeRole(str, Enum):
    """試行の役割。比較基準(baseline/control)と注入(attack)、検証(verify)を区別する。"""

    DISCOVER = "discover"
    BASELINE = "baseline"
    CONTROL = "control"
    ATTACK = "attack"
    VERIFY = "verify"
    CLEANUP = "cleanup"


class ProbeOutcome(str, Enum):
    """試行の結果分類。Finding だけでなく非検出・失敗・未実行も明示する（silent 偽陰性防止）。"""

    MATCHED = "matched"                        # 脆弱性シグナル一致
    NO_MATCH = "no_match"                       # 送信したがシグナルなし
    BLOCKED = "blocked"                         # WAF/フィルタ等でブロック
    SKIPPED = "skipped"                         # 方針/gate で意図的にスキップ
    TIMEOUT = "timeout"                         # 応答なし・時間切れ
    TRANSPORT_ERROR = "transport_error"         # 接続/送信失敗
    VERIFICATION_ERROR = "verification_error"   # 検証段の失敗（再現不能でなく実行失敗）
    UNEXECUTABLE = "unexecutable"               # template 不在等で送信不能


class Transport(str, Enum):
    """送信路。全 transport を同じ台帳へ通すための正規化語彙。"""

    HTTPX = "httpx"
    PLAYWRIGHT = "playwright"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    OOB = "oob"
    DOM = "dom"


def sha256_hex(body) -> str:
    """body（str/bytes/None）の SHA-256 16 進。証跡の完全性検証・重複検出に使う純粋関数。"""
    if body is None:
        return ""
    if isinstance(body, str):
        body = body.encode("utf-8", "replace")
    return hashlib.sha256(body).hexdigest()


def body_length(body) -> int:
    """body のバイト長（str は utf-8 換算）。redact 前の実長を保つ。"""
    if body is None:
        return 0
    if isinstance(body, str):
        return len(body.encode("utf-8", "replace"))
    return len(body)


def redact_excerpt(text: Optional[str], cap: int = 512) -> str:
    """機微値を伏せ、長さを cap で切詰めた excerpt を返す（純粋・保守的）。

    Privacy is part of evidence integrity: token/Cookie/secret を素で残さない。redaction は
    **`request_logger` の正典**（#90 R13）へ委譲する＝独自の機微集合/正規表現を持たない:
      - ヘッダ行（`Name: value`）は `is_sensitive_header`（静的＋runtime 登録＝カスタム認証ヘッダも）で
        名前判定し値を伏せる。
      - それ以外の行は `redact_text`（urlencoded の `key=value` と **JSON の `"key":"value"`** 両対応）
        で機微ボディ値を伏せる。
    最後に cap で切詰める。redaction ポリシー拡張は正典側で一元的に行う。"""
    if not text:
        return ""
    lines_out = []
    for line in text.splitlines():
        name, sep, rest = line.partition(":")
        if sep and is_sensitive_header(name.strip()):
            lines_out.append(f"{name}:{' ' if rest[:1] == ' ' else ''}<redacted>")
            continue
        lines_out.append(redact_text(line))
    redacted = "\n".join(lines_out)
    if len(redacted) > cap:
        redacted = redacted[:cap] + "…"
    return redacted


@dataclass(frozen=True)
class RequestRecord:
    """送信リクエストの証跡（redact 済み）。body は excerpt＋hash＋length で保持する。"""

    method: str
    url: str                       # canonical URL
    transport: Transport
    headers_excerpt: str = ""      # redact 済み
    body_excerpt: str = ""         # redact 済み
    body_hash: str = ""
    body_length: int = 0
    sent: bool = False             # 送信成否（transport 成功）


@dataclass(frozen=True)
class ResponseRecord:
    """応答の証跡（redact 済み）。DOM/dialog/OOB/state 差の要約も持つ。"""

    status: Optional[int] = None
    final_url: str = ""
    headers_excerpt: str = ""
    body_excerpt: str = ""
    body_hash: str = ""
    body_length: int = 0
    elapsed_ms: Optional[float] = None
    dom_diff: str = ""             # DOM/state 差の要約
    dialog: bool = False           # JS dialog 発火
    oob: bool = False              # OOB 到達


@dataclass(frozen=True)
class ProbeAttemptRecord:
    """append-only な probe 試行の台帳レコード（正本）。純粋・不変・JSON 直列化可。

    相関 ID で `discover→baseline/control→attack→verify` を後から再現・説明できるようにする。
    outcome/decision_* により「なぜその判定か」を保存する（No correlation, no confirmed）。"""

    scan_id: str
    attempt_id: str
    role: ProbeRole
    parent_id: str = ""
    hypothesis_id: str = ""
    check: str = ""
    wave: str = ""
    actor: str = ""                # scanner 名 / "agent" / "llm"
    state_profile: str = ""        # unrestricted / controlled-write / read-only
    injection_key: str = ""        # InjectionPoint stable key
    baseline_attempt_ids: tuple[str, ...] = ()
    control_attempt_ids: tuple[str, ...] = ()
    started_at: Optional[float] = None   # epoch 秒（caller 注入・純粋性維持）
    ended_at: Optional[float] = None
    request: Optional[RequestRecord] = None
    response: Optional[ResponseRecord] = None
    outcome: Optional[ProbeOutcome] = None
    decision_rule: str = ""        # 判定 rule 名
    decision_version: str = ""     # 判定 rule version
    rationale: str = ""            # 判定根拠（redact 済み）

    @property
    def correlated(self) -> bool:
        """confirmed 昇格の前提: baseline か control の attempt を参照できるか。"""
        return bool(self.baseline_attempt_ids or self.control_attempt_ids)


def derive_attempt_id(scan_id: str, seq: int) -> str:
    """scan 内で単調増加する連番から決定論的に attempt_id を作る（純粋・resume 安定）。

    乱数/時刻を使わない＝同じ (scan_id, seq) は常に同じ ID（checkpoint/resume で因果を保つ）。"""
    return f"{scan_id}:{seq:06d}"


def to_jsonl_line(record: ProbeAttemptRecord) -> str:
    """台帳レコードを JSONL の 1 行へ直列化する（純粋）。

    Enum は str 継承のため値へ直列化される。改行を含まない 1 行を保証する。"""
    payload = dataclasses.asdict(record)
    # 永続化境界で URL クエリの機微値を伏せる（?access_token=... 等が redirect/callback/GET
    # probe から生で残らないように。正典 request_logger.redact_url へ委譲）。
    if payload.get("request") and payload["request"].get("url"):
        payload["request"]["url"] = redact_url(payload["request"]["url"])
    if payload.get("response") and payload["response"].get("final_url"):
        payload["response"]["final_url"] = redact_url(payload["response"]["final_url"])
    line = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    # 念のため（body_excerpt 等に改行が残っても）1 行不変条件を守る
    return line.replace("\n", "\\n")
