"""Agent Browser の監督状態・証跡・再開を担う薄いハーネス。

browser-use はブラウザ操作 executor として残し、このモジュールが run 全体の
step budget、進展停止、coverage、checkpoint、証跡完全性を管理する。モデルや
ブラウザへ依存しないため、replay/unit test で状態遷移を再現できる。
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterable

from wscan.request_logger import redact_text, redact_url


STATE_FILENAME = "agent_state.json"
TRACE_FILENAME = "agent_steps.jsonl"
MANIFEST_FILENAME = "agent_manifest.json"
SCHEMA_VERSION = 1


class AgentRunStatus(str, Enum):
    RUNNING = "running"
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    EVIDENCE_INCOMPLETE = "evidence_incomplete"
    CANCELLED = "cancelled"


class AgentPhase(str, Enum):
    INITIALIZING = "initializing"
    AUTHENTICATING = "authenticating"
    RECONNING = "reconning"
    EXECUTING = "executing"
    FINALIZING = "finalizing"


class AgentRole(str, Enum):
    AUTHENTICATOR = "authenticator"
    EXPLORER = "explorer"
    PROBE_SPECIALIST = "probe_specialist"
    VERIFIER = "verifier"
    ADVERSARIAL_REVIEWER = "adversarial_reviewer"


class WorkStatus(str, Enum):
    PLANNED = "planned"
    RUNNING = "running"
    COMPLETE = "complete"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"
    FAILED = "failed"


@dataclass
class AgentWorkItem:
    work_id: str
    role: AgentRole
    target: str
    check_type: str = ""
    status: WorkStatus = WorkStatus.PLANNED
    attempts: int = 0
    summary: str = ""

    def to_dict(self) -> dict:
        data = asdict(self)
        data["role"] = self.role.value
        data["status"] = self.status.value
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "AgentWorkItem":
        values = dict(data)
        values["role"] = AgentRole(values["role"])
        values["status"] = WorkStatus(values.get("status", "planned"))
        return cls(**values)


@dataclass(frozen=True)
class AgentRunSpec:
    mode: str
    target_url: str
    target_urls: tuple[str, ...]
    access_urls: tuple[str, ...]
    exclude_urls: tuple[str, ...]
    exclude_fields: tuple[str, ...]
    checks: tuple[str, ...]
    provider: str
    model: str
    max_steps: int

    def __post_init__(self) -> None:
        if self.max_steps < 1:
            raise ValueError("max_steps must be at least 1")

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def spec_hash(self) -> str:
        payload = json.dumps(
            self.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class AgentRunState:
    run_id: str
    spec_hash: str
    status: AgentRunStatus = AgentRunStatus.RUNNING
    phase: AgentPhase = AgentPhase.INITIALIZING
    consumed_steps: int = 0
    visited_urls: list[str] = field(default_factory=list)
    tested_targets: list[str] = field(default_factory=list)
    coverage_gaps: list[str] = field(default_factory=list)
    hypotheses_count: int = 0
    repeated_steps: int = 0
    stop_reason: str = ""
    last_error: str = ""
    evidence_errors: list[str] = field(default_factory=list)
    checkpoint_generation: int = 0
    work_queue: list[AgentWorkItem] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["status"] = self.status.value
        data["phase"] = self.phase.value
        data["work_queue"] = [item.to_dict() for item in self.work_queue]
        data["schema_version"] = SCHEMA_VERSION
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "AgentRunState":
        if data.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("unsupported agent checkpoint schema")
        values = dict(data)
        values.pop("schema_version", None)
        values["status"] = AgentRunStatus(values.get("status", "running"))
        values["phase"] = AgentPhase(values.get("phase", "initializing"))
        values["work_queue"] = [
            AgentWorkItem.from_dict(item) for item in values.get("work_queue", [])
        ]
        return cls(**values)


@dataclass(frozen=True)
class AgentStepRecord:
    run_id: str
    episode_id: str
    step_id: str
    global_step: int
    phase: str
    current_url: str
    proposed_actions: tuple[str, ...]
    executed_actions: tuple[str, ...]
    blocked_count: int
    repeat_signature: str
    repeated: bool
    timestamp: float

    def to_dict(self) -> dict:
        return asdict(self)


def _unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for raw in values:
        value = str(raw or "").strip()
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _redact_action(value) -> str:
    """action を決定論的な redact 済み短文へ変換する。"""
    if hasattr(value, "model_dump"):
        try:
            value = value.model_dump(exclude_unset=True)
        except Exception:
            value = str(type(value).__name__)
    try:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        text = str(value)
    return redact_text(text)[:1000]


def step_signature(url: str, actions: Iterable[str]) -> str:
    payload = json.dumps(
        {"url": redact_url(str(url or "").rstrip("/")), "actions": list(actions)},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()


class AgentHarness:
    """Agent run の append-only trace と atomic checkpoint を管理する。"""

    def __init__(
        self,
        output_dir: str | Path,
        spec: AgentRunSpec,
        *,
        resume: bool = False,
        repeat_threshold: int = 3,
        secret_values: Iterable[str] = (),
    ) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.spec = spec
        self.repeat_threshold = max(2, int(repeat_threshold))
        self.state_path = self.output_dir / STATE_FILENAME
        self.trace_path = self.output_dir / TRACE_FILENAME
        self.manifest_path = self.output_dir / MANIFEST_FILENAME
        self._base_consumed = 0
        self._last_signature = ""
        self._same_signature_count = 0
        self._evidence_failed = False
        self._secret_values = tuple(sorted(
            {str(value) for value in secret_values if str(value)}, key=len, reverse=True
        ))

        if resume:
            self.state = self._load_state()
            if self.state.spec_hash != spec.spec_hash:
                raise ValueError(
                    "Agent resume spec mismatch: target/provider/model/checks/max_steps "
                    "must match the original run"
                )
            self._base_consumed = self.state.consumed_steps
            if self.remaining_steps <= 0:
                raise ValueError("Agent resume has no remaining step budget")
            self.state.status = AgentRunStatus.RUNNING
            self.state.stop_reason = ""
            self.state.last_error = ""
            for item in self.state.work_queue:
                if item.status == WorkStatus.RUNNING:
                    item.status = WorkStatus.PLANNED
        else:
            if self.state_path.exists() or self.trace_path.exists():
                raise ValueError(
                    "Agent output already contains harness state; use --resume or a new output directory"
                )
            self.state = AgentRunState(
                run_id=f"agent-{uuid.uuid4().hex}", spec_hash=spec.spec_hash
            )
        self.checkpoint()

    @property
    def remaining_steps(self) -> int:
        return max(0, self.spec.max_steps - self.state.consumed_steps)

    @property
    def session_consumed_steps(self) -> int:
        """今回の process で消費した step 数（resume 前の分を除く）。"""
        return max(0, self.state.consumed_steps - self._base_consumed)

    @property
    def should_stop(self) -> bool:
        return bool(self.state.stop_reason) or self.remaining_steps <= 0

    def set_phase(self, phase: AgentPhase) -> None:
        self.state.phase = phase
        self.checkpoint()

    def resume_context(self) -> str:
        if not self._base_consumed:
            return ""
        visited = "\n".join(f"- {url}" for url in self.state.visited_urls[-30:])
        tested = "\n".join(f"- {item}" for item in self.state.tested_targets[-30:])
        return (
            "\n## Resume state\n"
            f"This is a resumed run. {self.remaining_steps} global steps remain.\n"
            "Already visited URLs (do not repeat without a concrete recovery reason):\n"
            f"{visited or '- (none)'}\n"
            "Already tested targets:\n"
            f"{tested or '- (none)'}\n"
        )

    def _redact_runtime(self, value: str) -> str:
        text = str(value or "")
        for secret in self._secret_values:
            text = text.replace(secret, "<redacted>")
        return text

    def enqueue(
        self,
        role: AgentRole,
        target: str,
        *,
        check_type: str = "",
    ) -> AgentWorkItem:
        """同じ役割・対象・検査の work item を重複なしで永続化する。"""
        raw_key = f"{role.value}\0{target}\0{check_type}"
        work_id = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:20]
        for item in self.state.work_queue:
            if item.work_id == work_id:
                return item
        item = AgentWorkItem(
            work_id=work_id,
            role=role,
            target=redact_url(str(target)),
            check_type=str(check_type),
        )
        self.state.work_queue.append(item)
        self.checkpoint()
        return item

    def next_work(self) -> AgentWorkItem | None:
        """未完了 work を安全優先順（認証→探索→検査→検証→レビュー）で返す。"""
        priority = {role: index for index, role in enumerate(AgentRole)}
        candidates = [
            item for item in self.state.work_queue
            if item.status == WorkStatus.PLANNED
            or (item.status == WorkStatus.INCONCLUSIVE and item.attempts < 2)
        ]
        if not candidates:
            return None
        item = min(candidates, key=lambda value: (priority[value.role], value.work_id))
        item.status = WorkStatus.RUNNING
        item.attempts += 1
        self.checkpoint()
        return item

    def finish_work(
        self,
        work_id: str,
        status: WorkStatus,
        *,
        summary: str = "",
    ) -> None:
        if status in {WorkStatus.PLANNED, WorkStatus.RUNNING}:
            raise ValueError("finish_work requires a terminal work status")
        for item in self.state.work_queue:
            if item.work_id == work_id:
                item.status = status
                item.summary = self._redact_runtime(redact_text(str(summary)))[:12000]
                self.checkpoint()
                return
        raise KeyError(work_id)

    @property
    def coverage_complete(self) -> bool:
        """強制確認対象が全て完了し、未解決 gap がない場合だけ真。"""
        return bool(self.state.work_queue) and not self.state.coverage_gaps and all(
            item.status == WorkStatus.COMPLETE for item in self.state.work_queue
        )

    def record_step(
        self,
        *,
        episode_id: str,
        local_step: int,
        url: str,
        proposed_actions: Iterable,
        executed_actions: Iterable,
        blocked_count: int = 0,
    ) -> AgentStepRecord:
        global_step = self._base_consumed + max(0, int(local_step))
        self.state.consumed_steps = min(self.spec.max_steps, max(
            self.state.consumed_steps, global_step
        ))
        safe_url = self._redact_runtime(redact_url(str(url or "")))
        proposed = tuple(
            self._redact_runtime(_redact_action(action)) for action in proposed_actions
        )
        executed = tuple(
            self._redact_runtime(_redact_action(action)) for action in executed_actions
        )
        signature = step_signature(safe_url, executed or proposed)
        if signature == self._last_signature:
            self._same_signature_count += 1
        else:
            self._last_signature = signature
            self._same_signature_count = 1
        repeated = self._same_signature_count >= self.repeat_threshold
        if repeated:
            self.state.repeated_steps += 1
            self.state.stop_reason = "loop_detected"
        if safe_url.startswith(("http://", "https://")):
            self.state.visited_urls = _unique([*self.state.visited_urls, safe_url])
        record = AgentStepRecord(
            run_id=self.state.run_id,
            episode_id=episode_id,
            step_id=f"{episode_id}:{global_step:06d}",
            global_step=global_step,
            phase=self.state.phase.value,
            current_url=safe_url,
            proposed_actions=proposed,
            executed_actions=executed,
            blocked_count=max(0, int(blocked_count)),
            repeat_signature=signature,
            repeated=repeated,
            timestamp=time.time(),
        )
        self._append_trace(record)
        self.checkpoint()
        return record

    def note_coverage(
        self,
        *,
        visited_urls: Iterable[str] = (),
        tested_targets: Iterable[str] = (),
        coverage_gaps: Iterable[str] = (),
        hypotheses_count: int | None = None,
    ) -> None:
        self.state.visited_urls = _unique([
            *self.state.visited_urls,
            *(redact_url(str(url)) for url in visited_urls),
        ])
        self.state.tested_targets = _unique([
            *self.state.tested_targets,
            *(redact_text(str(item))[:1000] for item in tested_targets),
        ])
        self.state.coverage_gaps = _unique(
            redact_text(str(item))[:1000] for item in coverage_gaps
        )
        if hypotheses_count is not None:
            self.state.hypotheses_count = max(0, int(hypotheses_count))
        self.checkpoint()

    def finalize(
        self,
        *,
        success: bool,
        coverage_complete: bool,
        error: str = "",
        cancelled: bool = False,
    ) -> AgentRunStatus:
        self.state.phase = AgentPhase.FINALIZING
        if cancelled:
            self.state.status = AgentRunStatus.CANCELLED
            self.state.stop_reason = self.state.stop_reason or "cancelled"
        elif error:
            self.state.status = AgentRunStatus.FAILED
            self.state.last_error = redact_text(str(error))[:1000]
        elif self._evidence_failed or self.state.evidence_errors:
            self.state.status = AgentRunStatus.EVIDENCE_INCOMPLETE
        elif success and coverage_complete and not self.state.coverage_gaps and not self.state.stop_reason:
            self.state.status = AgentRunStatus.COMPLETE
        else:
            self.state.status = AgentRunStatus.PARTIAL
            if not self.state.stop_reason:
                if self.remaining_steps <= 0:
                    self.state.stop_reason = "budget_exhausted"
                elif self.state.coverage_gaps:
                    self.state.stop_reason = "coverage_incomplete"
                else:
                    self.state.stop_reason = "agent_incomplete"
        self.checkpoint()
        self._write_manifest(coverage_complete=coverage_complete)
        return self.state.status

    def checkpoint(self) -> bool:
        self.state.checkpoint_generation += 1
        return self._atomic_write_json(self.state_path, self.state.to_dict())

    def _load_state(self) -> AgentRunState:
        if not self.state_path.exists():
            raise ValueError("Agent resume state was not found")
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeError) as exc:
            raise ValueError(f"Agent resume state is unreadable: {type(exc).__name__}") from exc
        if not isinstance(data, dict):
            raise ValueError("Agent resume state must be a JSON object")
        return AgentRunState.from_dict(data)

    def _append_trace(self, record: AgentStepRecord) -> None:
        if self._evidence_failed:
            return
        try:
            line = json.dumps(
                record.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
            with open(self.trace_path, "a", encoding="utf-8") as stream:
                stream.write(line + "\n")
                stream.flush()
                os.fsync(stream.fileno())
        except (OSError, UnicodeError, ValueError) as exc:
            self._note_evidence_error(f"trace_write:{type(exc).__name__}")

    def _atomic_write_json(self, path: Path, data: dict) -> bool:
        if self._evidence_failed and path == self.state_path:
            return False
        tmp_path = path.with_name(path.name + ".tmp")
        try:
            encoded = json.dumps(
                data, ensure_ascii=False, indent=2, sort_keys=True
            )
            with open(tmp_path, "w", encoding="utf-8") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp_path, path)
            return True
        except (OSError, UnicodeError, ValueError) as exc:
            self._note_evidence_error(f"checkpoint_write:{type(exc).__name__}")
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            return False

    def _note_evidence_error(self, error: str) -> None:
        self._evidence_failed = True
        if error not in self.state.evidence_errors:
            self.state.evidence_errors.append(error)

    def _write_manifest(self, *, coverage_complete: bool) -> None:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "run_id": self.state.run_id,
            "spec_hash": self.spec.spec_hash,
            "status": self.state.status.value,
            "resolved_provider": self.spec.provider,
            "resolved_model": self.spec.model,
            "max_steps": self.spec.max_steps,
            "consumed_steps": self.state.consumed_steps,
            "remaining_steps": self.remaining_steps,
            "visited_url_count": len(self.state.visited_urls),
            "tested_target_count": len(self.state.tested_targets),
            "hypotheses_count": self.state.hypotheses_count,
            "coverage_complete": bool(coverage_complete),
            "coverage_gaps": list(self.state.coverage_gaps),
            "stop_reason": self.state.stop_reason,
            "evidence_errors": list(self.state.evidence_errors),
            "work_items": [item.to_dict() for item in self.state.work_queue],
            "trace": TRACE_FILENAME,
            "checkpoint": STATE_FILENAME,
        }
        self._atomic_write_json(self.manifest_path, payload)
