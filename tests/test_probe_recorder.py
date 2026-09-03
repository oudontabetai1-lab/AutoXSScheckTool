"""probe 台帳 recorder のユニットテスト（0032-B・簡素化 durability モデル）。

単一 source（jsonl）＋write 失敗＝quarantine の規律を固定する:
attempt_id 決定論・append-only 追記・manifest 集計・**write 失敗で quarantine・以後 append 拒否**・
resume 復元（seq/内訳）・crash 耐久（末尾修復・非 object・破損 manifest は note_gap で evidence
incomplete、crash させない）・並列 thread-safe。
"""
import json
import threading

from wscan.probe_ledger import (
    ProbeAttemptRecord,
    ProbeOutcome,
    ProbeRole,
    RequestRecord,
    Transport,
)
from wscan.probe_recorder import (
    LEDGER_FILENAME,
    MANIFEST_FILENAME,
    LedgerManifest,
    ProbeLedger,
)


def _rec(ledger, role, outcome=None):
    return ProbeAttemptRecord(
        scan_id=ledger.scan_id, attempt_id=ledger.next_attempt_id(),
        role=role, check="xss", outcome=outcome,
        request=RequestRecord(method="GET", url="http://h/a", transport=Transport.HTTPX),
    )


# ── basics ────────────────────────────────────────────────────────────────
def test_attempt_id_monotonic_and_deterministic(tmp_path):
    led = ProbeLedger(tmp_path, "scanA")
    assert led.next_attempt_id() == "scanA:000001"
    assert led.next_attempt_id() == "scanA:000002"


def test_append_writes_jsonl_lines(tmp_path):
    led = ProbeLedger(tmp_path, "s")
    assert led.append(_rec(led, ProbeRole.BASELINE, ProbeOutcome.NO_MATCH))
    assert led.append(_rec(led, ProbeRole.ATTACK, ProbeOutcome.MATCHED))
    lines = [json.loads(l) for l in (tmp_path / LEDGER_FILENAME)
             .read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 2
    assert lines[0]["role"] == "baseline" and lines[1]["outcome"] == "matched"


def test_manifest_tallies_role_and_outcome(tmp_path):
    led = ProbeLedger(tmp_path, "s")
    led.append(_rec(led, ProbeRole.BASELINE, ProbeOutcome.NO_MATCH))
    led.append(_rec(led, ProbeRole.ATTACK, ProbeOutcome.MATCHED))
    led.append(_rec(led, ProbeRole.ATTACK, ProbeOutcome.BLOCKED))
    m = led.manifest.to_dict()
    assert m["total"] == 3
    assert m["by_role"] == {"baseline": 1, "attack": 2}
    assert m["by_outcome"] == {"no_match": 1, "matched": 1, "blocked": 1}
    assert m["had_write_error"] is False


def test_disabled_ledger_is_noop(tmp_path):
    led = ProbeLedger(tmp_path, "s", enabled=False)
    assert led.append(_rec(led, ProbeRole.ATTACK, ProbeOutcome.MATCHED)) is True
    assert not (tmp_path / LEDGER_FILENAME).exists()
    assert led.manifest.total == 0


def test_write_manifest_atomic_leaves_no_tmp(tmp_path):
    led = ProbeLedger(tmp_path, "s")
    led.append(_rec(led, ProbeRole.VERIFY, ProbeOutcome.MATCHED))
    assert led.write_manifest() is True
    assert (tmp_path / MANIFEST_FILENAME).exists()
    assert not (tmp_path / (MANIFEST_FILENAME + ".tmp")).exists()
    data = json.loads((tmp_path / MANIFEST_FILENAME).read_text(encoding="utf-8"))
    assert data["total"] == 1 and data["evidence_incomplete"] is False


# ── write failure → quarantine ──────────────────────────────────────────────
def test_write_failure_quarantines_and_blocks(tmp_path):
    # 親 dir 不在の出力先＝open が OSError → quarantine、以後 append は拒否
    led = ProbeLedger(tmp_path / "does_not_exist", "s")
    assert led.append(_rec(led, ProbeRole.ATTACK, ProbeOutcome.MATCHED)) is False
    assert led.quarantined is True
    assert led.evidence_incomplete is True
    assert led.append(_rec(led, ProbeRole.ATTACK, ProbeOutcome.NO_MATCH)) is False
    assert any(e["error"] == "ledger_quarantined" for e in led.manifest.write_errors)


def test_ledger_manifest_pure_record_and_note_gap():
    m = LedgerManifest()
    m.record(ProbeRole.ATTACK, ProbeOutcome.MATCHED, write_ok=True)
    m.record(ProbeRole.ATTACK, None, write_ok=False, error="disk full")
    assert m.total == 2
    assert m.by_outcome["matched"] == 1 and m.by_outcome["unrecorded"] == 1
    assert m.had_write_error
    assert m.write_errors[-1] == {"error": "disk full", "role": "attack", "outcome": "unrecorded"}
    before = m.total
    m.note_gap("prior_run_evidence_incomplete")
    assert m.total == before and m.had_write_error  # 件数は動かさず gate を立てる


# ── resume ──────────────────────────────────────────────────────────────────
def test_resume_restores_sequence_and_manifest(tmp_path):
    led1 = ProbeLedger(tmp_path, "sResume")
    led1.append(_rec(led1, ProbeRole.BASELINE, ProbeOutcome.NO_MATCH))
    led1.append(_rec(led1, ProbeRole.ATTACK, ProbeOutcome.MATCHED))
    led1.append(_rec(led1, ProbeRole.ATTACK, ProbeOutcome.BLOCKED))
    led2 = ProbeLedger(tmp_path, "sResume")
    assert led2.next_attempt_id() == "sResume:000004"
    m = led2.manifest.to_dict()
    assert m["total"] == 3
    assert m["by_role"] == {"baseline": 1, "attack": 2}
    assert m["by_outcome"] == {"no_match": 1, "matched": 1, "blocked": 1}


def test_resume_no_duplicate_ids(tmp_path):
    led1 = ProbeLedger(tmp_path, "s")
    for _ in range(2):
        led1.append(_rec(led1, ProbeRole.ATTACK, ProbeOutcome.MATCHED))
    led2 = ProbeLedger(tmp_path, "s")
    led2.append(_rec(led2, ProbeRole.ATTACK, ProbeOutcome.NO_MATCH))
    ids = [json.loads(l)["attempt_id"]
           for l in (tmp_path / LEDGER_FILENAME).read_text(encoding="utf-8").splitlines() if l.strip()]
    assert ids == ["s:000001", "s:000002", "s:000003"]
    assert len(ids) == len(set(ids))


def test_resume_repairs_invalid_tail(tmp_path):
    path = tmp_path / LEDGER_FILENAME
    path.write_bytes(
        b'{"scan_id":"s","attempt_id":"s:000001","role":"attack","outcome":"matched"}\n'
        b'{"attempt_id":"s:000002","role":"attack"'  # 不完全
    )
    led = ProbeLedger(tmp_path, "s")
    assert led.next_attempt_id() == "s:000002"
    led.append(_rec(led, ProbeRole.ATTACK, ProbeOutcome.NO_MATCH))
    lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    for l in lines:
        json.loads(l)
    assert len(lines) == 2


def test_resume_keeps_complete_tail_without_newline(tmp_path):
    path = tmp_path / LEDGER_FILENAME
    path.write_bytes(
        b'{"scan_id":"s","attempt_id":"s:000001","role":"attack","outcome":"matched"}\n'
        b'{"scan_id":"s","attempt_id":"s:000002","role":"attack","outcome":"no_match"}'
    )
    led = ProbeLedger(tmp_path, "s")
    assert led.next_attempt_id() == "s:000003"
    lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 2 and json.loads(lines[1])["attempt_id"] == "s:000002"


def test_resume_skips_non_object_json_without_crash(tmp_path):
    (tmp_path / LEDGER_FILENAME).write_text(
        'null\n[]\n"str"\n{"scan_id":"s","attempt_id":"s:000003","role":"attack","outcome":"matched"}\n',
        encoding="utf-8")
    led = ProbeLedger(tmp_path, "s")
    assert led.next_attempt_id() == "s:000004"
    assert led.manifest.to_dict()["total"] == 1
    # 破損/非 object 行は証跡欠落＝gate を倒す（Codex P1）
    assert led.evidence_incomplete is True
    assert any(e["error"] == "ledger_rows_skipped_on_resume" for e in led.manifest.write_errors)


def test_resume_unreadable_ledger_quarantines(tmp_path):
    (tmp_path / LEDGER_FILENAME).mkdir()
    led = ProbeLedger(tmp_path, "s")
    assert led.quarantined is True and led.evidence_incomplete is True
    assert led.append(_rec(led, ProbeRole.ATTACK, ProbeOutcome.MATCHED)) is False


# ── resume: 前 run の不完全さ/破損 manifest を crash させず evidence_incomplete に ──
def test_resume_prior_incomplete_preserves_gate(tmp_path):
    (tmp_path / LEDGER_FILENAME).write_text(
        '{"scan_id":"s","attempt_id":"s:000001","role":"attack","outcome":"matched"}\n', encoding="utf-8")
    (tmp_path / MANIFEST_FILENAME).write_text(json.dumps({
        "total": 2, "write_errors": [{"error": "disk full", "role": "attack", "outcome": "matched"}],
    }), encoding="utf-8")
    led = ProbeLedger(tmp_path, "s")
    assert led.evidence_incomplete is True         # gate をすり抜けさせない
    assert led.next_attempt_id() == "s:000003"      # seq は prior total を継ぐ


def test_resume_detects_missing_rows(tmp_path):
    # manifest total > 実在 jsonl 行＝行が失われている → evidence_incomplete（Codex P1）
    (tmp_path / LEDGER_FILENAME).write_text(
        '{"scan_id":"s","attempt_id":"s:000001","role":"attack","outcome":"matched"}\n', encoding="utf-8")
    (tmp_path / MANIFEST_FILENAME).write_text(json.dumps({"total": 3, "write_errors": []}),
                                              encoding="utf-8")
    led = ProbeLedger(tmp_path, "s")
    assert led.evidence_incomplete is True
    assert any(e["error"] == "ledger_rows_missing_on_resume" for e in led.manifest.write_errors)


def test_resume_non_object_manifest_marks_incomplete(tmp_path):
    # 非 object manifest（[]/null）で crash せず evidence_incomplete（Codex P2）
    (tmp_path / MANIFEST_FILENAME).write_text("[]", encoding="utf-8")
    led = ProbeLedger(tmp_path, "s")
    assert led.evidence_incomplete is True
    assert any(e["error"] == "prior_manifest_not_object" for e in led.manifest.write_errors)


def test_resume_malformed_manifest_total_marks_incomplete(tmp_path):
    (tmp_path / MANIFEST_FILENAME).write_text(
        json.dumps({"total": "abc", "write_errors": []}), encoding="utf-8")
    led = ProbeLedger(tmp_path, "s")
    assert any(e["error"] == "prior_manifest_bad_total" for e in led.manifest.write_errors)


# ── concurrency ─────────────────────────────────────────────────────────────
def test_concurrent_appends_are_thread_safe(tmp_path):
    led = ProbeLedger(tmp_path, "s")

    def worker():
        for _ in range(20):
            led.append(_rec(led, ProbeRole.ATTACK, ProbeOutcome.MATCHED))

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    lines = [l for l in (tmp_path / LEDGER_FILENAME).read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 120
    ids = [json.loads(l)["attempt_id"] for l in lines]
    assert len(ids) == len(set(ids))


def test_manifest_write_failure_marks_incomplete(tmp_path):
    # 最終 manifest 書出しが失敗したら evidence_incomplete を立てる（Codex P1）
    led = ProbeLedger(tmp_path, "s")
    led.append(_rec(led, ProbeRole.ATTACK, ProbeOutcome.MATCHED))
    # manifest の出力先ディレクトリを消して write を失敗させる
    import shutil
    shutil.rmtree(tmp_path)
    assert led.write_manifest() is False
    assert led.evidence_incomplete is True


def test_resume_non_utf8_manifest_handled(tmp_path):
    # 非 UTF-8 manifest でも crash せず prior_manifest_unreadable（UnicodeDecodeError は ValueError 系）
    (tmp_path / MANIFEST_FILENAME).write_bytes(b"\xff\xfe not utf8 \x80")
    led = ProbeLedger(tmp_path, "s")  # crash しない
    assert led.evidence_incomplete is True
    assert any(e["error"] == "prior_manifest_unreadable" for e in led.manifest.write_errors)


def test_truncated_tail_marks_evidence_gap(tmp_path):
    # 不完全な末尾断片を truncate＝実行済み probe の証跡喪失→evidence_incomplete（Codex P1）
    path = tmp_path / LEDGER_FILENAME
    path.write_bytes(
        b'{"scan_id":"s","attempt_id":"s:000001","role":"attack","outcome":"matched"}\n'
        b'{"scan_id":"s","attempt_id":"s:000002","role":"att'  # 不完全断片
    )
    led = ProbeLedger(tmp_path, "s")
    assert led.evidence_incomplete is True
    assert any(e["error"] == "ledger_tail_truncated" for e in led.manifest.write_errors)


def test_schema_invalid_rows_are_gaps(tmp_path):
    # {} / foreign scan_id / 壊れ attempt_id / 語彙外 role は成功に数えず gap（Codex P1）
    (tmp_path / LEDGER_FILENAME).write_text(
        '{}\n'
        '{"scan_id":"OTHER","attempt_id":"x:000001","role":"attack"}\n'          # foreign scan
        '{"scan_id":"s","attempt_id":"nobadseq","role":"attack"}\n'              # 壊れ id
        '{"scan_id":"s","attempt_id":"s:000002","role":"bogus"}\n'               # 語彙外 role
        '{"scan_id":"s","attempt_id":"s:000003","role":"attack","outcome":"matched"}\n',  # valid
        encoding="utf-8")
    led = ProbeLedger(tmp_path, "s")
    assert led.manifest.to_dict()["total"] == 1        # valid 1 件のみ成功計上
    assert led.evidence_incomplete is True             # 破損行あり＝gate
    assert led.next_attempt_id() == "s:000004"


def test_ledger_row_with_bad_utf8_quarantines(tmp_path):
    # jsonl 行の不正バイト列で iteration が UnicodeDecodeError→crash させず quarantine（Codex P2）
    (tmp_path / LEDGER_FILENAME).write_bytes(
        b'{"scan_id":"s","attempt_id":"s:000001","role":"attack","outcome":"matched"}\n'
        b'{"bad": "\xff\xfe not utf8"}\n'
    )
    led = ProbeLedger(tmp_path, "s")  # crash しない
    assert led.quarantined is True and led.evidence_incomplete is True
    assert led.append(_rec(led, ProbeRole.ATTACK, ProbeOutcome.MATCHED)) is False


def test_manifest_write_failure_flag_clears_on_success(tmp_path):
    # 一過性の manifest 書出し失敗→回復（retry 成功）で sticky flag が解除される（Codex P1）
    led = ProbeLedger(tmp_path, "s")
    led.append(_rec(led, ProbeRole.ATTACK, ProbeOutcome.MATCHED))
    (tmp_path / MANIFEST_FILENAME).mkdir()          # os.replace 先が dir＝失敗
    assert led.write_manifest() is False
    assert led.evidence_incomplete is True
    (tmp_path / MANIFEST_FILENAME).rmdir()          # 障害解消
    assert led.write_manifest() is True
    assert led.evidence_incomplete is False         # 回復＝incomplete を引きずらない


def test_foreign_attempt_id_prefix_rejected(tmp_path):
    # attempt_id の prefix が scan_id と一致しない行は不正＝gap（Codex P1）
    (tmp_path / LEDGER_FILENAME).write_text(
        '{"scan_id":"s","attempt_id":"other:999999","role":"attack","outcome":"matched"}\n'
        '{"scan_id":"s","attempt_id":"s:000001","role":"attack","outcome":"matched"}\n',
        encoding="utf-8")
    led = ProbeLedger(tmp_path, "s")
    assert led.manifest.to_dict()["total"] == 1     # foreign prefix は数えない
    assert led.evidence_incomplete is True
    assert led.next_attempt_id() == "s:000002"


def test_append_lone_surrogate_quarantines(tmp_path):
    # 文字列フィールドの lone surrogate で encode 失敗→crash させず quarantine（Codex P2）
    led = ProbeLedger(tmp_path, "s")
    bad = ProbeAttemptRecord(
        scan_id="s", attempt_id=led.next_attempt_id(), role=ProbeRole.ATTACK,
        rationale="lonely \ud800 surrogate")
    assert led.append(bad) is False
    assert led.quarantined is True and led.evidence_incomplete is True


def test_resume_detects_sequence_hole(tmp_path):
    # 連番の穴（:000001 が無く :000002 のみ）＝並列採番後の crash 等→evidence_incomplete（Codex P1）
    (tmp_path / LEDGER_FILENAME).write_text(
        '{"scan_id":"s","attempt_id":"s:000002","role":"attack","outcome":"matched"}\n',
        encoding="utf-8")
    led = ProbeLedger(tmp_path, "s")
    assert led.evidence_incomplete is True
    assert any(e["error"] == "ledger_sequence_hole" for e in led.manifest.write_errors)


def test_resume_rejects_foreign_outcome(tmp_path):
    # 語彙外 outcome の行は成功に数えず gap（Codex P1）
    (tmp_path / LEDGER_FILENAME).write_text(
        '{"scan_id":"s","attempt_id":"s:000001","role":"attack","outcome":"bogus"}\n',
        encoding="utf-8")
    led = ProbeLedger(tmp_path, "s")
    assert led.manifest.to_dict()["total"] == 0       # 成功に数えない
    assert led.evidence_incomplete is True


def test_manifest_retry_persists_complete_state(tmp_path):
    # 一過性の manifest 書出し失敗→retry 成功で、永続化 manifest は complete（Codex P2）
    led = ProbeLedger(tmp_path, "s")
    led.append(_rec(led, ProbeRole.ATTACK, ProbeOutcome.MATCHED))
    led._manifest_write_failed = True  # 直前の write_manifest が一過性失敗したと仮定
    assert led.write_manifest() is True
    assert led.evidence_incomplete is False           # 回復＝complete
    data = json.loads((tmp_path / MANIFEST_FILENAME).read_text(encoding="utf-8"))
    assert data["evidence_incomplete"] is False        # 永続化された manifest も complete


def test_manifest_encode_failure_marks_incomplete(tmp_path):
    # scan_id に lone surrogate → write_text が UnicodeEncodeError → incomplete（crash させない）（Codex P2）
    led = ProbeLedger(tmp_path, "s\ud800bad")
    led.append(_rec(led, ProbeRole.ATTACK, ProbeOutcome.MATCHED))
    assert led.write_manifest() is False
    assert led.evidence_incomplete is True
