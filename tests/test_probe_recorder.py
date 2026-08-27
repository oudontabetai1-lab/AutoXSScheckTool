"""probe 台帳 recorder のユニットテスト（0032-B）。

attempt_id の決定論・append-only 追記・manifest 集計・**書込み失敗を握りつぶさない**を固定。
"""
import json

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


def test_attempt_id_monotonic_and_deterministic(tmp_path):
    led = ProbeLedger(tmp_path, "scanA")
    assert led.next_attempt_id() == "scanA:000001"
    assert led.next_attempt_id() == "scanA:000002"


def test_append_writes_jsonl_lines(tmp_path):
    led = ProbeLedger(tmp_path, "s")
    assert led.append(_rec(led, ProbeRole.BASELINE, ProbeOutcome.NO_MATCH))
    assert led.append(_rec(led, ProbeRole.ATTACK, ProbeOutcome.MATCHED))
    path = tmp_path / LEDGER_FILENAME
    lines = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
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


def test_write_failure_is_not_swallowed(tmp_path):
    # 親ディレクトリが存在しない出力先＝open が OSError → append は False、manifest に error
    bad_dir = tmp_path / "does_not_exist"
    led = ProbeLedger(bad_dir, "s")
    ok = led.append(_rec(led, ProbeRole.ATTACK, ProbeOutcome.MATCHED))
    assert ok is False
    assert led.manifest.had_write_error is True
    assert led.manifest.total == 1  # 欠落として計上（0 に丸めない）


def test_disabled_ledger_is_noop(tmp_path):
    led = ProbeLedger(tmp_path, "s", enabled=False)
    assert led.append(_rec(led, ProbeRole.ATTACK, ProbeOutcome.MATCHED)) is True
    assert not (tmp_path / LEDGER_FILENAME).exists()
    assert led.manifest.total == 0  # 無効時は集計しない（operator 選択＝失敗でない）


def test_write_manifest_file(tmp_path):
    led = ProbeLedger(tmp_path, "scanZ")
    led.append(_rec(led, ProbeRole.VERIFY, ProbeOutcome.MATCHED))
    assert led.write_manifest() is True
    data = json.loads((tmp_path / MANIFEST_FILENAME).read_text(encoding="utf-8"))
    assert data["scan_id"] == "scanZ"
    assert data["total"] == 1 and data["ledger"] == LEDGER_FILENAME


def test_ledger_manifest_pure_record():
    # LedgerManifest 単体（I/O 非依存）の集計・失敗計上
    m = LedgerManifest()
    m.record(ProbeRole.ATTACK, ProbeOutcome.MATCHED, write_ok=True)
    m.record(ProbeRole.ATTACK, None, write_ok=False, error="disk full")
    assert m.total == 2
    assert m.by_outcome["matched"] == 1 and m.by_outcome["unrecorded"] == 1
    assert m.had_write_error
    assert m.write_errors == [{"error": "disk full", "role": "attack", "outcome": "unrecorded"}]


def test_resume_restores_sequence_and_manifest(tmp_path):
    # 1st run: 3 試行を記録
    led1 = ProbeLedger(tmp_path, "sResume")
    led1.append(_rec(led1, ProbeRole.BASELINE, ProbeOutcome.NO_MATCH))
    led1.append(_rec(led1, ProbeRole.ATTACK, ProbeOutcome.MATCHED))
    led1.append(_rec(led1, ProbeRole.ATTACK, ProbeOutcome.BLOCKED))
    # resume: 同じ output dir / scan_id で再構築
    led2 = ProbeLedger(tmp_path, "sResume")
    # seq は継続＝重複 ID を出さない
    assert led2.next_attempt_id() == "sResume:000004"
    # manifest は既存3件を含む（post-resume だけの過少集計でない）
    m = led2.manifest.to_dict()
    assert m["total"] == 3
    assert m["by_role"] == {"baseline": 1, "attack": 2}
    assert m["by_outcome"] == {"no_match": 1, "matched": 1, "blocked": 1}


def test_resume_append_does_not_duplicate_ids(tmp_path):
    led1 = ProbeLedger(tmp_path, "s")
    for _ in range(2):
        led1.append(_rec(led1, ProbeRole.ATTACK, ProbeOutcome.MATCHED))
    led2 = ProbeLedger(tmp_path, "s")
    led2.append(_rec(led2, ProbeRole.ATTACK, ProbeOutcome.NO_MATCH))  # should be :000003
    import json as _json
    ids = [
        _json.loads(l)["attempt_id"]
        for l in (tmp_path / LEDGER_FILENAME).read_text(encoding="utf-8").splitlines() if l.strip()
    ]
    assert ids == ["s:000001", "s:000002", "s:000003"]
    assert len(ids) == len(set(ids))  # 重複なし


def test_resume_skips_corrupt_lines(tmp_path):
    path = tmp_path / LEDGER_FILENAME
    path.write_text('{"attempt_id":"s:000005","role":"attack","outcome":"matched"}\n'
                    'not-json-garbage\n', encoding="utf-8")
    led = ProbeLedger(tmp_path, "s")
    assert led.next_attempt_id() == "s:000006"   # 壊れ行は無視、最大 seq=5 を継承
    assert led.manifest.to_dict()["total"] == 1  # 有効行のみ集計


def test_resume_repairs_unterminated_tail(tmp_path):
    # 前 append が改行前に中断＝末尾 partial 行。次の append が壊れた行を作らないよう truncate。
    path = tmp_path / LEDGER_FILENAME
    path.write_bytes(
        b'{"attempt_id":"s:000001","role":"attack","outcome":"matched"}\n'
        b'{"attempt_id":"s:000002","role":"attack"'  # 改行なしの partial
    )
    led = ProbeLedger(tmp_path, "s")
    # partial は落ちるので seq は完全行の最大=1 を継ぐ→次は 000002
    assert led.next_attempt_id() == "s:000002"
    led.append(_rec(led, ProbeRole.ATTACK, ProbeOutcome.MATCHED))
    import json as _json
    lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    # 全行が有効 JSON（連結による破損なし）
    for l in lines:
        _json.loads(l)
    assert len(lines) == 2  # 完全行1 + 新規1（partial は truncate 済み）


def test_resume_preserves_prior_write_errors(tmp_path):
    # 前 run: append 失敗を記録し manifest を書き出す
    bad = tmp_path / "nope"
    led1 = ProbeLedger(bad, "s")
    assert led1.append(_rec(led1, ProbeRole.ATTACK, ProbeOutcome.MATCHED)) is False
    assert led1.manifest.had_write_error
    # manifest を書ける場所へ（jsonl は書けなかったが manifest は別途残ると想定）
    # ここでは手動で manifest を tmp_path に置いて resume 復元を検証
    import json as _json
    (tmp_path / MANIFEST_FILENAME).write_text(
        _json.dumps({"write_errors": ["OSError: disk full"], "total": 1}), encoding="utf-8")
    # resume: jsonl は空でも prior manifest の write_errors を継承（legacy 文字列は dict へ）
    led2 = ProbeLedger(tmp_path, "s")
    assert led2.manifest.had_write_error is True   # gate をすり抜けさせない
    assert any(e["error"] == "OSError: disk full" for e in led2.manifest.write_errors)
    assert led2.manifest.total == 1


def test_resume_keeps_complete_tail_without_newline(tmp_path):
    # 末尾が「改行なしだが完全な JSON レコード」なら truncate せず delimiter を補い残す（Codex P1）
    path = tmp_path / LEDGER_FILENAME
    path.write_bytes(
        b'{"attempt_id":"s:000001","role":"attack","outcome":"matched"}\n'
        b'{"attempt_id":"s:000002","role":"attack","outcome":"no_match"}'  # 完全だが改行なし
    )
    led = ProbeLedger(tmp_path, "s")
    assert led.next_attempt_id() == "s:000003"  # 000002 を失わず継承
    import json as _json
    lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 2
    assert _json.loads(lines[1])["attempt_id"] == "s:000002"


def test_recovery_read_failure_blocks_appends(tmp_path):
    # 既存正本を読めない（ここでは path が dir）＝復元不能→append を拒否し ID 再発行を防ぐ（Codex P1）
    (tmp_path / LEDGER_FILENAME).mkdir()
    led = ProbeLedger(tmp_path, "s")
    assert led.recovery_failed is True
    ok = led.append(_rec(led, ProbeRole.ATTACK, ProbeOutcome.MATCHED))
    assert ok is False
    assert led.manifest.had_write_error
    assert any(e["error"] == "ledger_recovery_failed" for e in led.manifest.write_errors)


def test_resume_restores_failed_attempt_breakdowns(tmp_path):
    # 前 run の失敗試行の role/outcome 内訳を resume で復元（Codex P2・内訳の内部整合）
    import json as _json
    (tmp_path / MANIFEST_FILENAME).write_text(_json.dumps({
        "total": 1,
        "write_errors": [{"error": "disk full", "role": "attack", "outcome": "matched"}],
    }), encoding="utf-8")
    led = ProbeLedger(tmp_path, "s")
    m = led.manifest.to_dict()
    assert m["total"] == 1
    assert m["by_role"] == {"attack": 1}
    assert m["by_outcome"] == {"matched": 1}
    assert m["had_write_error"] is True
