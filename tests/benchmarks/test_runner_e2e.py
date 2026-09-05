"""実ポートの fixture で runner **配管**（manifest→起動→実行→保存）を検証する opt-in E2E。

注意: ここで使う HttpxCaseExecutor は fixture の反射有無を測る**参照オラクル**であって、
製品スキャナ（XSSScanner/ScanEngine）ではない。したがって本テストは runner の配管と
fixture の健全性（脆弱は反射・安全は非反射）を確認するもので、**製品スキャナの recall を
測るものではない**。実スキャナを走らせて findings から採点する scanner-backed executor は
0034-R2（既存 E2E 移植）で追加する。manifest も出荷 canonical（benchmarks/manifests/）では
なくテストローカル（tests/benchmarks/data/）に置き、registry 完全性の covered を実スキャナ
未計測のまま偽らない。"""
import hashlib
import json
import os
from pathlib import Path
import threading

import pytest

from wscan.benchmark_fixtures import UvicornFixtureLauncher
from wscan.benchmark_model import load_manifest_file
from wscan.benchmark_runner import HttpxCaseExecutor, run_suite, write_scorecard
from wscan.scanners import SCANNERS


pytestmark = pytest.mark.skipif(not os.getenv("WSCAN_E2E"), reason="opt-in E2E")


def test_realistic_site_runner_plumbing(tmp_path):
    # テストローカル manifest（出荷 canonical ではない＝covered を偽らない）を参照オラクルで実行。
    path = Path(__file__).resolve().parent / "data" / "realistic_site_reflection.yaml"
    suite = load_manifest_file(path, registry_keys=frozenset(SCANNERS))
    before = set(threading.enumerate())
    out = run_suite(
        suite, executor=HttpxCaseExecutor(), launcher=UvicornFixtureLauncher(),
        run_id="runner-e2e", source_sha="test-worktree",
        manifest_digest=hashlib.sha256(path.read_bytes()).hexdigest(),
        registry_digest=hashlib.sha256("\n".join(sorted(SCANNERS)).encode()).hexdigest(),
    )
    assert "run_error" not in out
    assert out["case_counts"] == {"planned": 2, "completed": 2, "incomplete": 0}
    assert [c["classification"]["candidate"] for c in out["cases"]] == ["tp", "tn"]
    assert [c["classification"]["confirmed"] for c in out["cases"]] == ["tp", "tn"]
    assert out["overall_status"] == "PARTIAL"
    assert not any(t.name.startswith("benchmark-fixture-") for t in set(threading.enumerate()) - before)
    json_path, md_path = write_scorecard(out, tmp_path)
    assert json.loads(json_path.read_text(encoding="utf-8")) == out
    assert md_path.read_text(encoding="utf-8")
