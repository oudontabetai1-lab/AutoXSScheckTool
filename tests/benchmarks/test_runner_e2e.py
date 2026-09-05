"""実ポートの fixture で manifest → 実行 → 保存を検証する opt-in E2E。"""
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


def test_realistic_site_runner(tmp_path):
    path = Path(__file__).resolve().parents[2] / "benchmarks/manifests/realistic_site.yaml"
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
