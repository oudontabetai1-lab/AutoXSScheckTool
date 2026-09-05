"""Chromium 無しで suite の採点と未完了会計、worker の上限を固定する。"""
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from wscan import benchmark_runner as br
from wscan.benchmark_model import (
    CaseExecutionState as State, checks_covered_by_suites, load_manifest_file,
)
from wscan.benchmark_scan import ScanEngineScanRunner

MANIFEST = Path(__file__).resolve().parents[2] / "benchmarks/manifests/realistic_site_xss.yaml"
METADATA = dict(run_id="test", source_sha="sha", manifest_digest="manifest", registry_digest="registry")


@pytest.fixture
def suite():
    return load_manifest_file(MANIFEST, registry_keys={"xss"})


@pytest.fixture(autouse=True)
def workers():
    br._reset_lingering_workers()
    yield
    for thread in threading.enumerate():
        if thread.name.startswith("benchmark-scan-"):
            thread.join(2)
    assert br._reserved_worker_count() == 0
    br._reset_lingering_workers()


class FakeLauncher:
    def __init__(self, fail=False):
        self.fail = fail
        self.launched = False
        self.stopped = False

    @contextmanager
    def launch(self, fixture_id):
        assert fixture_id == "realistic_site"
        self.launched = True
        if self.fail:
            raise RuntimeError("fixture unavailable")
        try:
            yield "http://fixture.invalid"
        finally:
            self.stopped = True


class FakeScanRunner:
    def __init__(self, findings):
        self.findings = findings
        self.calls = []

    def __call__(self, base_url, checks):
        self.calls.append((base_url, checks))
        return self.findings


def finding(**overrides):
    return dict(check_type="xss", url="http://fixture.invalid/search?q=payload",
                field_name="q", verified=True) | overrides


def run(suite, runner, launcher=None, **kwargs):
    return br.run_scanned_suite(suite, scan_runner=runner,
                                launcher=launcher or FakeLauncher(), **METADATA, **kwargs)


@pytest.mark.parametrize("as_dict", [False, True])
@pytest.mark.parametrize("verified", [False, True])
def test_score_and_single_scan(suite, as_dict, verified):
    item = finding(verified=verified)
    runner = FakeScanRunner([item if as_dict else SimpleNamespace(**item)])
    if as_dict:
        suite = replace(suite, cases=tuple(replace(c, match=vars(c.match)) for c in suite.cases))
    results = br.score_cases(suite, runner.findings, ran_checks={"xss"})
    assert [(r.candidate_match, r.confirmed_match) for r in results] == [(True, verified), (False, False)]
    launcher = FakeLauncher()
    out = run(suite, runner, launcher, environment={"test": True})
    assert "run_error" not in out
    assert [c["classification"]["candidate"] for c in out["cases"]] == ["tp", "tn"]
    assert out["environment"] == {"test": True}
    assert runner.calls == [("http://fixture.invalid", ["xss"])]
    assert launcher.stopped


@pytest.mark.parametrize("override", [dict(check_type="sqli"), dict(url="http://fixture.invalid/other"), dict(field_name="other")])
def test_matching_requires_all_three_keys(suite, override):
    assert not br.score_cases(suite, [finding(**override)], ran_checks={"xss"})[0].candidate_match


def test_unsupported_and_missing_match(suite):
    assert all(r.state == State.UNSUPPORTED for r in br.score_cases(suite, [finding()], ran_checks={"sqli"}))
    suite = replace(suite, cases=(replace(suite.cases[0], match=None),))
    assert br.score_cases(suite, [finding()], ran_checks={"xss"})[0].state == State.UNSUPPORTED


def assert_failure(out, error, state):
    assert out["run_error"] == error
    assert all(c["state"] == state for c in out["cases"])
    assert out["metrics"]["candidate"]["fn"] == out["metrics"]["candidate"]["tn"] == 0
    assert out["case_counts"]["completed"] == 0


def test_fixture_failure(suite):
    runner = FakeScanRunner([finding()])
    assert_failure(run(suite, runner, FakeLauncher(fail=True)), "fixture_unavailable", "fixture_unavailable")
    assert runner.calls == []


@pytest.mark.parametrize("error", [RuntimeError, TimeoutError])
def test_scan_exception(suite, error):
    def scan(base_url, checks):
        raise error("scan failed")
    launcher = FakeLauncher()
    assert_failure(run(suite, scan, launcher), "scan_failed", "not_reached")
    assert launcher.stopped


def test_invalid_return_is_measurement_failure(suite):
    assert_failure(run(suite, FakeScanRunner(None)), "scan_failed", "not_reached")


def test_timeout_daemon_and_shared_cap(suite):
    release = threading.Event()
    calls = []
    # R1 が確立した limit を使い、繰り返し suite でも追加 worker を積まない。
    br._establish_worker_limit(1)
    def scan(base_url, checks):
        calls.append(threading.current_thread())
        release.wait()
        return [finding()]
    try:
        launcher = FakeLauncher()
        out = run(suite, scan, launcher, scan_timeout=0.02)
        assert_failure(out, "scan_failed", "not_reached")
        assert launcher.stopped
        assert len(calls) == 1 and calls[0].daemon and calls[0].is_alive()
        assert br._reserved_worker_count() == 1
        assert_failure(run(suite, scan, scan_timeout=0.02), "scan_failed", "not_reached")
        assert len(calls) == 1
    finally:
        release.set()
        for thread in calls:
            thread.join(2)
    assert_failure(out, "scan_failed", "not_reached")


def test_start_failure_releases_reservation(suite, monkeypatch):
    def fail(self):
        raise RuntimeError("cannot start")
    monkeypatch.setattr(threading.Thread, "start", fail)
    assert_failure(run(suite, FakeScanRunner([])), "scan_failed", "not_reached")
    assert br._reserved_worker_count() == 0


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), -float("inf")])
def test_timeout_validation(suite, timeout):
    launcher = FakeLauncher()
    with pytest.raises(ValueError, match="finite and positive"):
        run(suite, FakeScanRunner([]), launcher, scan_timeout=timeout)
    assert not launcher.launched
    with pytest.raises(ValueError, match="finite and positive"):
        ScanEngineScanRunner(timeout=timeout)


def test_empty_suite(suite):
    launcher = FakeLauncher()
    runner = FakeScanRunner([])
    out = run(replace(suite, cases=()), runner, launcher)
    assert out["run_error"] == "empty_suite"
    assert out["cases"] == []
    assert not launcher.launched and not runner.calls


def test_canonical_xss_coverage_and_ground_truth(suite):
    from tests.fixtures.realistic_site import EXPECTED_FINDINGS, SAFE_ENDPOINTS
    assert checks_covered_by_suites([suite]) == ({"xss"}, {"xss"})
    vulnerable, safe = suite.cases
    assert any((f["check"], f["path"], f["field"]) == (vulnerable.check, vulnerable.match.path, vulnerable.match.field) for f in EXPECTED_FINDINGS)
    assert any((f["path"], f["field"]) == (safe.match.path, safe.match.field) for f in SAFE_ENDPOINTS)
