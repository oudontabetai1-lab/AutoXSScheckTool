"""Chromium 無しで suite の採点と未完了会計、worker の上限を固定する。"""
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from wscan import benchmark_runner as br
from wscan.benchmark_runner import ScanOutcome
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
            thread.join(3)
    assert br._reserved_worker_count() == 0
    br._reset_lingering_workers()


def _mpl(match):
    """MatchSpec でも dict でも (path, field, location) を取り出す。"""
    if isinstance(match, dict):
        return match.get("path"), match.get("field"), match.get("location", "")
    return match.path, match.field, getattr(match, "location", "")


def exercised_of(suite):
    """suite の全 case（match あり）の (check, path, field, location) を「実行済み」とみなす集合。"""
    out = set()
    for c in suite.cases:
        if c.match is not None:
            p, f, loc = _mpl(c.match)
            out.add((c.check, p, f, loc))
    return frozenset(out)


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
    """findings と exercised（注入点実行台帳）を返す ScanRunner。"""
    def __init__(self, findings, exercised):
        self.outcome = ScanOutcome(findings=list(findings), exercised=frozenset(exercised))
        self.calls = []

    def __call__(self, base_url, checks):
        self.calls.append((base_url, checks))
        return self.outcome


def finding(**overrides):
    # 出荷 manifest は form 注入（scanner が /search を form で検出する実態に合わせている）。
    return dict(check_type="xss", url="http://fixture.invalid/search?q=payload",
                field_name="q", injection_location="form", verified=True) | overrides


def run(suite, runner, launcher=None, **kwargs):
    return br.run_scanned_suite(suite, scan_runner=runner,
                                launcher=launcher or FakeLauncher(), **METADATA, **kwargs)


@pytest.mark.parametrize("as_dict", [False, True])
@pytest.mark.parametrize("verified", [False, True])
def test_score_and_single_scan(suite, as_dict, verified):
    item = finding(verified=verified)
    findings = [item if as_dict else SimpleNamespace(**item)]
    if as_dict:
        suite = replace(suite, cases=tuple(replace(c, match=vars(c.match)) for c in suite.cases))
    outcome = ScanOutcome(findings=findings, exercised=exercised_of(suite))
    results = br.score_cases(suite, outcome, ran_checks={"xss"})
    # vulnerable(/search q) にマッチ→TP、safe(/help query) は実行済みだが finding 無し→TN。
    assert [(r.candidate_match, r.confirmed_match) for r in results] == [(True, verified), (False, False)]
    launcher = FakeLauncher()
    out = run(suite, FakeScanRunner(findings, exercised_of(suite)), launcher, environment={"test": True})
    assert "run_error" not in out
    assert [c["classification"]["candidate"] for c in out["cases"]] == ["tp", "tn"]
    assert out["environment"] == {"test": True}
    assert launcher.stopped


@pytest.mark.parametrize("override", [dict(check_type="sqli"), dict(url="http://fixture.invalid/other"), dict(field_name="other")])
def test_matching_requires_all_three_keys(suite, override):
    outcome = ScanOutcome(findings=[finding(**override)], exercised=exercised_of(suite))
    assert not br.score_cases(suite, outcome, ran_checks={"xss"})[0].candidate_match


def test_unsupported_and_missing_match(suite):
    outcome = ScanOutcome(findings=[finding()], exercised=exercised_of(suite))
    assert all(r.state == State.UNSUPPORTED for r in br.score_cases(suite, outcome, ran_checks={"sqli"}))
    nomatch = replace(suite, cases=(replace(suite.cases[0], match=None),))
    assert br.score_cases(nomatch, ScanOutcome([], frozenset()), ran_checks={"xss"})[0].state == State.UNSUPPORTED


_PASSIVE_MANIFEST = (
    Path(__file__).resolve().parents[2]
    / "benchmarks/manifests/realistic_healthcare_security_headers.yaml"
)


def _passive_suite():
    return load_manifest_file(_PASSIVE_MANIFEST, registry_keys={"security_headers"})


def _sh_finding(**overrides):
    # page 観測系 finding は header 固有の field_name を持ち injection_location は空/固有。
    return dict(
        check_type="security_headers",
        url="http://fixture.invalid/legacy/status",
        field_name="(Header: content-security-policy)",
        injection_location="", verified=True,
    ) | overrides


def test_passive_case_scored_by_check_and_path():
    """injection を宣言しない passive case（security_headers）は (check, path) で採点する。

    field/location（注入概念）が finding と一致しなくても、vulnerable=TP・safe twin=TN になる。
    exercised は page-level 行（field="(page)"/location="page-level"）で表す。
    """
    suite = _passive_suite()
    # 両 case が exercised（page-level スキャナが実走した証拠）。
    exercised = frozenset({
        ("security_headers", "/legacy/status", "(page)", "page-level"),
        ("security_headers", "/legacy/status-secure", "(page)", "page-level"),
    })
    outcome = ScanOutcome(findings=[_sh_finding()], exercised=exercised)
    results = br.score_cases(suite, outcome, ran_checks={"security_headers"})
    # vulnerable(/legacy/status) に finding→TP、safe(/legacy/status-secure) は exercised だが finding 無し→TN。
    assert [(r.state, r.candidate_match) for r in results] == [
        (State.COMPLETED, True), (State.COMPLETED, False),
    ]


def test_passive_case_not_exercised_is_not_reached():
    """passive case も page-level 行が exercised に無ければ NOT_REACHED（未計測を TN/FN にしない）。"""
    suite = _passive_suite()
    outcome = ScanOutcome(findings=[_sh_finding()], exercised=frozenset())
    results = br.score_cases(suite, outcome, ran_checks={"security_headers"})
    assert all(r.state == State.NOT_REACHED for r in results)


def test_passive_finding_field_location_ignored():
    """passive では finding の field_name/injection_location が何であっても (check, path) で採る。"""
    suite = _passive_suite()
    exercised = frozenset({("security_headers", "/legacy/status", "(page)", "page-level")})
    # わざと異なる field_name / injection_location を持つ finding。
    outcome = ScanOutcome(
        findings=[_sh_finding(field_name="(Header: x-frame-options)", injection_location="url_param")],
        exercised=exercised,
    )
    vuln = br.score_cases(suite, outcome, ran_checks={"security_headers"})[0]
    assert vuln.candidate_match  # field/location 差異に関係なく TP


def test_non_field_carrier_is_unsupported(suite):
    """R2 は field carrier（query/form）だけ忠実に採点。json/header 等は UNSUPPORTED（Codex #134 P2）。"""
    from wscan.scanner_contract import Carrier
    for carrier in (Carrier.JSON, Carrier.HEADER, Carrier.COOKIE):
        case = replace(suite.cases[0], injection=replace(suite.cases[0].injection, carrier=carrier))
        s = replace(suite, cases=(case,))
        outcome = ScanOutcome(findings=[finding()], exercised=exercised_of(s))
        assert br.score_cases(s, outcome, ran_checks={"xss"})[0].state == State.UNSUPPORTED


def test_unprovisioned_prerequisite_is_unsupported(suite):
    """前提を宣言した case は、スキャンがそれを用意したときだけ採点する（Codex #134 P2）。"""
    case = replace(suite.cases[0], prerequisites=("auth_session",))
    s = replace(suite, cases=(case,))
    ex = exercised_of(s)
    # 未充足（fulfilled 空）→ UNSUPPORTED。
    unmet = ScanOutcome(findings=[finding()], exercised=ex)
    assert br.score_cases(s, unmet, ran_checks={"xss"})[0].state == State.UNSUPPORTED
    # 充足（auth_session を用意）→ 通常どおり採点（COMPLETED・TP）。
    met = ScanOutcome(findings=[finding()], exercised=ex, fulfilled_prerequisites=frozenset({"auth_session"}))
    r = br.score_cases(s, met, ran_checks={"xss"})[0]
    assert r.state == State.COMPLETED and r.candidate_match


def test_unexercised_case_is_not_reached(suite):
    """宣言された注入点をスキャンが突いていない case は NOT_REACHED（TN/FN に混ぜない・Codex #134 P1）。"""
    # exercised に vulnerable だけ入れ、safe(/help query) は未実行にする。
    vuln = suite.cases[0]
    exercised = frozenset({(vuln.check, vuln.match.path, vuln.match.field, vuln.match.location)})
    outcome = ScanOutcome(findings=[finding()], exercised=exercised)
    results = br.score_cases(suite, outcome, ran_checks={"xss"})
    assert results[0].state == State.COMPLETED  # vulnerable は実行済み
    assert results[1].state == State.NOT_REACHED  # safe は未実行→陰性にしない
    assert results[1].candidate_match is False and results[1].confirmed_match is False


def test_other_carrier_exercised_is_not_reached(suite):
    """同名 field でも別 carrier だけ突いた場合は NOT_REACHED（location を exercised に含める・#134 P2）。"""
    vuln = suite.cases[0]  # location=form
    # 実行台帳には url_param だけ（form は突いていない）。case は form なので未計測扱い。
    exercised = frozenset({(vuln.check, vuln.match.path, vuln.match.field, "url_param")})
    outcome = ScanOutcome(findings=[finding()], exercised=exercised)
    assert br.score_cases(suite, outcome, ran_checks={"xss"})[0].state == State.NOT_REACHED


def test_location_disambiguates_findings(suite):
    """同名 field でも injection_location が異なれば candidate にしない（Codex #134 P2）。"""
    # vulnerable case は location=form。url_param 由来 finding は別 carrier なので一致しない。
    other = ScanOutcome(findings=[finding(injection_location="url_param")], exercised=exercised_of(suite))
    assert not br.score_cases(suite, other, ran_checks={"xss"})[0].candidate_match
    # 同じ location なら一致する。
    ok = ScanOutcome(findings=[finding(injection_location="form")], exercised=exercised_of(suite))
    assert br.score_cases(suite, ok, ran_checks={"xss"})[0].candidate_match
    # finding 側が location 空なら弁別できないので 3 キー一致で採る（実 scanner が空を返す場合の互換）。
    empty = ScanOutcome(findings=[finding(injection_location="")], exercised=exercised_of(suite))
    assert br.score_cases(suite, empty, ran_checks={"xss"})[0].candidate_match


def test_subtype_and_alias_findings_match_check_family(suite):
    """サブタイプ/エイリアスの finding も check ファミリに一致させ FN にしない（Codex #134 P2）。"""
    # 完全一致（xss）は当然一致。<check>_ 前置（xss_stored）も一致する。
    for ct in ("xss", "xss_stored"):
        outcome = ScanOutcome(findings=[finding(check_type=ct)], exercised=exercised_of(suite))
        assert br.score_cases(suite, outcome, ran_checks={"xss"})[0].candidate_match, ct
    # 純粋 predicate: engine のエイリアス表を再利用（cache_poisoning←cache_deception）。
    assert br._finding_check_matches("graphql_introspection", "graphql")
    assert br._finding_check_matches("jwt_alg_none", "jwt")
    assert br._finding_check_matches("cache_deception", "cache_poisoning")
    assert not br._finding_check_matches("sqli", "xss")


def assert_failure(out, error, state):
    assert out["run_error"] == error
    assert all(c["state"] == state for c in out["cases"])
    assert out["metrics"]["candidate"]["fn"] == out["metrics"]["candidate"]["tn"] == 0
    assert out["case_counts"]["completed"] == 0


def test_fixture_failure(suite):
    runner = FakeScanRunner([finding()], exercised_of(suite))
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
    # ScanOutcome でない戻り値（None）は measurement 失敗として NOT_REACHED（scan_failed）。
    assert_failure(run(suite, lambda base_url, checks: None), "scan_failed", "not_reached")


def test_timeout_daemon_and_shared_cap(suite):
    release = threading.Event()
    calls = []
    br._establish_worker_limit(1)
    def scan(base_url, checks):
        calls.append(threading.current_thread())
        release.wait()
        return ScanOutcome([finding()], exercised_of(suite))
    try:
        launcher = FakeLauncher()
        out = run(suite, scan, launcher, scan_timeout=0.02)
        assert_failure(out, "scan_failed", "not_reached")
        assert launcher.stopped
        assert len(calls) == 1 and calls[0].daemon and calls[0].is_alive()
        assert br._reserved_worker_count() == 1
        assert_failure(run(suite, scan, scan_timeout=0.02), "scan_failed", "not_reached")
        assert len(calls) == 1  # cap 到達で2回目は起動しない
    finally:
        release.set()
        for thread in calls:
            thread.join(3)


def test_start_failure_releases_reservation(suite, monkeypatch):
    def fail(self):
        raise RuntimeError("cannot start")
    monkeypatch.setattr(threading.Thread, "start", fail)
    assert_failure(run(suite, FakeScanRunner([], frozenset())), "scan_failed", "not_reached")
    assert br._reserved_worker_count() == 0


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), -float("inf")])
def test_timeout_validation(suite, timeout):
    launcher = FakeLauncher()
    with pytest.raises(ValueError, match="finite and positive"):
        run(suite, FakeScanRunner([], frozenset()), launcher, scan_timeout=timeout)
    assert not launcher.launched
    with pytest.raises(ValueError, match="finite and positive"):
        ScanEngineScanRunner(timeout=timeout)


def test_default_scan_timeout_exceeds_runner_default():
    """外側 backstop の既定は内側 runner の既定より大きい（健全な scan を誤って中断しない・#134 P2）。"""
    import inspect
    outer = inspect.signature(br.run_scanned_suite).parameters["scan_timeout"].default
    inner = inspect.signature(ScanEngineScanRunner.__init__).parameters["timeout"].default
    assert outer > inner


def test_empty_suite(suite):
    launcher = FakeLauncher()
    runner = FakeScanRunner([], frozenset())
    out = run(replace(suite, cases=()), runner, launcher)
    assert out["run_error"] == "empty_suite"
    assert out["cases"] == []
    assert not launcher.launched and not runner.calls


def test_exercised_from_scan_matrix_filters_status_and_normalizes_location():
    """tested/finding だけ exercised に入れ error/skip を除く・location を正規化（Codex #134 P1/P2）。"""
    from wscan.benchmark_scan import _exercised_from_scan_matrix
    rows = [
        {"check": "xss", "url": "http://h/search?q=1", "field_name": "q", "location": "form field", "status": "finding"},
        {"check": "xss", "url": "http://h/help?query=1", "field_name": "query", "location": "URL param", "status": "tested"},
        {"check": "xss", "url": "http://h/err", "field_name": "e", "location": "form field", "status": "error"},  # 除外
        {"check": "xss", "url": "http://h/skip", "field_name": "s", "location": "form field", "status": "skipped"},  # 除外
    ]
    ex = _exercised_from_scan_matrix(rows)
    assert ("xss", "/search", "q", "form") in ex          # form field → form 正規化
    assert ("xss", "/help", "query", "url_param") in ex    # URL param → url_param 正規化
    assert not any(e[1] in ("/err", "/skip") for e in ex)  # error/skip は未計測なので除外


def test_degraded_checks_excluded_from_exercised():
    """transport 握りつぶし等が観測された check の tested 行は exercised から除く（Codex #134 P1）。"""
    from wscan.benchmark_scan import _exercised_from_scan_matrix, _degraded_checks
    wave = ["transport_error:xss: NavigationError: boom", "unexecutable_template:mass_assignment",
            "state_change_skipped:sqli"]  # state_change は劣化ではない
    degraded = _degraded_checks(wave)
    assert degraded == frozenset({"xss", "mass_assignment"})
    tested = [{"check": "xss", "url": "http://h/s?q=1", "field_name": "q", "location": "form field", "status": "tested"}]
    # 劣化 check なので tested でも exercised に入れない（probe 未送達かもしれない）。
    assert _exercised_from_scan_matrix(tested, degraded_checks=degraded) == frozenset()
    # 劣化していなければ入る。
    assert _exercised_from_scan_matrix(tested, degraded_checks=frozenset())
    # finding 行は送達の陽性証拠なので、同 check が劣化していても残す（Codex #134 P2）。
    found = [{"check": "xss", "url": "http://h/s?q=1", "field_name": "q", "location": "form field", "status": "finding"}]
    assert _exercised_from_scan_matrix(found, degraded_checks=degraded) == frozenset(
        {("xss", "/s", "q", "form")}
    )


def test_canonical_xss_coverage_and_ground_truth(suite):
    from tests.fixtures.realistic_site import EXPECTED_FINDINGS, SAFE_ENDPOINTS
    assert checks_covered_by_suites([suite]) == ({"xss"}, {"xss"})
    vulnerable, safe = suite.cases
    assert any((f["check"], f["path"], f["field"]) == (vulnerable.check, vulnerable.match.path, vulnerable.match.field) for f in EXPECTED_FINDINGS)
    assert any((f["path"], f["field"]) == (safe.match.path, safe.match.field) for f in SAFE_ENDPOINTS)
