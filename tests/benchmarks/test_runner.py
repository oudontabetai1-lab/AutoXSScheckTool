"""実ネットや browser に依存せず runner の未完了会計を固定する。"""
from contextlib import contextmanager
from dataclasses import replace
import html
import json
from pathlib import Path
import threading
from threading import Event
from urllib.parse import parse_qs

import httpx
import pytest

from wscan.benchmark_model import (
    CaseExecutionState as State, CaseResult, load_manifest_file, scorecard_to_markdown,
)
from wscan.benchmark_runner import (
    HttpxCaseExecutor, run_suite, write_scorecard,
    _reset_lingering_workers, _reserved_worker_count,
)
from wscan.scanner_contract import Carrier


@pytest.fixture(autouse=True)
def _clean_lingering_workers():
    """プロセス横断の滞留 worker トラッカーをテスト間で分離する。"""
    _reset_lingering_workers()
    yield
    _reset_lingering_workers()


MANIFEST = Path(__file__).resolve().parent / "data" / "realistic_site_reflection.yaml"
METADATA = dict(run_id="test", source_sha="sha", manifest_digest="manifest",
                registry_digest="registry", environment={"note": "単体テスト"})


@pytest.fixture
def suite():
    return load_manifest_file(MANIFEST, registry_keys=frozenset({"xss"}))


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


class FakeExecutor:
    def __init__(self, results):
        self.results = results
        self.calls = []

    def __call__(self, case, base_url):
        assert base_url == "http://fixture.invalid"
        self.calls.append(case.case_id)
        return self.results[case.case_id]


def good_executor(suite):
    return FakeExecutor({
        case.case_id: CaseResult(case.case_id, State.COMPLETED, i == 0, i == 0)
        for i, case in enumerate(suite.cases)
    })


def test_normal_suite_and_write_scorecard(suite, tmp_path):
    launcher = FakeLauncher()
    executor = good_executor(suite)
    out = run_suite(suite, executor=executor, launcher=launcher, **METADATA)
    assert "run_error" not in out
    # observed のみなので、実行完了でも required gate は未達成。
    assert out["overall_status"] == "PARTIAL"
    assert out["case_counts"] == {"planned": 2, "completed": 2, "incomplete": 0}
    assert [c["classification"]["candidate"] for c in out["cases"]] == ["tp", "tn"]
    assert out["metrics"]["candidate"]["fp"] == 0
    assert out["environment"] == METADATA["environment"]
    assert executor.calls == [c.case_id for c in suite.cases]
    assert launcher.stopped

    json_path, md_path = write_scorecard(out, tmp_path / "nested" / "run")
    assert json_path.name == "scorecard.json"
    assert md_path.name == "scorecard.md"
    assert json.loads(json_path.read_text(encoding="utf-8")) == out
    assert "単体テスト" in json_path.read_text(encoding="utf-8")
    assert md_path.read_text(encoding="utf-8") == scorecard_to_markdown(out)
    assert md_path.stat().st_size > 0


def test_fixture_unavailable(suite):
    executor = good_executor(suite)
    out = run_suite(suite, executor=executor, launcher=FakeLauncher(fail=True), **METADATA)
    assert out["run_error"] == "fixture_unavailable"
    assert out["overall_status"] == "INCOMPLETE"
    assert all(c["state"] == "fixture_unavailable" for c in out["cases"])
    assert executor.calls == []
    assert out["metrics"]["candidate"]["tn"] == 0


def test_timeout_does_not_wait_or_block_next_case(suite):
    release = Event()
    finished = Event()
    launcher = FakeLauncher()

    def executor(case, base_url):
        if case == suite.cases[0]:
            try:
                assert release.wait(5), "runner waited for timed-out executor"
            finally:
                finished.set()
        return CaseResult(case.case_id, State.COMPLETED)

    try:
        out = run_suite(suite, executor=executor, launcher=launcher,
                        per_case_timeout=0.05, **METADATA)
        assert not finished.is_set()
        assert [c["state"] for c in out["cases"]] == ["timeout", "completed"]
        assert out["overall_status"] == "INCOMPLETE"
        assert out["cases"][0]["classification"]["candidate"] is None
        assert launcher.stopped
    finally:
        release.set()
        assert finished.wait(2)
    assert out["cases"][0]["state"] == "timeout"


def test_worker_exhaustion_aborts_loudly(suite):
    """滞留 worker が上限に達したら新規 case を起動せず run_error=worker_exhaustion で中断（Codex #133）。"""
    release = Event()

    def executor(case, base_url):
        release.wait(5)  # 常にハング（テスト終了時に release）
        return CaseResult(case.case_id, State.COMPLETED)

    try:
        # cap=1: case[0] がハングして1つ滞留 → case[1] を起動せず中断。
        out = run_suite(suite, executor=executor, launcher=FakeLauncher(),
                        per_case_timeout=0.05, max_lingering_workers=1, **METADATA)
        assert out["run_error"] == "worker_exhaustion"
        states = [c["state"] for c in out["cases"]]
        assert states == ["timeout", "not_reached"]  # 未処理は NOT_REACHED（陰性に混ぜない）
        assert out["overall_status"] != "COMPLETE"
    finally:
        release.set()


def test_lingering_worker_cap_is_process_wide(suite):
    """滞留 worker の上限は run_suite を跨いで効く（per-call でなくプロセス横断・Codex #133）。"""
    release = Event()

    def executor(case, base_url):
        release.wait(5)
        return CaseResult(case.case_id, State.COMPLETED)

    try:
        # 1回目: cap=2・2 case とも timeout → プロセス横断で 2 滞留（この run では未中断）。
        out1 = run_suite(suite, executor=executor, launcher=FakeLauncher(),
                         per_case_timeout=0.05, max_lingering_workers=2, **METADATA)
        assert [c["state"] for c in out1["cases"]] == ["timeout", "timeout"]
        assert "run_error" not in out1
        assert _reserved_worker_count() == 2
        # 2回目: 既に global 2 >= cap 2 なので最初の case を起動せず即中断（跨ぎ累積を bound）。
        out2 = run_suite(suite, executor=executor, launcher=FakeLauncher(),
                         per_case_timeout=0.05, max_lingering_workers=2, **METADATA)
        assert out2["run_error"] == "worker_exhaustion"
        assert all(c["state"] == "not_reached" for c in out2["cases"])
    finally:
        release.set()


def test_max_lingering_workers_must_be_positive(suite):
    import pytest as _pytest
    with _pytest.raises(ValueError):
        run_suite(suite, executor=lambda c, b: CaseResult(c.case_id, State.COMPLETED),
                  launcher=FakeLauncher(), max_lingering_workers=0, **METADATA)


def test_inconsistent_worker_limit_is_rejected(suite):
    """異なる max_lingering_workers の混在は拒否し、単一のプロセス横断 limit を強制（Codex #133）。"""
    import pytest as _pytest
    run_suite(suite, executor=good_executor(suite), launcher=FakeLauncher(),
              max_lingering_workers=2, **METADATA)
    with _pytest.raises(ValueError):
        run_suite(suite, executor=good_executor(suite), launcher=FakeLauncher(),
                  max_lingering_workers=5, **METADATA)


def test_none_executor_result_is_rejected(suite):
    """executor が None を返したら TRANSPORT_ERROR で隠さず TypeError で弾く（Codex #133）。"""
    import pytest as _pytest
    with _pytest.raises(TypeError):
        run_suite(suite, executor=lambda c, b: None, launcher=FakeLauncher(), **METADATA)


def test_reservation_released_when_thread_start_fails(suite, monkeypatch):
    """thread.start() が失敗しても予約はリークしない（先取り監査・fixture 側の対称）。"""
    from wscan import benchmark_runner as br
    real_thread = br.threading.Thread

    def make_thread(*args, **kwargs):
        t = real_thread(*args, **kwargs)
        def _bad_start():
            raise RuntimeError("cannot start new thread")
        t.start = _bad_start
        return t

    monkeypatch.setattr(br.threading, "Thread", make_thread)
    with pytest.raises(RuntimeError):
        run_suite(suite, executor=good_executor(suite), launcher=FakeLauncher(), **METADATA)
    assert br._reserved_worker_count() == 0  # start 失敗でも予約を解放している


def test_timed_out_worker_is_daemon(suite):
    """ハングした executor の worker は daemon＝インタプリタ終了をブロックしない（Codex #133 P2）。"""
    release = Event()

    def executor(case, base_url):
        release.wait(5)  # 期限より長く待つ。テスト終了時に release で解放する。
        return CaseResult(case.case_id, State.COMPLETED)

    try:
        out = run_suite(suite, executor=executor, launcher=FakeLauncher(),
                        per_case_timeout=0.05, **METADATA)
        assert out["cases"][0]["state"] == "timeout"
        lingering = [t for t in threading.enumerate() if t.name.startswith("benchmark-case-")]
        assert lingering, "期限切れ worker が残っているはず（daemon 性を検証する対象）"
        assert all(t.daemon for t in lingering), "残存 worker は daemon でなければならない"
    finally:
        release.set()


@pytest.mark.parametrize("exception", [RuntimeError, TimeoutError])
def test_executor_exception(suite, exception):
    def executor(case, base_url):
        raise exception("I/O failed")

    out = run_suite(suite, executor=executor, launcher=FakeLauncher(), **METADATA)
    assert all(c["state"] == "transport_error" for c in out["cases"])
    assert out["overall_status"] == "INCOMPLETE"


def test_empty_suite(suite):
    launcher = FakeLauncher()
    executor = good_executor(suite)
    out = run_suite(replace(suite, cases=()), executor=executor, launcher=launcher, **METADATA)
    assert out["run_error"] == "empty_suite"
    assert out["overall_status"] != "COMPLETE"
    assert out["cases"] == []
    assert not launcher.launched
    assert executor.calls == []


def test_case_id_mismatch_is_not_fixture_failure(suite):
    launcher = FakeLauncher()
    executor = FakeExecutor({c.case_id: CaseResult("wrong", State.COMPLETED) for c in suite.cases})
    with pytest.raises(ValueError, match="case_id mismatch"):
        run_suite(suite, executor=executor, launcher=launcher, **METADATA)
    assert launcher.stopped


def test_not_reached_is_not_a_negative(suite):
    executor = FakeExecutor({c.case_id: CaseResult(c.case_id, State.NOT_REACHED) for c in suite.cases})
    out = run_suite(suite, executor=executor, launcher=FakeLauncher(), **METADATA)
    assert out["overall_status"] == "INCOMPLETE"
    assert out["metrics"]["candidate"]["tn"] == 0
    assert out["metrics"]["candidate"]["fn"] == 0


@pytest.mark.parametrize("carrier", [None, *[c for c in Carrier if c not in {Carrier.QUERY, Carrier.FORM}]])
def test_httpx_unsupported_carrier(suite, monkeypatch, carrier):
    def no_client(*args, **kwargs):
        pytest.fail("unsupported case must not create an HTTP client")

    monkeypatch.setattr(httpx, "Client", no_client)
    case = suite.cases[0]
    case = replace(case, injection=replace(case.injection, carrier=carrier) if carrier else None)
    assert HttpxCaseExecutor()(case, "http://fixture.invalid").state == State.UNSUPPORTED


@pytest.mark.parametrize("prerequisite", ["browser", "browser_required", "chromium", "playwright"])
def test_httpx_browser_prerequisite(suite, monkeypatch, prerequisite):
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: pytest.fail("browser case sent HTTP"))
    case = replace(suite.cases[0], prerequisites=(prerequisite,))
    assert HttpxCaseExecutor()(case, "http://fixture.invalid").state == State.UNSUPPORTED


@pytest.mark.parametrize("carrier", [Carrier.QUERY, Carrier.FORM])
@pytest.mark.parametrize("reflection", ["raw", "escaped", "absent"])
def test_httpx_probe_with_mock_transport(suite, monkeypatch, carrier, reflection):
    def handler(request):
        if carrier == Carrier.QUERY:
            assert request.method == "GET"
            assert request.url.params["keep"] == "yes"
            probe = request.url.params["q"]
        else:
            assert request.method == "POST"
            probe = parse_qs(request.content.decode())["q"][0]
        assert "<svg/onload=alert(1)>" in probe
        body = probe if reflection == "raw" else html.escape(probe) if reflection == "escaped" else "ok"
        return httpx.Response(200, text=body)

    client = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: client(
        transport=httpx.MockTransport(handler), **kwargs,
    ))
    # executor は manifest の宣言メソッドを尊重する（P2）。query=GET / form=POST を宣言する。
    method = "GET" if carrier == Carrier.QUERY else "POST"
    case = suite.cases[0]
    case = replace(case, injection=replace(case.injection, carrier=carrier),
                   request=replace(case.request, path="/search?keep=yes", method=method))
    result = HttpxCaseExecutor()(case, "http://fixture.invalid")
    assert result.state == State.COMPLETED
    assert result.candidate_match == (reflection == "raw")
    assert result.confirmed_match == result.candidate_match


def test_http_error_is_not_safe(suite, monkeypatch):
    client = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: client(
        transport=httpx.MockTransport(lambda request: httpx.Response(404)), **kwargs,
    ))
    out = run_suite(suite, executor=HttpxCaseExecutor(), launcher=FakeLauncher(), **METADATA)
    assert all(c["state"] == "transport_error" for c in out["cases"])


@pytest.mark.parametrize("carrier,method", [(Carrier.QUERY, "PUT"), (Carrier.FORM, "PATCH")])
def test_httpx_honors_declared_method(suite, monkeypatch, carrier, method):
    """executor は carrier 既定(GET/POST)でなく manifest の宣言メソッドで送る（Codex #133 P2）。"""
    seen = {}

    def handler(request):
        seen["method"] = request.method
        return httpx.Response(200, text="ok")

    client = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: client(
        transport=httpx.MockTransport(handler), **kwargs,
    ))
    case = suite.cases[0]
    case = replace(case, injection=replace(case.injection, carrier=carrier),
                   request=replace(case.request, method=method))
    HttpxCaseExecutor()(case, "http://fixture.invalid")
    assert seen["method"] == method  # GET/POST 固定ではなく宣言メソッド
