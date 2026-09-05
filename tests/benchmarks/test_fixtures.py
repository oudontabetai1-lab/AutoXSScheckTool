"""UvicornFixtureLauncher の起動前ガードを browser/実サーバ無しで固定する（0034-R1）。"""
import threading

import pytest

from wscan.benchmark_fixtures import (
    UvicornFixtureLauncher,
    _register_abandoned_fixture,
    _reset_abandoned_fixtures,
    _live_abandoned_fixture_count,
)


@pytest.fixture(autouse=True)
def _clean_abandoned():
    _reset_abandoned_fixtures()
    yield
    _reset_abandoned_fixtures()


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), 0.0, -1.0])
def test_rejects_non_finite_startup_timeout(bad):
    with pytest.raises(ValueError):
        UvicornFixtureLauncher(startup_timeout=bad)


def test_rejects_non_positive_abandoned_cap():
    with pytest.raises(ValueError):
        UvicornFixtureLauncher(max_abandoned_fixtures=0)


def test_unknown_fixture_id_rejected():
    launcher = UvicornFixtureLauncher()
    with pytest.raises(ValueError):
        with launcher.launch("does_not_exist"):
            pass


def test_launch_refused_when_abandoned_fixtures_at_cap():
    """放置 fixture worker が上限なら launch を拒否（実サーバを起動しない・Codex #133）。"""
    release = threading.Event()

    def _hang():
        release.wait(5)

    try:
        # 生存中の「放置 worker」を上限まで登録する（実際にハングした fixture を模す）。
        for _ in range(2):
            t = threading.Thread(target=_hang, daemon=True)
            t.start()
            _register_abandoned_fixture(t)
        assert _live_abandoned_fixture_count() == 2

        launcher = UvicornFixtureLauncher(max_abandoned_fixtures=2)
        # realistic_site は valid だが、上限超過なので起動前に RuntimeError で拒否される。
        with pytest.raises(RuntimeError):
            with launcher.launch("realistic_site"):
                pass
    finally:
        release.set()


def test_dead_abandoned_workers_are_pruned():
    t = threading.Thread(target=lambda: None)
    t.start()
    t.join()
    _register_abandoned_fixture(t)
    # 死んだ worker は掃除されカウントされない。
    assert _live_abandoned_fixture_count() == 0
