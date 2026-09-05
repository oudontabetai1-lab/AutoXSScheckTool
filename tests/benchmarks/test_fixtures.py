"""UvicornFixtureLauncher の起動前ガードを browser/実サーバ無しで固定する（0034-R1）。"""
import pytest

from wscan.benchmark_fixtures import (
    UvicornFixtureLauncher,
    _establish_fixture_limit,
    _try_reserve_fixture,
    _release_fixture,
    _reserved_fixture_count,
    _reset_fixture_workers,
)


@pytest.fixture(autouse=True)
def _clean_fixture_workers():
    _reset_fixture_workers()
    yield
    _reset_fixture_workers()


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


def test_launch_refused_when_fixture_workers_at_cap():
    """予約が上限なら launch を拒否（実サーバを起動しない・Codex #133）。"""
    _establish_fixture_limit(2)
    assert _try_reserve_fixture() is True
    assert _try_reserve_fixture() is True
    assert _reserved_fixture_count() == 2
    # 上限到達 → realistic_site は valid でも起動前に RuntimeError で拒否。
    launcher = UvicornFixtureLauncher(max_abandoned_fixtures=2)
    with pytest.raises(RuntimeError):
        with launcher.launch("realistic_site"):
            pass
    # 予約はテストが埋めた 2 のまま（launch は取れなかったので増やしていない）。
    assert _reserved_fixture_count() == 2
    _release_fixture()
    _release_fixture()


def test_inconsistent_fixture_limit_rejected():
    """異なる max_abandoned_fixtures の混在は拒否（プロセス横断で単一 limit・Codex #133）。"""
    _establish_fixture_limit(1)
    launcher = UvicornFixtureLauncher(max_abandoned_fixtures=100)
    with pytest.raises(ValueError):
        with launcher.launch("realistic_site"):
            pass


def test_reserve_and_release_roundtrip():
    _establish_fixture_limit(1)
    assert _try_reserve_fixture() is True
    assert _try_reserve_fixture() is False  # 上限到達
    _release_fixture()
    assert _reserved_fixture_count() == 0
