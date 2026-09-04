"""0016: --all-checks フラグのテスト。"""
import sys
from unittest import mock

import main
from wscan.scanners import SCANNERS


def _parse(*cli_args):
    argv = ["main.py", "scan", "http://example.com", *cli_args]
    with mock.patch.object(sys, "argv", argv):
        return main.parse_args()


def test_all_checks_flag_defaults_false():
    args = _parse()
    assert getattr(args, "all_checks", False) is False


def test_all_checks_flag_sets_true():
    args = _parse("--all-checks")
    assert args.all_checks is True


def test_all_checks_selects_full_registry():
    # run_scan の checks_list override 相当のロジック: all_checks なら全 registry。
    args = _parse("--all-checks", "--checks", "sqli")
    checks_list = list(args.checks)
    if getattr(args, "all_checks", False):
        checks_list = list(SCANNERS.keys())
    assert set(checks_list) == set(SCANNERS.keys())
    assert len(checks_list) == len(SCANNERS)


def test_without_all_checks_respects_explicit_checks():
    args = _parse("--checks", "sqli", "xss")
    checks_list = list(args.checks)
    if getattr(args, "all_checks", False):
        checks_list = list(SCANNERS.keys())
    assert checks_list == ["sqli", "xss"]
