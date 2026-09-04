"""0016: --all-checks フラグのテスト。

実効 check の解決は main._effective_checks に一元化されており、起動バナー表示
（_checks_display）と engine へ渡す checks_list が同一ソースから導かれる。テストは
その実関数を直接叩き、「表示＝実行」がコピペ乖離しないことを固定する。
"""
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
    args = _parse("--all-checks", "--checks", "sqli")
    checks_list = main._effective_checks(args)
    assert set(checks_list) == set(SCANNERS.keys())
    assert len(checks_list) == len(SCANNERS)


def test_without_all_checks_respects_explicit_checks():
    args = _parse("--checks", "sqli", "xss")
    assert main._effective_checks(args) == ["sqli", "xss"]


def test_dom_xss_flag_appends_when_missing():
    args = _parse("--checks", "sqli", "--dom-xss")
    assert main._effective_checks(args) == ["sqli", "dom_xss"]


def test_all_checks_display_matches_effective_execution():
    """起動バナーの表示が実際に実行される check と一致する（Codex P2 の乖離を固定）。"""
    args = _parse("--all-checks")
    display = main._checks_display(args)
    effective = main._effective_checks(args)
    # 表示は実効一覧をそのまま列挙する（sqli,xss,os の既定にフォールバックしない）。
    assert display == ", ".join(effective)
    assert set(effective) == set(SCANNERS.keys())
    # 既定 3 種の嘘表示になっていないこと。
    assert display != "sqli, xss, os"


def test_all_checks_overrides_explicit_checks_in_display():
    """--all-checks --checks sqli でも表示は SQLi 単独ではなく全 registry。"""
    args = _parse("--all-checks", "--checks", "sqli")
    assert main._checks_display(args) != "sqli"
    assert set(main._effective_checks(args)) == set(SCANNERS.keys())
