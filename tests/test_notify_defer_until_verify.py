"""検出時通知の保留判定の回帰（#107 Codex P1）。

verify で最終 state が確定する finding（verifiable かつ非 dialog）は検出時に通知せず、
reproduced 確定後にのみ通知する。confidence=confirmed 起点でも早期 confirmed 誤通知を防ぐ。
"""
from wscan.engine import ScanEngine
from wscan.scanners.base import Finding


def _mk(ct, dialog=False, conf="confirmed"):
    return Finding(
        check_type=ct, severity="high", url="u", field_name="q",
        payload="p", evidence="e", dialog_confirmed=dialog, confidence=conf,
    )


def test_defer_verifiable_nondialog():
    eng = ScanEngine.__new__(ScanEngine)
    # sqli(verifiable, 非 dialog, confidence=confirmed で reproduced 起点) は保留
    assert eng._notify_defer_until_verify(_mk("sqli")) is True


def test_no_defer_for_dialog_or_nonverifiable():
    eng = ScanEngine.__new__(ScanEngine)
    # dialog 確証 xss は verify を通らない → 検出時に通知
    assert eng._notify_defer_until_verify(_mk("xss", dialog=True)) is False
    # mail_header は _VERIFIABLE_CHECKS 非対象 → 検出時に通知
    assert eng._notify_defer_until_verify(_mk("mail_header")) is False
