"""非 dialog でも confidence='confirmed' の決定的 finding は reproduced 扱いになる回帰。

#105 段階1 で非 dialog 既定を assumed(=verified False) にした際、_VERIFIABLE_CHECKS に
含まれない決定的プロデューサ（mail_header の OOB 到達確証など）が review-only に落ちる
P1 リグレッションを防ぐ。
"""
from wscan.scanners.base import Finding
from wscan.action_plan import _is_actionable


def _mk(check_type, confidence, dialog=False):
    return Finding(
        check_type=check_type, severity="high", url="http://t/",
        field_name="f", payload="p", evidence="e",
        confidence=confidence, dialog_confirmed=dialog,
    )


def test_confirmed_nondialog_is_reproduced_and_actionable():
    # mail_header は _VERIFIABLE_CHECKS 非対象＝_phase_verify が state を補正しない。
    f = _mk("mail_header", "confirmed")
    assert f.verification_state == "reproduced"
    assert f.verified is True
    assert _is_actionable(f) is True


def test_nonconfirmed_nondialog_stays_assumed():
    for conf in ("likely", "tentative"):
        f = _mk("xss", conf)
        assert f.verification_state == "assumed"
        assert f.verified is False


def test_dialog_still_reproduced():
    f = _mk("xss", "tentative", dialog=True)
    assert f.verification_state == "reproduced"
    assert f.verified is True
