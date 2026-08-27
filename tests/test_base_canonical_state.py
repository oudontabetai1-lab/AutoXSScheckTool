"""base.py が検証状態を VerificationState enum を正本に扱うことの回帰（0015 MODEL-001b）。

挙動は #105 と不変（str Enum なので文字列比較と等価）。canonical 語彙の採用を固定する。
"""
from wscan.scanners.base import Finding, finding_dict_confirmed
from wscan.verification_model import VerificationState


def _finding(**kw):
    base = dict(check_type="xss", severity="medium", url="/a", field_name="q",
                payload="x", evidence="e")
    base.update(kw)
    return Finding(**base)


def test_default_state_assumed_for_non_decisive():
    f = _finding()
    assert f.verification_state == VerificationState.ASSUMED
    assert f.verification_state == "assumed"  # str Enum 互換
    assert f.verified is False


def test_default_state_reproduced_when_dialog_confirmed():
    f = _finding(dialog_confirmed=True)
    assert f.verification_state == VerificationState.REPRODUCED
    assert f.verified is True


def test_default_state_reproduced_when_confidence_confirmed():
    f = _finding(confidence="confirmed")
    assert f.verified is True


def test_apply_verification_and_confirmed_agree_with_enum():
    f = _finding()
    f.apply_verification(VerificationState.UNREPRODUCED.value)
    assert f.verified is False
    d = f.to_dict()
    assert finding_dict_confirmed(d) is False
    f.apply_verification(VerificationState.REPRODUCED.value)
    assert finding_dict_confirmed(f.to_dict()) is True
