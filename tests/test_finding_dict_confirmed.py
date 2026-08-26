"""finding_dict_confirmed の解決規則と SARIF 後方互換の回帰（#107 Codex P2）。

verified 欠落の旧 dict や verification_state だけの dict を未確証へ格下げしない。
"""
from wscan.scanners.base import finding_dict_confirmed
from wscan.sarif import SarifExporter


def test_resolution_rules():
    assert finding_dict_confirmed({"verified": True}) is True
    assert finding_dict_confirmed({"verified": False, "verification_state": "assumed"}) is False
    # verified 欠落 + state=reproduced → confirmed（冗長 bool が無くても格下げしない）
    assert finding_dict_confirmed({"verification_state": "reproduced"}) is True
    assert finding_dict_confirmed({"verification_state": "assumed"}) is False
    # verified も state も無い旧 dict → 従来の confirmed 既定を保つ
    assert finding_dict_confirmed({}) is True


def test_sarif_legacy_reproduced_without_verified_is_confirmed():
    d = {
        "check_type": "sqli", "severity": "high", "url": "u", "field_name": "q",
        "payload": "p", "evidence": "e", "verification_state": "reproduced",
    }
    run = SarifExporter().export([d], target_url="t")["runs"][0]
    assert run["results"][0]["level"] == "error"
    assert run["properties"]["total_findings"] == 1


def test_sarif_unverified_is_note_and_excluded_from_confirmed_total():
    d = {
        "check_type": "sqli", "severity": "high", "url": "u", "field_name": "q",
        "payload": "p", "evidence": "e", "verified": False, "verification_state": "assumed",
    }
    run = SarifExporter().export([d], target_url="t")["runs"][0]
    assert run["results"][0]["level"] == "note"
    assert run["properties"]["total_findings"] == 0
    assert run["properties"]["hypothesis_findings"] == 1
