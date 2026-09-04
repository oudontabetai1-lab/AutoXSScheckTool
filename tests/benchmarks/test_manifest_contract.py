from copy import deepcopy

import pytest

from wscan.benchmark_model import (
    ManifestError,
    load_manifest,
)
from wscan.scanner_contract import Carrier, ValueKind
from wscan.scanners import SCANNERS


REGISTRY_KEYS = frozenset(SCANNERS)


def _manifest():
    vulnerable_id = "sample.xss.search.q.vulnerable"
    safe_id = "sample.xss.search.q.safe"
    common = {
        "check": "xss",
        "request": {"method": "GET", "path": "/search"},
        "injection": {
            "carrier": "query",
            "parameter_id": "q",
            "value_kind": "string",
        },
        "taxonomy": ["reflected", "unauthenticated"],
        "difficulty": "low",
        "prerequisites": ["chromium"],
        "match": {"path": "/search", "field": "q", "location": "url_param"},
    }
    return {
        "schema_version": 1,
        "suite_id": "sample",
        "fixture_id": "sample_fixture",
        "runner_profile": "browser",
        "mode": "normal-deterministic",
        "source_kind": "first_party",
        "cases": [
            {
                **common,
                "case_id": vulnerable_id,
                "expected": "vulnerable",
                "twin_id": safe_id,
                "gate": "required",
            },
            {
                **common,
                "case_id": safe_id,
                "expected": "safe",
                "twin_id": vulnerable_id,
                "gate": "observed",
            },
        ],
    }


def _load(data):
    return load_manifest(data, registry_keys=REGISTRY_KEYS)


def test_valid_manifest_loads_as_immutable_contract_enums():
    suite = _load(_manifest())

    assert len(suite.cases) == 2
    assert isinstance(suite.cases, tuple)
    assert suite.cases[0].injection is not None
    assert suite.cases[0].injection.carrier is Carrier.QUERY
    assert suite.cases[0].injection.value_kind is ValueKind.STRING


def test_duplicate_case_id_is_rejected():
    data = _manifest()
    data["cases"][1]["case_id"] = data["cases"][0]["case_id"]

    with pytest.raises(ManifestError):
        _load(data)


def test_missing_twin_is_rejected():
    data = _manifest()
    data["cases"] = data["cases"][:1]

    with pytest.raises(ManifestError):
        _load(data)


def test_twin_that_is_not_safe_is_rejected():
    data = _manifest()
    data["cases"][1]["expected"] = "vulnerable"

    with pytest.raises(ManifestError):
        _load(data)


def test_unknown_registry_check_is_rejected():
    data = _manifest()
    data["cases"][0]["check"] = "jwt_weak_secret"

    with pytest.raises(ManifestError):
        _load(data)


def test_unknown_carrier_is_rejected():
    data = _manifest()
    data["cases"][0]["injection"]["carrier"] = "url_param"

    with pytest.raises(ManifestError):
        _load(data)


def test_unknown_value_kind_is_rejected():
    data = _manifest()
    data["cases"][0]["injection"]["value_kind"] = "text"

    with pytest.raises(ManifestError):
        _load(data)


def test_gap_without_complete_gap_info_is_rejected():
    for gap in (None, {"reason": "not wired", "owner_task": "0034-C"}):
        data = _manifest()
        data["cases"][0]["gate"] = "gap"
        if gap is not None:
            data["cases"][0]["gap"] = gap

        with pytest.raises(ManifestError):
            _load(data)


def test_schema_version_other_than_one_is_rejected():
    data = _manifest()
    data["schema_version"] = 2

    with pytest.raises(ManifestError):
        _load(data)


def test_unknown_top_level_key_and_type_mismatch_are_rejected():
    unknown = _manifest()
    unknown["runner"] = "surprise"
    wrong_type = deepcopy(_manifest())
    wrong_type["cases"] = "not-a-list"

    with pytest.raises(ManifestError):
        _load(unknown)
    with pytest.raises(ManifestError):
        _load(wrong_type)
