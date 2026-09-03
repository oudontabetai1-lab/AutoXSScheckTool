import pytest

from wscan.scanners import SCANNERS
from wscan.scanner_contract import (
    Carrier, CapabilityState, ExecutionKind, StateChangeClass,
    ScannerContract, validate_scanner_contract, build_capability_matrix,
)

# SUPPORTS_JSON_BODY 実値と JSON carrier supported の一致を免除する既知例外
_JSON_FLAG_ALLOWLIST = {"mass_assignment", "prototype_pollution"}  # api_seed 経由で JSON を扱うが base json 経路は使わない


def _contracts():
    return {check: cls.CONTRACT for check, cls in SCANNERS.items()}


def test_every_scanner_declares_contract():
    for check, cls in SCANNERS.items():
        assert hasattr(cls, "CONTRACT"), f"{check}: missing CONTRACT"
        assert isinstance(cls.CONTRACT, ScannerContract), f"{check}: CONTRACT wrong type"


def test_contracts_are_statically_valid():
    errors = []
    for check, cls in SCANNERS.items():
        errors += validate_scanner_contract(check, cls.CONTRACT)
    assert not errors, "contract violations:\n" + "\n".join(errors)


def test_all_carriers_classified():
    for check, cls in SCANNERS.items():
        classified = {c.carrier for c in cls.CONTRACT.capabilities}
        assert classified == set(Carrier), (
            f"{check}: carriers not fully classified: {set(Carrier) - classified}"
        )


def test_old_flags_match_contract():
    mismatches = []
    for check, cls in SCANNERS.items():
        contract = cls.CONTRACT
        # JSON carrier ⟺ SUPPORTS_JSON_BODY（mass_assignment は既知例外）
        if check not in _JSON_FLAG_ALLOWLIST:
            json_supported = Carrier.JSON in contract.supported_carriers()
            if bool(getattr(cls, "SUPPORTS_JSON_BODY", False)) != json_supported:
                mismatches.append(f"{check}: SUPPORTS_JSON_BODY vs JSON carrier")
        # HAS_PAGE_LEVEL ⟺ PAGE_ANALYSIS
        if bool(getattr(cls, "HAS_PAGE_LEVEL", False)) != (
            ExecutionKind.PAGE_ANALYSIS in contract.execution_kinds
        ):
            mismatches.append(f"{check}: HAS_PAGE_LEVEL vs PAGE_ANALYSIS")
        # ALWAYS_STATE_CHANGING ⟺ state_change==ALWAYS
        if bool(getattr(cls, "ALWAYS_STATE_CHANGING", False)) != (
            contract.state_change == StateChangeClass.ALWAYS
        ):
            mismatches.append(f"{check}: ALWAYS_STATE_CHANGING vs state_change")
    assert not mismatches, "old-flag/contract drift:\n" + "\n".join(mismatches)


def test_capability_matrix_shape():
    matrix = build_capability_matrix(_contracts())
    assert set(matrix["scanners"]) == set(SCANNERS)
    for check, row in matrix["scanners"].items():
        assert set(row["carriers"]) == {c.value for c in Carrier}
        for carrier, cell in row["carriers"].items():
            assert cell["symbol"] in {"s", "P", "U", "?"}
            assert cell["symbol"] != "?", f"{check}:{carrier} unclassified"
            # capability の全次元がセルに載っていること（下流の再構成用）
            for key in ("transports", "payload_shapes", "value_kinds"):
                assert isinstance(cell[key], list), f"{check}:{carrier} {key}"
            assert isinstance(cell["browser_required"], bool)
            assert isinstance(cell["structured_payload"], bool)
            if cell["symbol"] == "s":  # supported は payload_shapes を必ず持つ
                assert cell["payload_shapes"], f"{check}:{carrier} supported without payload_shapes"
