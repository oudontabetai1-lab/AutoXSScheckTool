"""0035-C: dispatcher facade の純粋な結果型と分類 hint のテスト。"""
from dataclasses import FrozenInstanceError

import pytest

from wscan.dispatch_result import DispatchResult, DispatchState, transport_hint_for
from wscan.scanner_contract import Carrier, TransportKind


def test_dispatch_state_values():
    assert {state.value for state in DispatchState} == {
        "sent",
        "unsupported",
        "blocked",
        "unexecutable",
        "transport_error",
    }


@pytest.mark.parametrize(
    ("state", "pair", "sent", "has_response"),
    [
        (DispatchState.SENT, {"response": "ok"}, True, True),
        (DispatchState.SENT, {}, True, False),
        (DispatchState.TRANSPORT_ERROR, {"response": "partial"}, False, False),
        (DispatchState.BLOCKED, {}, False, False),
    ],
)
def test_dispatch_result_properties(state, pair, sent, has_response):
    result = DispatchResult(state=state, carrier=Carrier.QUERY, pair=pair)

    assert result.sent is sent
    assert result.has_response is has_response


def test_dispatch_result_is_frozen_and_pair_defaults_are_independent():
    first = DispatchResult(state=DispatchState.BLOCKED, carrier=Carrier.FORM)
    second = DispatchResult(state=DispatchState.BLOCKED, carrier=Carrier.FORM)

    assert first.pair is not second.pair
    with pytest.raises(FrozenInstanceError):
        first.state = DispatchState.SENT


@pytest.mark.parametrize(
    ("carrier", "expected"),
    [
        (Carrier.QUERY, TransportKind.PLAYWRIGHT),
        (Carrier.FORM, TransportKind.PLAYWRIGHT),
        (Carrier.JSON, TransportKind.HTTPX),
        (Carrier.XML, None),
    ],
)
def test_transport_hint_for(carrier, expected):
    assert transport_hint_for(carrier) is expected
