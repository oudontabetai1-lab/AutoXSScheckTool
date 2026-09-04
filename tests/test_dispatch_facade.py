"""0035-C: typed facade が既存 dispatch の挙動を変えないことを fake で検証する。"""
from types import SimpleNamespace

import pytest

from wscan.dispatch_result import DispatchState
from wscan.injection_point import InjectionPoint
from wscan.scanner_contract import (
    CapabilityState,
    Carrier,
    CarrierCapability,
    ExecutionKind,
    PayloadShape,
    ScannerContract,
    TransportKind,
    ValueKind,
)
from wscan.scanners.base import BaseScanner


def _supported_cap(carrier: Carrier, transport: TransportKind) -> CarrierCapability:
    return CarrierCapability(
        carrier=carrier,
        state=CapabilityState.SUPPORTED,
        value_kinds=frozenset({ValueKind.STRING}),
        transports=frozenset({transport}),
        payload_shapes=frozenset({PayloadShape.SCALAR}),
    )


class _FakeScanner(BaseScanner):
    CHECK_TYPE = "fake"
    # capability guard を通すため query/form を supported にした最小 CONTRACT（JSON は非宣言＝
    # capability()=None → UNSUPPORTED）。registry 非登録の test fake なので validate 対象外。
    CONTRACT = ScannerContract(
        execution_kinds=frozenset({ExecutionKind.FIELD_INJECTION}),
        capabilities=(
            _supported_cap(Carrier.QUERY, TransportKind.PLAYWRIGHT),
            _supported_cap(Carrier.FORM, TransportKind.PLAYWRIGHT),
        ),
    )

    def __init__(self, apply_result=("", {}), apply_error=None):
        engine = SimpleNamespace(
            browser=None,
            monitor=None,
            payload_gen=None,
            state_profile="unrestricted",
            wave_errors=[],
        )
        super().__init__(engine)
        self.apply_result = apply_result
        self.apply_error = apply_error
        self.apply_calls = []

    async def scan_field(self, url, form_index, field, is_url_param=False):
        return []

    async def _apply_ip(self, ip, payload):
        self.apply_calls.append((ip, payload))
        if self.apply_error is not None:
            raise self.apply_error
        return self.apply_result


class _JsonFakeScanner(_FakeScanner):
    SUPPORTS_JSON_BODY = True
    CONTRACT = ScannerContract(
        execution_kinds=frozenset({ExecutionKind.FIELD_INJECTION}),
        capabilities=(
            _supported_cap(Carrier.QUERY, TransportKind.PLAYWRIGHT),
            _supported_cap(Carrier.FORM, TransportKind.PLAYWRIGHT),
            _supported_cap(Carrier.JSON, TransportKind.HTTPX),
        ),
    )


@pytest.mark.asyncio
async def test_dispatch_sent_preserves_legacy_source_pair_and_carrier():
    pair = {"request": {"url": "http://t/?q=x"}, "response": {"status": 200}}
    scanner = _FakeScanner(("http://t/?q=x", pair))
    ip = InjectionPoint.for_url_param("http://t/", "q")

    result = await scanner.dispatch(ip, "x")

    assert result.state is DispatchState.SENT
    assert result.sent is True
    assert result.source == "http://t/?q=x"
    assert result.pair is pair
    assert result.carrier is Carrier.QUERY
    assert result.transport is TransportKind.PLAYWRIGHT
    assert scanner.apply_calls == [(ip, "x")]


@pytest.mark.asyncio
async def test_dispatch_unsupported_json_does_not_call_apply_ip():
    scanner = _FakeScanner(("should-not-be-used", {"response": {}}))
    ip = InjectionPoint.for_json_body("POST", "http://t/api", "/name")

    result = await scanner.dispatch(ip, "x")

    assert result.state is DispatchState.UNSUPPORTED
    assert result.carrier is Carrier.JSON
    assert result.source == ""
    assert result.pair == {}
    assert scanner.apply_calls == []


@pytest.mark.asyncio
async def test_dispatch_blocked_by_state_profile_does_not_send_or_log_twice():
    scanner = _FakeScanner(("should-not-be-used", {"response": {}}))
    scanner.engine.state_profile = "controlled-write"
    ip = InjectionPoint.for_form(
        "http://t/account/delete",
        "confirm",
        method="POST",
        action="http://t/account/delete",
    )

    result = await scanner.dispatch(ip, "yes")

    assert result.state is DispatchState.BLOCKED
    assert result.carrier is Carrier.FORM
    assert scanner.apply_calls == []
    assert scanner.engine.wave_errors == []


@pytest.mark.asyncio
async def test_dispatch_empty_pair_after_gates_is_transport_error():
    scanner = _JsonFakeScanner(("http://t/api", {}))
    ip = InjectionPoint.for_json_body("POST", "http://t/api", "/name")

    result = await scanner.dispatch(ip, "x")

    assert result.state is DispatchState.TRANSPORT_ERROR
    assert result.source == "http://t/api"
    assert result.pair == {}
    assert result.carrier is Carrier.JSON
    assert result.transport is TransportKind.HTTPX
    assert result.note == "empty result after gates (json unexecutable/transport 未区別)"
    assert scanner.apply_calls == [(ip, "x")]


@pytest.mark.asyncio
async def test_dispatch_propagates_apply_ip_exception_unchanged():
    error = RuntimeError("transport failed")
    scanner = _FakeScanner(apply_error=error)
    ip = InjectionPoint.for_url_param("http://t/", "q")

    with pytest.raises(RuntimeError) as caught:
        await scanner.dispatch(ip, "x")

    assert caught.value is error
    assert scanner.apply_calls == [(ip, "x")]


@pytest.mark.asyncio
@pytest.mark.parametrize("alias", ["query", "json"])
async def test_dispatch_rejects_noncanonical_location_before_apply(alias):
    scanner = _FakeScanner(("should-not-be-used", {"response": {}}))
    ip = InjectionPoint(location=alias, url="http://t/", parameter_id="q")

    with pytest.raises(ValueError, match="carrier 未対応"):
        await scanner.dispatch(ip, "x")

    assert scanner.apply_calls == []


@pytest.mark.asyncio
async def test_dispatch_returns_unsupported_for_page_scanner_carrier():
    """page scanner（CONTRACT で query/form unsupported・_apply_payload 無し）に dispatch を
    query で呼んでも _apply_ip へ達して AttributeError にならず UNSUPPORTED を返す（0035-C レビュー）。"""
    from wscan.scanners.clickjacking import ClickjackingScanner

    scanner = ClickjackingScanner.__new__(ClickjackingScanner)
    scanner.engine = SimpleNamespace(state_profile="unrestricted", attempt_ledger=None)
    scanner.monitor = None
    ip = InjectionPoint.for_url_param("http://x", "q")

    result = await scanner.dispatch(ip, "PAYLOAD")

    assert result.state is DispatchState.UNSUPPORTED


@pytest.mark.asyncio
async def test_dispatch_send_override_preserves_dom_xss_argument_order():
    """DOMXSSScanner の独自 _apply_payload シグネチャ (url, field_name, payload, form_index,
    is_url_param) を facade が正しい順で呼ぶ（base の _apply_ip 順ではない）（0035-C レビュー）。"""
    from wscan.scanners.dom_xss import DOMXSSScanner

    scanner = DOMXSSScanner.__new__(DOMXSSScanner)
    scanner.engine = SimpleNamespace(state_profile="unrestricted", attempt_ledger=None)
    scanner.monitor = None
    seen = {}

    async def fake_apply(url, field_name, payload, form_index=0, is_url_param=False):
        seen.update(field_name=field_name, payload=payload, form_index=form_index,
                    is_url_param=is_url_param)
        return "SRC", {"request": {}, "response": {}}

    scanner._apply_payload = fake_apply
    ip = InjectionPoint.for_form("http://x", "myfield", form_index=3)

    result = await scanner.dispatch(ip, "ATTACK")

    assert result.state is DispatchState.SENT
    assert seen["field_name"] == "myfield"
    assert seen["payload"] == "ATTACK"
    assert seen["form_index"] == 3
    assert seen["is_url_param"] is False
