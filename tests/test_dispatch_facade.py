"""0035-C: typed facade が既存 dispatch の挙動を変えないことを fake で検証する。"""
from types import SimpleNamespace

import pytest

from wscan.dispatch_result import DispatchState
from wscan.injection_point import InjectionPoint
from wscan.scanner_contract import Carrier, TransportKind
from wscan.scanners.base import BaseScanner


class _FakeScanner(BaseScanner):
    CHECK_TYPE = "fake"

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
