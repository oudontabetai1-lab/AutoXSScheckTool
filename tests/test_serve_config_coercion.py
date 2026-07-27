"""serve モードへ届くダッシュボード/config 値の正規化テスト。"""

import pytest

import main
from wscan.header_manager import apply_bearer


def test_coerce_headers_parses_header_text():
    assert main._coerce_headers("Authorization: Bearer x\nX-A: b") == {
        "Authorization": "Bearer x",
        "X-A": "b",
    }


def test_coerce_headers_copies_dict():
    source = {"X-A": "b"}

    result = main._coerce_headers(source)

    assert result == source
    assert result is not source


@pytest.mark.parametrize("value", ["", None, "not a header", [], 42])
def test_coerce_headers_returns_empty_for_empty_or_unparseable_input(value):
    assert main._coerce_headers(value) == {}


def test_coerced_header_text_can_be_passed_to_apply_bearer():
    headers = main._coerce_headers("X-A: b")

    assert apply_bearer(headers, "token") == {
        "X-A": "b",
        "Authorization": "Bearer token",
    }


@pytest.mark.parametrize("value", ["6x", "", None, -1, "-2", "６"])
def test_safe_int_falls_back_for_invalid_unset_negative_or_fullwidth(value):
    assert main._safe_int(value, 17) == 17


@pytest.mark.parametrize(
    ("value", "expected"),
    [(0, 0), (6, 6), ("8", 8), (" +9 ", 9)],
)
def test_safe_int_returns_normal_values_as_int(value, expected):
    result = main._safe_int(value, 17)

    assert result == expected
    assert isinstance(result, int)


def test_serve_integer_coercion_keeps_engine_construction_inputs_safe():
    cfg = {
        "depth": "6x",
        "timeout": "３０",
        "concurrency": -2,
        "mfa_totp_digits": "6x",
        "mfa_totp_period": "45",
        "max_payloads": "",
    }

    values, invalid = main._coerce_serve_ints(cfg)

    class StubEngine:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    engine = StubEngine(
        depth=values["depth"],
        timeout=values["timeout"],
        concurrency=values["concurrency"],
        mfa_totp_digits=values["mfa_totp_digits"],
        mfa_totp_period=values["mfa_totp_period"],
        max_payloads=values["max_payloads"],
    )

    assert engine.kwargs == {
        "depth": 2,
        "timeout": 30,
        "concurrency": 1,
        "mfa_totp_digits": 0,
        "mfa_totp_period": 45,
        "max_payloads": 0,
    }
    assert invalid == {
        "depth": "6x",
        "timeout": "３０",
        "concurrency": -2,
        "mfa_totp_digits": "6x",
    }
