"""ネイティブ TOTP の生成・解析・入力解決を検証する。"""
import base64
import sys

import pytest

from wscan import totp


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1234567890, "89005924"),
    ],
)
def test_generate_totp_rfc6238_sha1(timestamp, expected):
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert totp.generate_totp(secret, digits=8, timestamp=timestamp) == expected


def test_generate_totp_rfc6238_sha256():
    seed = "12345678901234567890123456789012".encode()
    secret = base64.b32encode(seed).decode()
    assert (
        totp.generate_totp(secret, digits=8, algorithm="SHA256", timestamp=59)
        == "46119246"
    )


def test_generate_totp_rfc6238_sha512():
    seed = ("1234567890" * 6 + "1234").encode()
    secret = base64.b32encode(seed).decode()
    assert (
        totp.generate_totp(secret, digits=8, algorithm="SHA512", timestamp=59)
        == "90693936"
    )


def test_generate_totp_invalid_inputs_return_none():
    assert totp.generate_totp("not-base32!") is None
    assert totp.generate_totp("GEZDGNBVGY3TQOJQ", digits=0) is None
    assert totp.generate_totp("GEZDGNBVGY3TQOJQ", period=0) is None
    assert totp.generate_totp("GEZDGNBVGY3TQOJQ", algorithm="MD5") is None


@pytest.mark.parametrize("digits", [1000000000, 0, -1, "abc"])
def test_generate_totp_rejects_out_of_range_digits_immediately(digits):
    assert totp.generate_totp("GEZDGNBVGY3TQOJQ", digits=digits, timestamp=59) is None


@pytest.mark.parametrize("digits", [6, 8])
def test_generate_totp_keeps_supported_digits(digits):
    code = totp.generate_totp("GEZDGNBVGY3TQOJQ", digits=digits, timestamp=59)

    assert code is not None
    assert len(code) == digits


@pytest.mark.parametrize("period", [0, -1, 86401, "abc"])
def test_generate_totp_rejects_out_of_range_period(period):
    assert totp.generate_totp("GEZDGNBVGY3TQOJQ", period=period, timestamp=59) is None


def test_normalize_base32():
    assert totp.normalize_base32(" gezd-gnbv gy3tqojq ") == "GEZDGNBVGY3TQOJQ"
    assert totp.normalize_base32("mzxw6") == "MZXW6==="


def test_parse_otpauth_uri_full_parameters():
    parsed = totp.parse_otpauth_uri(
        "otpauth://totp/Example%20Co:alice%40example.com?"
        "secret=GEZDGNBVGY3TQOJQ&issuer=Example%20Co&algorithm=SHA256&digits=8&period=45"
    )
    assert parsed == {
        "secret": "GEZDGNBVGY3TQOJQ",
        "digits": 8,
        "period": 45,
        "algorithm": "SHA256",
        "label": "Example Co:alice@example.com",
        "issuer": "Example Co",
    }


def test_parse_otpauth_uri_supplements_issuer_from_label():
    parsed = totp.parse_otpauth_uri(
        "otpauth://totp/Issuer%20Name:account?secret=GEZDGNBVGY3TQOJQ"
    )
    assert parsed is not None
    assert parsed["issuer"] == "Issuer Name"
    assert parsed["digits"] == 6
    assert parsed["period"] == 30
    assert parsed["algorithm"] == "SHA1"


@pytest.mark.parametrize(
    "uri",
    [
        "otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ",
        "otpauth:///x?secret=GEZDGNBVGY3TQOJQ",
        "otpauth://totp/x?issuer=Example",
    ],
)
def test_parse_otpauth_uri_rejects_unsupported_or_incomplete(uri):
    assert totp.parse_otpauth_uri(uri) is None


def test_parse_otpauth_uri_unknown_algorithm_falls_back_to_sha1():
    parsed = totp.parse_otpauth_uri(
        "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&algorithm=MD5"
    )
    assert parsed is not None
    assert parsed["algorithm"] == "SHA1"


@pytest.mark.parametrize("digits", ["1000000000", "0", "-1", "abc"])
def test_parse_otpauth_uri_defaults_invalid_digits(digits):
    parsed = totp.parse_otpauth_uri(
        "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&digits=" + digits
    )

    assert parsed is not None
    assert parsed["digits"] == 6


@pytest.mark.parametrize("period", ["0", "-1", "86401", "abc"])
def test_parse_otpauth_uri_defaults_invalid_period(period):
    parsed = totp.parse_otpauth_uri(
        "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&period=" + period
    )

    assert parsed is not None
    assert parsed["period"] == 30


def test_resolve_totp_secret_uri_precedes_secret():
    resolved = totp.resolve_totp_secret(
        uri="otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&digits=8&period=45",
        secret="MZXW6",
        digits=7,
        period=60,
    )
    assert resolved == {
        "secret": "GEZDGNBVGY3TQOJQ",
        "digits": 8,
        "period": 45,
        "algorithm": "SHA1",
    }


def test_resolve_totp_secret_qr_precedes_secret(monkeypatch):
    monkeypatch.setattr(totp, "decode_qr_image", lambda _path: "MZXW6")
    resolved = totp.resolve_totp_secret(
        qr="code.png", secret="GEZDGNBVGY3TQOJQ", digits=7, period=60, algorithm="SHA512"
    )
    assert resolved == {
        "secret": "MZXW6",
        "digits": 7,
        "period": 60,
        "algorithm": "SHA512",
    }


def test_resolve_totp_secret_raw_parameters():
    assert totp.resolve_totp_secret(
        secret="GEZDGNBVGY3TQOJQ", digits=8, period=45, algorithm="SHA256"
    ) == {
        "secret": "GEZDGNBVGY3TQOJQ",
        "digits": 8,
        "period": 45,
        "algorithm": "SHA256",
    }


def test_resolve_totp_secret_bounds_raw_parameters():
    resolved = totp.resolve_totp_secret(
        secret="GEZDGNBVGY3TQOJQ",
        digits=1000000000,
        period=1000000000,
    )

    assert resolved is not None
    assert resolved["digits"] == 6
    assert resolved["period"] == 30


def test_resolve_totp_secret_bounds_raw_qr_parameters(monkeypatch):
    monkeypatch.setattr(totp, "decode_qr_image", lambda _path: "GEZDGNBVGY3TQOJQ")

    resolved = totp.resolve_totp_secret(
        qr="code.png",
        digits="abc",
        period=-1,
    )

    assert resolved is not None
    assert resolved["digits"] == 6
    assert resolved["period"] == 30


def test_decode_qr_image_missing_path_returns_none(tmp_path):
    assert totp.decode_qr_image(str(tmp_path / "missing.png")) is None


def test_decode_qr_image_round_trip(tmp_path):
    pytest.importorskip("cv2")
    qrcode = pytest.importorskip("qrcode")
    uri = "otpauth://totp/Test:alice?secret=GEZDGNBVGY3TQOJQ&issuer=Test"
    path = tmp_path / "totp.png"
    qrcode.make(uri).save(path)
    assert totp.decode_qr_image(str(path)) == uri


def test_scan_cli_accepts_totp_and_bearer_options(monkeypatch):
    import main

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "scan",
            "https://example.test",
            "--bearer",
            "token-value",
            "--mfa-totp-secret",
            "GEZDGNBVGY3TQOJQ",
            "--mfa-totp-digits",
            "8",
            "--mfa-totp-period",
            "45",
            "--mfa-totp-algorithm",
            "SHA256",
        ],
    )
    args = main.parse_args()
    assert args.bearer == "token-value"
    assert args.mfa_totp_secret == "GEZDGNBVGY3TQOJQ"
    assert args.mfa_totp_digits == 8
    assert args.mfa_totp_period == 45
    assert args.mfa_totp_algorithm == "SHA256"
