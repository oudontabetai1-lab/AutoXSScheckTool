"""RFC 6238 準拠のネイティブ TOTP 生成と入力解決。"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import time
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, unquote, urlparse


_ALGORITHMS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}

_MIN_TOTP_DIGITS = 6
_MAX_TOTP_DIGITS = 10
_DEFAULT_TOTP_DIGITS = 6
_MIN_TOTP_PERIOD = 1
_MAX_TOTP_PERIOD = 24 * 60 * 60
_DEFAULT_TOTP_PERIOD = 30


def _bounded_int(value, minimum: int, maximum: int, default=None):
    """整数を安全に範囲検証し、不正値は ``default`` へ落とす。"""
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return parsed if minimum <= parsed <= maximum else default


def normalize_base32(secret: str) -> str:
    """空白とハイフンを除去し、大文字化とパディング補完を行う。"""
    try:
        normalized = re.sub(r"[\s-]+", "", str(secret or "")).upper()
        return normalized + "=" * ((-len(normalized)) % 8)
    except Exception:
        return ""


def parse_otpauth_uri(uri: str) -> Optional[dict]:
    """TOTP 用 ``otpauth://`` URI を解析し、生成パラメータを返す。"""
    try:
        parsed = urlparse(str(uri or "").strip())
        if parsed.scheme.lower() != "otpauth" or parsed.netloc.lower() != "totp":
            return None
        query = parse_qs(parsed.query, keep_blank_values=True)
        secret = (query.get("secret") or [""])[0].strip()
        if not secret:
            return None

        algorithm = str((query.get("algorithm") or ["SHA1"])[0]).upper()
        if algorithm not in _ALGORITHMS:
            algorithm = "SHA1"
        label = unquote(parsed.path.lstrip("/"))
        issuer = str((query.get("issuer") or [""])[0])
        if not issuer and ":" in label:
            issuer = label.split(":", 1)[0]
        return {
            "secret": secret,
            "digits": _bounded_int(
                (query.get("digits") or [_DEFAULT_TOTP_DIGITS])[0],
                _MIN_TOTP_DIGITS,
                _MAX_TOTP_DIGITS,
                _DEFAULT_TOTP_DIGITS,
            ),
            "period": _bounded_int(
                (query.get("period") or [_DEFAULT_TOTP_PERIOD])[0],
                _MIN_TOTP_PERIOD,
                _MAX_TOTP_PERIOD,
                _DEFAULT_TOTP_PERIOD,
            ),
            "algorithm": algorithm,
            "label": label,
            "issuer": issuer,
        }
    except Exception:
        return None


def decode_qr_image(path: str) -> Optional[str]:
    """QR 画像を読み取り、埋め込まれた文字列を返す。失敗時は ``None``。"""
    try:
        if not path or not Path(path).is_file():
            return None
        import cv2  # type: ignore

        image = cv2.imread(path)
        if image is None:
            return None
        data, _points, _straight = cv2.QRCodeDetector().detectAndDecode(image)
        return data if isinstance(data, str) and data else None
    except Exception:
        return None


def generate_totp(
    secret_base32: str,
    *,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
    timestamp: Optional[float] = None,
) -> Optional[str]:
    """RFC 6238 の TOTP コードを生成する純粋関数。"""
    try:
        digits = _bounded_int(digits, _MIN_TOTP_DIGITS, _MAX_TOTP_DIGITS)
        period = _bounded_int(period, _MIN_TOTP_PERIOD, _MAX_TOTP_PERIOD)
        algorithm = str(algorithm or "").upper()
        if (
            not secret_base32
            or digits is None
            or period is None
            or algorithm not in _ALGORITHMS
        ):
            return None
        normalized = normalize_base32(secret_base32)
        if not normalized:
            return None
        key = base64.b32decode(normalized, casefold=False)
        if not key:
            return None
        now = time.time() if timestamp is None else float(timestamp)
        counter = int(now // period)
        if counter < 0:
            return None
        digest = hmac.new(
            key,
            counter.to_bytes(8, byteorder="big"),
            _ALGORITHMS[algorithm],
        ).digest()
        offset = digest[-1] & 0x0F
        binary = int.from_bytes(digest[offset:offset + 4], byteorder="big") & 0x7FFFFFFF
        return str(binary % (10 ** digits)).zfill(digits)
    except Exception:
        return None


def resolve_totp_secret(
    uri: str = "",
    secret: str = "",
    qr: str = "",
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
) -> Optional[dict]:
    """URI、QR、生 Base32 を優先順に TOTP 生成パラメータへ解決する。"""
    try:
        if uri:
            parsed = parse_otpauth_uri(uri)
            if parsed:
                return {key: parsed[key] for key in ("secret", "digits", "period", "algorithm")}
        if qr:
            decoded = decode_qr_image(qr)
            if decoded:
                decoded = decoded.strip()
                if decoded.lower().startswith("otpauth://"):
                    parsed = parse_otpauth_uri(decoded)
                    if parsed:
                        return {
                            key: parsed[key]
                            for key in ("secret", "digits", "period", "algorithm")
                        }
                else:
                    return {
                        "secret": decoded,
                        "digits": _bounded_int(
                            digits,
                            _MIN_TOTP_DIGITS,
                            _MAX_TOTP_DIGITS,
                            _DEFAULT_TOTP_DIGITS,
                        ),
                        "period": _bounded_int(
                            period,
                            _MIN_TOTP_PERIOD,
                            _MAX_TOTP_PERIOD,
                            _DEFAULT_TOTP_PERIOD,
                        ),
                        "algorithm": algorithm,
                    }
        if secret:
            return {
                "secret": secret,
                "digits": _bounded_int(
                    digits,
                    _MIN_TOTP_DIGITS,
                    _MAX_TOTP_DIGITS,
                    _DEFAULT_TOTP_DIGITS,
                ),
                "period": _bounded_int(
                    period,
                    _MIN_TOTP_PERIOD,
                    _MAX_TOTP_PERIOD,
                    _DEFAULT_TOTP_PERIOD,
                ),
                "algorithm": algorithm,
            }
    except Exception:
        return None
    return None
