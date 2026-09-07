"""RFC 6238 準拠のネイティブ TOTP 生成と入力解決。"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import re
import time
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, unquote, urlparse

_log = logging.getLogger(__name__)


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


def _silence_cv2() -> None:
    """OpenCV の stderr へ出る WARN（``findDecoder`` 等）を抑制する（best-effort）。

    cv2 はデコード不能を C++ 層から stderr に直接吐くため、Python の except では
    握れず、利用者には脈絡のない WARN だけが見える。本ツールで cv2 を使うのは QR
    デコードのみなので、ここでログレベルを下げても副作用は無い。API 差異は無視する。
    """
    try:
        import cv2  # type: ignore

        cv2.utils.logging.setLogLevel(cv2.utils.logging.LOG_LEVEL_SILENT)
    except Exception:
        pass


def _load_image_bgr(data: bytes):
    """画像バイト列を numpy BGR 配列へ復号する。読めなければ ``None``。

    ``cv2.imread`` はファイルパス依存（非ASCII パスや一部ビルドで無言 ``None``）の
    ため使わず、まず ``cv2.imdecode``（バイト経由＝パス非依存）で読む。cv2 が苦手な
    形式（WEBP/BMP/TIFF 等）は PIL で開いて配列化して救済する。
    """
    if not data:
        return None
    try:
        import cv2  # type: ignore
        import numpy as np

        arr = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
        if arr is not None:
            return arr
    except Exception:
        pass
    try:
        import io

        import numpy as np
        from PIL import Image  # type: ignore

        with Image.open(io.BytesIO(data)) as im:
            arr = np.array(im.convert("RGB"))[:, :, ::-1].copy()  # RGB->BGR
        return arr
    except Exception:
        return None


def _detect_qr_text(image) -> Optional[str]:
    """BGR 配列から QR 文字列を取り出す。小さい QR は拡大＋余白付与で再試行する。"""
    try:
        import cv2  # type: ignore
    except Exception:
        _log.warning(
            "QR デコーダ（opencv-python）が見つかりません。"
            "`pip install opencv-python` するか --mfa-totp-uri/--mfa-totp-secret を指定してください"
        )
        return None
    detector = cv2.QRCodeDetector()
    try:
        data, _pts, _s = detector.detectAndDecode(image)
        if isinstance(data, str) and data:
            return data
    except Exception:
        pass
    # 小さい/低解像度の QR は detectAndDecode が空を返すため、最近傍拡大＋quiet zone
    # （白余白）を足して再検出する（スクリーンショットの小さな QR の救済）。
    try:
        h = int(image.shape[0]) if hasattr(image, "shape") and image.shape else 0
        if h and h < 300:
            scale = max(2, (300 // max(1, h)) + 1)
            big = cv2.resize(image, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST)
            big = cv2.copyMakeBorder(big, 20, 20, 20, 20, cv2.BORDER_CONSTANT, value=(255, 255, 255))
            data, _pts, _s = detector.detectAndDecode(big)
            if isinstance(data, str) and data:
                return data
    except Exception:
        pass
    return None


def decode_qr_image(path: str) -> Optional[str]:
    """QR 画像を読み取り、埋め込まれた文字列を返す。失敗時は ``None``。

    ``cv2.imread`` のパス依存問題（非ASCII パス・未対応形式で無言 ``None`` を返し、
    stderr に ``findDecoder`` WARN だけを残す）を避けるため、パス展開 → バイト読み →
    ``imdecode``/PIL の順で堅牢に読み込み、失敗時は利用者が uri/secret へ切り替えられる
    よう**具体的な診断**をログに残す（従来は無言で ``None`` を返すだけだった）。
    """
    try:
        raw = str(path or "").strip()
        if not raw:
            return None
        _silence_cv2()
        # ~ と環境変数を展開する（`~/totp.png` や `$HOME/...` を is_file 前に解決）。
        resolved = Path(os.path.expandvars(os.path.expanduser(raw)))
        if not resolved.is_file():
            _log.warning("TOTP QR 画像が見つかりません。指定したファイルを確認してください")
            return None
        try:
            data_bytes = resolved.read_bytes()
        except Exception:
            _log.warning("TOTP QR 画像を読み込めません（権限/破損の可能性）")
            return None
        # Pillow だけでは QR を検出できない。画像形式の診断より先に確認する。
        try:
            import cv2  # type: ignore

            if not callable(getattr(cv2, "QRCodeDetector", None)):
                raise ImportError("QRCodeDetector unavailable")
        except Exception:
            _log.warning(
                "QR デコーダ（opencv-python）を利用できません。"
                "`pip install opencv-python` するか --mfa-totp-uri/--mfa-totp-secret を指定してください"
            )
            return None
        image = _load_image_bgr(data_bytes)
        if image is None:
            _log.warning(
                "TOTP QR 画像をデコードできません（破損または未対応形式の可能性）。"
                "PNG/JPG に変換するか --mfa-totp-uri/--mfa-totp-secret での指定を検討してください",
            )
            return None
        text = _detect_qr_text(image)
        if text:
            return text
        _log.warning(
            "画像は読み込めましたが QR コードを検出できませんでした（画質/トリミングを確認、"
            "または --mfa-totp-uri/--mfa-totp-secret を使用してください）",
        )
        return None
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
