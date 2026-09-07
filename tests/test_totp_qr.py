"""TOTP QR 画像デコードの堅牢化テスト（wscan/totp.decode_qr_image）。

利用者から「特に QR コード指定時にログインが失敗し、OpenCV が
``findDecoder imread_ can't open/read file`` を出す」という報告があった。原因は
``cv2.imread`` のパス依存（非ASCII パス・未対応形式で無言 ``None``）。修正後は
バイト読み→``imdecode``/PIL で堅牢に読み込み、失敗時は診断ログを残す。

opencv-python は本体の必須依存ではない（QR は任意機能）ため、cv2 が無い環境では
このモジュールごと skip する。QR 生成にも cv2.QRCodeEncoder を使う。
"""
import logging

import pytest

cv2 = pytest.importorskip("cv2", reason="opencv-python 未導入（QR は任意機能）")
np = pytest.importorskip("numpy")

if not hasattr(cv2, "QRCodeEncoder"):
    pytest.skip("cv2.QRCodeEncoder が無いビルド", allow_module_level=True)

from wscan.totp import (  # noqa: E402
    decode_qr_image,
    generate_totp,
    resolve_totp_secret,
)

_URI = "otpauth://totp/Test:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test&digits=6&period=30"


def _qr_bgr(text: str):
    """text を埋め込んだ QR を、検出しやすいよう余白＋拡大した BGR 配列で返す。"""
    img = cv2.QRCodeEncoder.create().encode(text)
    bordered = cv2.copyMakeBorder(img, 4, 4, 4, 4, cv2.BORDER_CONSTANT, value=255)
    return cv2.resize(bordered, None, fx=10, fy=10, interpolation=cv2.INTER_NEAREST)


def _write_qr(path, text: str = _URI, fmt: str = ".png") -> None:
    ok, buf = cv2.imencode(fmt, _qr_bgr(text))
    assert ok
    path.write_bytes(buf.tobytes())


def test_decode_qr_from_png(tmp_path):
    p = tmp_path / "totp.png"
    _write_qr(p)
    assert decode_qr_image(str(p)) == _URI


def test_decode_qr_unicode_path(tmp_path):
    """非ASCII（日本語）パスでもデコードできる（imread のパス依存を回避した回帰）。"""
    p = tmp_path / "認証コード_テスト.png"
    _write_qr(p)
    assert decode_qr_image(str(p)) == _URI


def test_decode_qr_path_with_space(tmp_path):
    p = tmp_path / "my totp qr.png"
    _write_qr(p)
    assert decode_qr_image(str(p)) == _URI


def test_decode_qr_tilde_expansion(tmp_path, monkeypatch):
    """`~/...` の home 展開（is_file 前に expanduser する回帰）。"""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))  # Windows 保険
    _write_qr(tmp_path / "t.png")
    assert decode_qr_image("~/t.png") == _URI


def test_decode_qr_webp_fallback(tmp_path, monkeypatch):
    """cv2 が苦手な形式でも PIL フォールバックで読める（形式非依存化の回帰）。"""
    Image = pytest.importorskip("PIL.Image")
    arr = _qr_bgr(_URI)  # QRCodeEncoder はグレースケール(2D)を返す
    p = tmp_path / "totp.webp"
    try:
        Image.fromarray(arr).save(p, format="WEBP", lossless=True)
    except Exception:
        pytest.skip("PIL WEBP 書き出し不可")
    monkeypatch.setattr(cv2, "imdecode", lambda *args: None)
    assert decode_qr_image(str(p)) == _URI


def test_resolve_totp_secret_from_qr_end_to_end(tmp_path):
    """QR → resolve_totp_secret → generate_totp の一気通貫（実利用経路）。"""
    p = tmp_path / "totp.png"
    _write_qr(p)
    resolved = resolve_totp_secret(qr=str(p))
    assert resolved and resolved["secret"] == "JBSWY3DPEHPK3PXP"
    assert resolved["digits"] == 6 and resolved["period"] == 30
    code = generate_totp(resolved["secret"], digits=resolved["digits"],
                         period=resolved["period"], algorithm=resolved["algorithm"])
    assert code and code.isdigit() and len(code) == 6


def test_missing_file_returns_none_and_warns(tmp_path, caplog):
    with caplog.at_level(logging.WARNING, logger="wscan.totp"):
        assert decode_qr_image(str(tmp_path / "nope.png")) is None
    assert any("見つかりません" in r.message for r in caplog.records)


def test_corrupt_file_returns_none_and_warns(tmp_path, caplog):
    """画像でないファイルは None＋「デコードできません」診断（従来は無言 None）。"""
    p = tmp_path / "broken.png"
    p.write_bytes(b"this is not an image")
    with caplog.at_level(logging.WARNING, logger="wscan.totp"):
        assert decode_qr_image(str(p)) is None
    assert any("デコードできません" in r.message for r in caplog.records)


def test_empty_path_returns_none():
    assert decode_qr_image("") is None
    assert decode_qr_image(None) is None  # type: ignore[arg-type]
