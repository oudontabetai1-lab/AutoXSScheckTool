"""任意の画像依存が無い環境でも QR の診断と秘匿を検証する。"""
import logging
import sys
from types import SimpleNamespace

import pytest

from wscan import totp


@pytest.mark.parametrize("failure", ["missing", "read", "corrupt", "no_qr"])
def test_qr_failure_does_not_log_secret_path(tmp_path, monkeypatch, caplog, failure):
    path = tmp_path / "private-account-JBSWY3DPEHPK3PXP.png"
    if failure != "missing":
        path.write_bytes(b"fixture")
    monkeypatch.setitem(sys.modules, "cv2", SimpleNamespace(QRCodeDetector=lambda: object()))
    monkeypatch.setattr(totp, "_silence_cv2", lambda: None)
    if failure == "read":
        def fail_read(self):
            raise PermissionError(str(path))
        monkeypatch.setattr(type(path), "read_bytes", fail_read)
    monkeypatch.setattr(totp, "_load_image_bgr", lambda data: None if failure == "corrupt" else object())
    monkeypatch.setattr(totp, "_detect_qr_text", lambda image: None)
    with caplog.at_level(logging.WARNING, logger="wscan.totp"):
        assert totp.decode_qr_image(str(path)) is None
    assert caplog.records
    assert str(tmp_path) not in caplog.text
    assert path.name not in caplog.text
    assert "JBSWY3DPEHPK3PXP" not in caplog.text


@pytest.mark.parametrize("decoder", [None, SimpleNamespace()])
def test_missing_qr_decoder_is_diagnosed_before_image_loading(tmp_path, monkeypatch, caplog, decoder):
    path = tmp_path / "private.png"
    path.write_bytes(b"image")
    monkeypatch.setitem(sys.modules, "cv2", decoder)
    monkeypatch.setitem(sys.modules, "PIL", None)
    def unexpected_load(data):
        pytest.fail("デコーダ未導入時に画像破損と誤診しない")
    monkeypatch.setattr(totp, "_load_image_bgr", unexpected_load)
    with caplog.at_level(logging.WARNING, logger="wscan.totp"):
        assert totp.decode_qr_image(str(path)) is None
    assert "pip install opencv-python" in caplog.text
    assert "破損" not in caplog.text
    assert "QR コードを検出できません" not in caplog.text
    assert path.name not in caplog.text
