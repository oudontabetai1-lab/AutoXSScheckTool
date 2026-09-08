"""TOTP登録確認APIの入力検証・認証・秘匿と設定の配線。"""
import sys
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi.testclient import TestClient

from wscan.monitor import MonitorServer
from wscan.totp import inspect_totp_payload

SECRET = "JBSWY3DPEHPK3PXP"
URI = f"otpauth://totp/Example:alice?secret={SECRET}&issuer=Example&digits=8&period=45&algorithm=SHA256"


def test_inspect_totp_registration():
    assert inspect_totp_payload(URI) == {
        "secret": SECRET, "issuer": "Example", "label": "Example:alice",
        "digits": 8, "period": 45, "algorithm": "SHA256",
    }
    assert inspect_totp_payload(SECRET.lower())["secret"] == SECRET


@pytest.mark.parametrize("text", [
    "https://example.test/", "", "not a secret!", "otpauth://hotp/x?secret=" + SECRET,
    "otpauth://totp/x", "otpauth://totp/x?secret=!",
    URI + "&secret=" + SECRET, URI.replace("SHA256", "MD5"),
    URI.replace("digits=8", "digits=99"), URI.replace("period=45", "period=0"),
])
def test_preview_rejects_invalid_registration_without_echoing_content(text):
    with pytest.raises(ValueError) as error:
        inspect_totp_payload(text)
    assert SECRET not in str(error.value)
    assert "otpauth:" not in str(error.value)


def test_preview_api_returns_only_to_authenticated_requester(tmp_path, monkeypatch):
    monkeypatch.setattr("wscan.monitor.OUTPUT_BASE", tmp_path / "output")
    monkeypatch.setattr("wscan.totp.decode_qr_bytes", lambda data: URI)
    server = MonitorServer(port=0, auth_token="test-token")
    server._audit = Mock()
    with TestClient(server.app) as client:
        files = {"file": ("private-account.png", b"fixture", "image/png")}
        assert client.post("/api/v1/mfa/totp/preview", files=files).status_code == 401
        response = client.post("/api/v1/mfa/totp/preview", files=files,
                               headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == inspect_totp_payload(URI)
    server._audit.assert_not_called()
    assert not server.event_history
    assert not (tmp_path / "output").exists()


def test_preview_api_rejects_large_file_before_decode(monkeypatch):
    monkeypatch.setattr("wscan.monitor._UPLOAD_MAX_BYTES", 16)
    decoder = Mock()
    monkeypatch.setattr("wscan.totp.decode_qr_bytes", decoder)
    with TestClient(MonitorServer(port=0).app) as client:
        response = client.post("/api/v1/mfa/totp/preview", files={"file": ("x.png", b"x" * 17)})
    assert response.status_code == 413
    decoder.assert_not_called()


def test_preview_api_handles_missing_decoder_without_image_dependencies(monkeypatch):
    monkeypatch.setitem(sys.modules, "cv2", None)
    with TestClient(MonitorServer(port=0).app) as client:
        response = client.post("/api/v1/mfa/totp/preview", files={"file": ("private.png", b"x")})
    assert response.status_code == 400
    assert "pip install opencv-python" in response.json()["error"]
    assert "private.png" not in response.text


def test_manual_selection_validates_coordinates_and_returns_selector():
    server = MonitorServer(port=0)
    session = Mock()
    session.select_mfa_field = AsyncMock(return_value={"selector": "#custom"})
    server.manual_crawl_session = session
    with TestClient(server.app) as client:
        for point in ({}, {"nx": -1, "ny": 0}, {"nx": "nan", "ny": 0}):
            assert client.post("/api/v1/manual-crawl/mfa-selector", json=point).status_code == 400
        response = client.post("/api/v1/manual-crawl/mfa-selector", json={"nx": .25, "ny": .5})
    assert response.json() == {"selector": "#custom"}
    session.select_mfa_field.assert_awaited_once_with(.25, .5)


def test_scan_cli_mfa_selector(monkeypatch):
    import main
    monkeypatch.setattr(sys, "argv", ["main.py", "scan", "http://127.0.0.1", "--mfa-selector", "#code"])
    assert main.parse_args().mfa_selector == "#code"
