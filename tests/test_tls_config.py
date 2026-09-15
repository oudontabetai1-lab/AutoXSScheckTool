import ssl
import tempfile
import unittest
from pathlib import Path

from wscan.tls_config import TLSConfig

# CI のクリーン環境（requirements.txt のみ）でも動くよう、証明書は静的に埋め込む。
# cryptography 等の未宣言パッケージへ依存しない（F05 の CI 失敗対策）。
# 用途はテスト専用の使い捨て自己署名証明書（CA:TRUE）。有効期限 2036 まで。
_TEST_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIUMv9bHmIhKKJveEL3v83vlrJ9zzAwDQYJKoZIhvcNAQEL
BQAwFTETMBEGA1UEAwwKd3NjYW4tdGVzdDAeFw0yNjA5MTUwMTU4MTZaFw0zNjA5
MTIwMTU4MTZaMBUxEzARBgNVBAMMCndzY2FuLXRlc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCuCJEFMp+DzCrEaYPv6Gb3PMRF96rp+qOQsQTrbso8
hxB/3Uz/Q+Zr7/GsXlBkh5EY0G6veZQmL7df6eU5qgJ0N5327iR+G5PKWZW5+SO0
qMeszgT4INHrP8hesuFi6ZcjRcNdJR/jQB/PQ6leM7YRnHMo7bpEd+j374Q3pfGV
zeH7XVeqfKIjv7z0U9a3Ufzc4XOOL/vjGniZZLqtUVFRsUcoh4d4l+wVWi87G8rt
B6NxrYUKqPT6+IuJWiQta+pIX1fW3VzG1jRrtYX/XKjSfwgeDSdfmf6FbxOrRqDM
NdWMZ3vQ3wfZpRXXRs+MDIfoscC24OANHY56Rem1fns9AgMBAAGjUzBRMB0GA1Ud
DgQWBBQBl2yUClDWb1A96hX+wuDI2mRMJDAfBgNVHSMEGDAWgBQBl2yUClDWb1A9
6hX+wuDI2mRMJDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBb
HOuUbmOwFUgPuIcnaPoctzHOvUC4IEMsX52ComsTx10xN/ry7JvZWrjy+AaCyStx
ELuHFOfP3f0xh3PZ9CXRysTw0+WoNTuKuyHmnQnmvRO3im1z6FoPXF1E5xw0/xlI
zvSZPcGF/OwVJT99Xi9fQTEvn6W6P7u97PvmYDnPajWIwgdKBkM3f+935UpHfpGw
SK5SrFxpurkJB8w7rT3Ff43fUogrkMnpcbf8I3WXzCcsZ5jLanVOSWl/3QAx3HLw
wCemwWO9MQqYxb936QbtzAj6q436s598ER9Np6hrmsUFkCQCE73CY5QVljRIeKTF
oRsWWCLShiz80g5gTK04
-----END CERTIFICATE-----
"""

_TEST_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCuCJEFMp+DzCrE
aYPv6Gb3PMRF96rp+qOQsQTrbso8hxB/3Uz/Q+Zr7/GsXlBkh5EY0G6veZQmL7df
6eU5qgJ0N5327iR+G5PKWZW5+SO0qMeszgT4INHrP8hesuFi6ZcjRcNdJR/jQB/P
Q6leM7YRnHMo7bpEd+j374Q3pfGVzeH7XVeqfKIjv7z0U9a3Ufzc4XOOL/vjGniZ
ZLqtUVFRsUcoh4d4l+wVWi87G8rtB6NxrYUKqPT6+IuJWiQta+pIX1fW3VzG1jRr
tYX/XKjSfwgeDSdfmf6FbxOrRqDMNdWMZ3vQ3wfZpRXXRs+MDIfoscC24OANHY56
Rem1fns9AgMBAAECggEAAyVJ/m1OvKU116+C5ZT5OXpPyjuitfskYOLmOx2D9R9J
hnojoGXj4MBpSUuPdJsOXcO0tczC3K7WR8WfRvvM8rinol/lvnbKpNNviqPsx+Du
HQWV9D3e9XuFaGV01U1yFdPhZwoFqcf4sI3L86qHyF6K0VWnXSygBCKVl049+o5t
ZOuGnsCr7IBXid7tCA/oaBqEjCg2903n6DGilfxLC0fXoPVsM2M8iHKkY/wCIFUK
JJQgKXb5Dh8p+LQW7ze9jmQyLlEflDR25RFBMCmxLuo6n9yrfDvgqXRhnZ1U8c55
Lga/0V8icCGEoOYD0G8V4WGBNyf9nHTB1vVJ1LXOsQKBgQDfd61gOUg9ZkiRakV9
s8c/XHr0V5TwFVyZ25PScIzNJmD9li9NHA5nUx81/qBsoKL4bvvG6ffDUSfqVDZm
15ELRWiB+4KRUcC5sH/6T+bzrDM6A1QoyBB+PF8vBDrQ2/2A92/FsAZteSkr/JBy
K4DXKY0xyNgBDCz0/pwugPptLQKBgQDHXo1BF+yf/SR2pT1RlCHqbpHUjo9HDLYZ
Nq8wCCKSWC5S3xIMQ1aEDXPmPsp6A0/x4xD1hbZbuvLF3eh6Sv5hR30PVtmC+L1I
+6+FOE0YH2rl+5x7pnXW8hYpxcNZQ6NcmJW0DJP+Sc1QEwOT+VInwiOeeRMh7+nj
54KWxd+wUQKBgQDFtp0vBX9k05phDiVtkiI3bRtcFCEySbQkbKHdDreEyvAFbVts
XeZghKqYmzBU68tFAuzAkUElDijCqr93PkKWNlLArkZXTH23zPFuBkPQVAr+yPMt
IdV12vRcJOHk6L7h3AqIXbVSJmDHCi7C1Lqpo5nI8moqgxtDqAGHI5ZuAQKBgBux
L2+eMhja4Yi1VPoS2E8mwozCrHYS9uwzo0vJpXusUeri3y/i3o6DC9ksWZVvBliz
0HQ5+WVuZzBCrXrnFcRPWLibuKSvhiMwCmY3tsWl/4QoWcj3CyErCRcOSB8K/RLs
gsa6hIfqmmEH8xRHqjiph6cIbDbnixZD3uiwXWyxAoGBAL/C7kjDQHYQIEJcBnKl
jzppOmxtODCaF8aatCrkIBrKJHdpxGwP4zSYN4B3usSxCIW1nQyH2MbGFjsZKtjJ
jEa3u02I5tJfKx5L35rw8bEyFOTd7XEoqE7R+R4BPKoDtv6585TJ4qowJ5bkIL8g
/f48iA6vjC6UXblvbPqGOi0d
-----END PRIVATE KEY-----
"""


def _write_self_signed(dir_path: Path) -> tuple[str, str]:
    """埋め込み済みのテスト用証明書＋鍵を書き出し (cert_path, key_path) を返す。"""
    cert_path = dir_path / "cert.pem"
    key_path = dir_path / "key.pem"
    cert_path.write_text(_TEST_CERT_PEM, encoding="ascii")
    key_path.write_text(_TEST_KEY_PEM, encoding="ascii")
    return str(cert_path), str(key_path)


class TLSConfigTests(unittest.TestCase):
    def test_playwright_pem_client_certificate_options(self):
        cfg = TLSConfig.from_values(
            client_cert="/tmp/client.crt",
            client_key="/tmp/client.key",
            client_cert_password="secret",
            ca_cert="/tmp/ca.pem",
            verify_tls=True,
        )

        opts = cfg.playwright_context_options("https://secure.example.test/app")

        self.assertTrue(opts["ignore_https_errors"])
        self.assertEqual(
            opts["client_certificates"],
            [{
                "origin": "https://secure.example.test",
                "certPath": "/tmp/client.crt",
                "keyPath": "/tmp/client.key",
                "passphrase": "secret",
            }],
        )

    def test_httpx_builds_ssl_context_for_mtls(self):
        # httpx 0.28 は cert=/verify=path を廃止。mTLS では明示 SSLContext を返す（F05）。
        with tempfile.TemporaryDirectory() as d:
            cert, key = _write_self_signed(Path(d))
            cfg = TLSConfig.from_values(
                client_cert=cert, client_key=key, ca_cert=cert, verify_tls=True,
            )
            opts = cfg.httpx_options()

        self.assertIsInstance(opts["verify"], ssl.SSLContext)
        self.assertNotIn("cert", opts)  # 旧 cert= ショートカットは使わない
        self.assertTrue(opts["verify"].get_ca_certs())  # CA が context にロード済み

    def test_httpx_client_cert_without_validation_uses_context(self):
        # verify 無効でも client 証明書は SSLContext 経由で送る（自己署名内部ターゲット）。
        with tempfile.TemporaryDirectory() as d:
            cert, key = _write_self_signed(Path(d))
            cfg = TLSConfig.from_values(client_cert=cert, client_key=key, verify_tls=False)
            ctx = cfg.build_ssl_context()

        self.assertIsInstance(ctx, ssl.SSLContext)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
        self.assertFalse(ctx.check_hostname)

    def test_httpx_missing_client_cert_is_rejected(self):
        # 欠落した証明書はサイレントに素通しせず例外で拒否する（誠実な失敗）。
        cfg = TLSConfig.from_values(
            client_cert="/nonexistent/client.crt",
            client_key="/nonexistent/client.key",
        )
        with self.assertRaises((FileNotFoundError, ssl.SSLError, OSError)):
            cfg.httpx_options()

    def test_default_keeps_legacy_https_error_behavior(self):
        cfg = TLSConfig.from_values()

        self.assertEqual(cfg.httpx_options(), {"verify": False})
        self.assertTrue(cfg.playwright_context_options("https://example.test")["ignore_https_errors"])

    def test_missing_pem_pair_is_invalid(self):
        cfg = TLSConfig.from_values(client_cert="/tmp/client.crt")

        self.assertIn(
            "client key is required",
            "; ".join(cfg.validate_paths()),
        )

    def test_dashboard_exposes_tls_controls(self):
        html = Path("templates/dashboard.html").read_text(encoding="utf-8")

        for marker in (
            "cfgTlsClientCert",
            "cfgTlsClientKey",
            "cfgTlsClientPfx",
            "cfgTlsClientCertPassword",
            "cfgTlsCaCert",
            "tog-tls_verify",
            "tls_client_cert",
            "tls_verify",
        ):
            self.assertIn(marker, html)

    def test_default_config_documents_tls_keys(self):
        cfg = Path("config/wscan.yaml").read_text(encoding="utf-8")

        for marker in (
            "tls_client_cert",
            "tls_client_key",
            "tls_client_pfx",
            "tls_client_cert_password",
            "tls_ca_cert",
            "tls_verify",
        ):
            self.assertIn(marker, cfg)


if __name__ == "__main__":
    unittest.main()
