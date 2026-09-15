import datetime
import ssl
import tempfile
import unittest
from pathlib import Path

from wscan.tls_config import TLSConfig


def _write_self_signed(dir_path: Path) -> tuple[str, str]:
    """テスト用の自己署名証明書＋鍵(PEM)を生成し (cert_path, key_path) を返す。"""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wscan-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = dir_path / "cert.pem"
    key_path = dir_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
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
