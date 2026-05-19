import unittest
from pathlib import Path

from wscan.tls_config import TLSConfig


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

    def test_httpx_uses_ca_and_pem_client_certificate(self):
        cfg = TLSConfig.from_values(
            client_cert="/tmp/client.crt",
            client_key="/tmp/client.key",
            ca_cert="/tmp/ca.pem",
            verify_tls=True,
        )

        opts = cfg.httpx_options()

        self.assertEqual(opts["verify"], "/tmp/ca.pem")
        self.assertEqual(opts["cert"], ("/tmp/client.crt", "/tmp/client.key"))

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
