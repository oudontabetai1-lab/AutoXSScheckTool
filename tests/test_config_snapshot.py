import unittest

import main


class RedactSecretsTests(unittest.TestCase):
    def test_redacts_password_like_keys(self):
        cfg = {
            "mfa_email_imap_password": "app-secret",
            "tls_client_cert_password": "pfxpass",
            "openai_api_key": "sk-xxx",
            "session_token": "tok",
        }
        out = main._redact_secrets(cfg)
        for key in cfg:
            self.assertEqual(out[key], "***REDACTED***", key)

    def test_keeps_non_secret_and_empty_values(self):
        cfg = {
            "depth": 2,
            "url": "http://x.test/",
            "mfa_email_imap_password": "",  # 空は伏字にしない（送信なしと区別不要）
            "login_pass_field": "password",  # フィールド名であり秘匿値ではない
        }
        out = main._redact_secrets(cfg)
        self.assertEqual(out["depth"], 2)
        self.assertEqual(out["url"], "http://x.test/")
        self.assertEqual(out["mfa_email_imap_password"], "")
        # キー名は "pass_field" で "password" を含まないため伏字にしない
        # （これは秘匿値ではなく入力欄名）。
        self.assertEqual(out["login_pass_field"], "password")

    def test_does_not_mutate_input(self):
        cfg = {"mfa_email_imap_password": "s3cret"}
        main._redact_secrets(cfg)
        self.assertEqual(cfg["mfa_email_imap_password"], "s3cret")


if __name__ == "__main__":
    unittest.main()
