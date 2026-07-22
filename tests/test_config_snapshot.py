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

    def test_redacts_dashboard_totp_bearer_and_header_values(self):
        cfg = {
            "mfa_totp_uri": "otpauth://totp/x?secret=BASE32",
            "mfa_totp_secret": "BASE32",
            "bearer": "access-token",
            "headers": {"Authorization": "Bearer access-token", "X-Tenant": "acme"},
        }
        out = main._redact_secrets(cfg)
        self.assertEqual(out["mfa_totp_uri"], "***REDACTED***")
        self.assertEqual(out["mfa_totp_secret"], "***REDACTED***")
        self.assertEqual(out["bearer"], "***REDACTED***")
        self.assertEqual(
            out["headers"],
            {"Authorization": "***REDACTED***", "X-Tenant": "***REDACTED***"},
        )

    def test_placeholder_blank_for_served_defaults(self):
        # /api/config/defaults 用: 秘匿値は空文字にし、非秘匿フィールドは残す。
        # （"***REDACTED***" だとフォーム欄にその文字列が入ってしまうため空にする）
        cfg = {
            "mfa_totp_secret": "BASE32",
            "mfa_totp_uri": "otpauth://totp/x?secret=BASE32",
            "bearer": "tok",
            "auth_pass": "pw",
            "cookies": "session=abc",
            "headers": {"Authorization": "Bearer x"},
            # 非秘匿は保持
            "mfa_totp_digits": 8,
            "mfa_totp_period": 45,
            "mfa_totp_algorithm": "SHA256",
            "url": "http://x.test/",
        }
        out = main._redact_secrets(cfg, placeholder="")
        self.assertEqual(out["mfa_totp_secret"], "")
        self.assertEqual(out["mfa_totp_uri"], "")
        self.assertEqual(out["bearer"], "")
        self.assertEqual(out["auth_pass"], "")
        self.assertEqual(out["cookies"], "")
        self.assertEqual(out["headers"], {"Authorization": ""})
        self.assertEqual(out["mfa_totp_digits"], 8)
        self.assertEqual(out["mfa_totp_period"], 45)
        self.assertEqual(out["mfa_totp_algorithm"], "SHA256")
        self.assertEqual(out["url"], "http://x.test/")

    def test_redacts_string_form_headers(self):
        # headers_text（config 由来）は "Name: Value" の文字列。dict と同様に
        # 認証情報が入り得るため、defaults/snapshot 双方で丸ごと伏字化する。
        cfg = {"headers": "Authorization: Bearer leak\nX-Api-Key: k"}
        self.assertEqual(main._redact_secrets(cfg)["headers"], "***REDACTED***")
        self.assertEqual(main._redact_secrets(cfg, placeholder="")["headers"], "")
        # 空文字列はそのまま（送信なしと区別不要）。
        self.assertEqual(main._redact_secrets({"headers": ""})["headers"], "")

    def test_redacts_login_credentials_and_cookies_exact_keys(self):
        # 部分一致では拾えない明示キー。scan_started の再生・snapshot 経由で
        # ログイン PW / セッション Cookie が別クライアントへ漏れないようにする。
        cfg = {
            "auth_pass": "hunter2",
            "cookies": "session=abc; token=xyz",
            "low_priv_cookies": "session=low",
            # フィールド名は秘匿値ではないため伏字にしない
            "login_pass_field": "password",
            "login_user_field": "username",
        }
        out = main._redact_secrets(cfg)
        self.assertEqual(out["auth_pass"], "***REDACTED***")
        self.assertEqual(out["cookies"], "***REDACTED***")
        self.assertEqual(out["low_priv_cookies"], "***REDACTED***")
        self.assertEqual(out["login_pass_field"], "password")
        self.assertEqual(out["login_user_field"], "username")


if __name__ == "__main__":
    unittest.main()
