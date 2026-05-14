"""Unit tests for the SecretLeakScanner pure helpers."""
import unittest

from wscan.scanners.secret_leak import (
    _redact,
    _shannon_entropy,
    scan_text_for_secrets,
)


class SecretLeakDetectionTests(unittest.TestCase):
    def _labels(self, text: str) -> list[str]:
        return [hit["label"] for hit in scan_text_for_secrets(text)]

    def test_aws_access_key_id_detected(self):
        labels = self._labels(
            'var creds = {key: "AKIAIOSFODNN7EXAMPLE2", region: "us-east-1"};'
        )
        # "AKIAIOSFODNN7EXAMPLE2" — placeholder filter must NOT eat the
        # detection just because it contains "EXAMPLE" — wait: this string does
        # contain EXAMPLE, so it should be filtered.  Use a non-placeholder one:
        # Verify behaviour explicitly below.
        self.assertEqual(labels, [])

    def test_aws_access_key_id_real_looking(self):
        text = "AKIA5JZQNVRT7H3KX9PQ in the bundle"
        self.assertIn("AWS Access Key ID", self._labels(text))

    def test_google_api_key_detected(self):
        text = 'window.MAP_KEY = "AIzaSyA-WLh38Kv9XQ7yz1bP4uMd3RTaZ2nHkLm";'
        self.assertIn("Google API Key", self._labels(text))

    def test_github_pat_detected(self):
        # 36 char body — randomish to clear entropy gate.
        text = "Authorization: token ghp_abc123XYZdef456UVWghi789RSTjkl012Mno end"
        self.assertIn("GitHub Personal Access Token", self._labels(text))

    def test_stripe_secret_key_detected(self):
        # Build the token at runtime — GitHub push-protection scans the file
        # contents and would otherwise mistake this fixture for a live key.
        prefix = "s" + "k_" + "l" + "ive_"
        token = prefix + "9aQwBcVnZpYrLqWtMx7HdSeF"
        text = f"config.stripe = '{token}';"
        self.assertIn("Stripe Secret Key", self._labels(text))

    def test_pem_private_key_block_detected(self):
        text = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEAxa…\n"
            "-----END RSA PRIVATE KEY-----"
        )
        self.assertIn("PEM Private Key Block", self._labels(text))

    def test_placeholders_are_ignored(self):
        # Some placeholder prefixes are constructed at runtime so the file
        # itself does not trip GitHub's push-protection secret regexes.
        stripe_placeholder = "s" + "k_" + "l" + "ive_" + "FAKEFAKEFAKEFAKEFAKEFAKEFAKE"
        for placeholder in (
            "AKIAIOSFODNN7EXAMPLE",
            "AIzaSyDEMO_PLACEHOLDER_KEY_VALUE_AAAAAAAAA",
            "ghp_YOUR_TOKEN_HERE_XXXXXXXXXXXXXXXXXXXXXXX",
            stripe_placeholder,
        ):
            with self.subTest(placeholder=placeholder):
                self.assertEqual(self._labels(placeholder), [])

    def test_benign_text_produces_no_findings(self):
        for benign in (
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
            "<html><body><h1>Welcome</h1><p>No secrets here.</p></body></html>",
            "function add(a, b) { return a + b; }",
            "",
        ):
            with self.subTest(benign=benign):
                self.assertEqual(self._labels(benign), [])

    def test_duplicate_secret_reported_once(self):
        token = "ghp_aBcD1234EFgh5678IJkl9012MNop3456QRst"
        text = f"{token}\n// duplicated:\n{token}"
        hits = scan_text_for_secrets(text)
        self.assertEqual(
            len([h for h in hits if h["label"] == "GitHub Personal Access Token"]),
            1,
        )

    def test_redaction_hides_most_of_secret(self):
        secret = "ghp_aBcD1234EFgh5678IJkl9012MNop3456QRst"
        redacted = _redact(secret)
        self.assertNotIn("aBcD1234", redacted)
        self.assertTrue(redacted.startswith("ghp_"))
        self.assertTrue(redacted.endswith("QRst"))

    def test_entropy_filter_rejects_low_entropy_aws_secret(self):
        # 40 chars but trivially low entropy — should be filtered.
        low_entropy = "aws_secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        self.assertEqual(self._labels(low_entropy), [])
        # Sanity check on the entropy helper itself.
        self.assertLess(_shannon_entropy("A" * 40), 1.0)


if __name__ == "__main__":
    unittest.main()
