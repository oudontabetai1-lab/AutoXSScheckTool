import unittest
from pathlib import Path


class DashboardVerificationStateTests(unittest.TestCase):
    def test_live_finding_cards_distinguish_verification_states(self):
        html = Path("templates/dashboard.html").read_text(encoding="utf-8")

        self.assertIn("const verificationState = data.verification_state || '';", html)
        self.assertIn("verificationLabel = 'reproduced';", html)
        self.assertIn("verificationLabel = 'assumed（推定・再検証未実行）';", html)
        self.assertIn("'not reproduced'", html)
        self.assertIn(".fc-assumed", html)
        self.assertIn(".fc-unverified", html)


if __name__ == "__main__":
    unittest.main()
