import unittest
from pathlib import Path


class DashboardVerificationStateTests(unittest.TestCase):
    def test_live_finding_cards_distinguish_verification_states(self):
        html = Path("templates/dashboard.html").read_text(encoding="utf-8")

        # verification バッジ算出は computeVerification に集約（addFinding と finding_update で共有）。
        self.assertIn("function computeVerification(data)", html)
        self.assertIn("label: 'reproduced'", html)
        self.assertIn("label: 'assumed（推定・再検証未実行）'", html)
        self.assertIn("'not reproduced'", html)
        self.assertIn(".fc-assumed", html)
        self.assertIn(".fc-unverified", html)
        # 明示 state を legacy boolean より優先（state 判定が verified fallback より前）。
        self.assertLess(html.index("if (st === 'reproduced')"), html.index("if (!verified)"))

    def test_finding_update_refreshes_card_badge(self):
        # 検証フェーズの state 変化を live カードへ反映するハンドラと配信経路が存在する。
        html = Path("templates/dashboard.html").read_text(encoding="utf-8")
        self.assertIn("case 'finding_update'", html)
        self.assertIn("fc-verify-badge", html)
        self.assertIn("state.findingCards", html)


if __name__ == "__main__":
    unittest.main()
