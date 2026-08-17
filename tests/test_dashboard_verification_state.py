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

    def test_capped_cards_evicted_from_finding_map(self):
        # DOM キャップで外したカードは findingCards からも削除する（メモリリーク／detached
        # カードへの finding_update 適用を防ぐ）。
        html = Path("templates/dashboard.html").read_text(encoding="utf-8")
        self.assertIn("state.findingCards.delete", html)
        self.assertIn("card.dataset.findingKey = key", html)

    def test_json_finding_key_preserves_null_vs_root_pointer(self):
        # findingKey は json_body の null（欠落=corrupt）と ""（RFC6901 ルート）を潰さない
        # （Python 側 canonical key と同様に区別）。truthiness fallback `|| ''` を使わない。
        html = Path("templates/dashboard.html").read_text(encoding="utf-8")
        self.assertIn("JSON.stringify(d.injection_pointer ?? null)", html)
        self.assertNotIn("d.injection_pointer || ''", html)


if __name__ == "__main__":
    unittest.main()
