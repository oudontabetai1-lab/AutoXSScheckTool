import unittest
from unittest.mock import AsyncMock

from wscan.notification import NotificationManager
from wscan.scanners.base import Finding


class NotificationManagerTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _finding(state: str, field_name: str, severity: str = "high") -> Finding:
        return Finding(
            check_type="sqli",
            severity=severity,
            url=f"http://fixture.test/{field_name}",
            field_name=field_name,
            payload="' OR 1=1--",
            evidence=f"{state} evidence",
            verification_state=state,
        )

    async def test_only_confirmed_findings_above_threshold_are_sent(self):
        manager = NotificationManager(
            webhook_url="https://webhook.invalid/test",
            min_severity="high",
        )
        manager._send = AsyncMock()

        await manager.notify_finding(self._finding("assumed", "assumed"))
        await manager.notify_finding(self._finding("unreproduced", "unreproduced"))
        await manager.notify_finding(self._finding("reproduced", "confirmed"))
        await manager.notify_finding(self._finding("reproduced", "low", severity="low"))

        manager._send.assert_awaited_once()
        sent_payload = manager._send.await_args.args[0]
        self.assertEqual(sent_payload["field_name"], "confirmed")

    async def test_promotion_to_reproduced_notifies_once(self):
        # 検出時 assumed で弾かれた finding が検証で reproduced に昇格したら通知される。
        # 再送（dedup 済）は起きない＝#107 P1 の回帰ガード。
        manager = NotificationManager(
            webhook_url="https://webhook.invalid/test",
            min_severity="high",
        )
        manager._send = AsyncMock()
        f = self._finding("assumed", "promote")

        # 検出時（assumed）: 通知ゲートで弾かれる
        await manager.notify_finding(f)
        manager._send.assert_not_awaited()

        # 検証で reproduced へ昇格 → 通知される
        f.apply_verification("reproduced", "")
        await manager.notify_finding(f)
        manager._send.assert_awaited_once()

        # 同一 finding の再通知は dedup で送られない
        await manager.notify_finding(f)
        manager._send.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
