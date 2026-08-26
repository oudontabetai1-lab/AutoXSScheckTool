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


if __name__ == "__main__":
    unittest.main()
