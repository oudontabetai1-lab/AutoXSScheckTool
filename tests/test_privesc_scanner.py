import unittest
from unittest.mock import AsyncMock

from wscan.scanners.privesc import PrivEscScanner


class _DummyEngine:
    def __init__(self):
        self.browser = object()
        self.payload_gen = None
        self.proxy = ""
        self.timeout = 30
        self.all_findings = []
        self.monitor = None


class PrivEscScannerTests(unittest.IsolatedAsyncioTestCase):
    async def test_cross_account_flags_same_owner_resource(self):
        scanner = PrivEscScanner(_DummyEngine())
        scanner._get = AsyncMock(side_effect=[
            (200, "<html><h1>Order 100</h1><p>Owner: alice@example.test</p></html>"),
            (200, "<html><h1>Order 100</h1><p>Owner: alice@example.test</p></html>"),
            (200, "<html><h1>Order 100</h1><p>Owner: bob@example.test</p></html>"),
            (403, "forbidden"),
        ])

        findings = await scanner._test_cross_account(
            "http://fixture.test/orders/100",
            [
                {"username": "alice@example.test", "cookies": "sid=alice", "role": "user"},
                {"username": "bob@example.test", "cookies": "sid=bob", "role": "user"},
            ],
            timeout=3,
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].check_type, "privesc_cross_acct")
        self.assertIn("alice@example.test", findings[0].evidence)
        self.assertTrue(findings[0].response["owner_marker_seen"])

    async def test_cross_account_flags_explicit_vertical_role_mismatch(self):
        scanner = PrivEscScanner(_DummyEngine())
        scanner._get = AsyncMock(side_effect=[
            (200, "<html><h1>Admin reports</h1><p>secret exports</p></html>"),
            (200, "<html><h1>Admin reports</h1><p>secret exports</p></html>"),
            (403, "forbidden"),
        ])

        findings = await scanner._test_cross_account(
            "http://fixture.test/admin/reports",
            [
                {"username": "admin@example.test", "cookies": "sid=admin", "role": "admin"},
                {"username": "alice@example.test", "cookies": "sid=alice", "role": "user"},
            ],
            timeout=3,
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")
        self.assertIn("Vertical privilege escalation", findings[0].evidence)

    async def test_cross_account_does_not_flag_personalized_own_resource(self):
        scanner = PrivEscScanner(_DummyEngine())
        scanner._get = AsyncMock(side_effect=[
            (200, "<html><h1>Account</h1><p>Owner: alice@example.test</p><p>Balance: 100</p></html>"),
            (200, "<html><h1>Account</h1><p>Owner: bob@example.test</p><p>Balance: 20</p></html>"),
            (200, "<html><h1>Account</h1><p>Owner: bob@example.test</p><p>Balance: 20</p></html>"),
            (200, "<html><h1>Account</h1><p>Owner: alice@example.test</p><p>Balance: 100</p></html>"),
        ])

        findings = await scanner._test_cross_account(
            "http://fixture.test/account",
            [
                {"username": "alice@example.test", "cookies": "sid=alice", "role": "user"},
                {"username": "bob@example.test", "cookies": "sid=bob", "role": "user"},
            ],
            timeout=3,
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
