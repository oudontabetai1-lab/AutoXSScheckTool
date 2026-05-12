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
        self.low_priv_cookies = ""
        self.account_sessions = []


class _DummyPage:
    def __init__(self, url, forms):
        self.url = url
        self.forms = forms


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

    async def test_state_changing_privileged_form_flags_low_priv_submission(self):
        engine = _DummyEngine()
        engine.low_priv_cookies = "sid=low"
        scanner = PrivEscScanner(engine)
        scanner._request_form = AsyncMock(return_value=(200, "<html>user promoted</html>"))
        page = _DummyPage(
            "http://fixture.test/admin/users",
            [
                {
                    "method": "POST",
                    "action": "http://fixture.test/admin/users/role",
                    "inputs": [
                        {"name": "user_id", "value": "42", "type": "text"},
                        {"name": "role", "value": "admin", "type": "text"},
                    ],
                }
            ],
        )

        findings = await scanner._test_state_changing_forms(page)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].check_type, "privesc_action")
        self.assertIn("POST /admin/users/role", findings[0].evidence)
        scanner._request_form.assert_awaited_once()

    async def test_state_changing_form_ignores_unprivileged_action_path(self):
        engine = _DummyEngine()
        engine.low_priv_cookies = "sid=low"
        scanner = PrivEscScanner(engine)
        scanner._request_form = AsyncMock(return_value=(200, "ok"))
        page = _DummyPage(
            "http://fixture.test/support",
            [
                {
                    "method": "POST",
                    "action": "http://fixture.test/support",
                    "inputs": [{"name": "message", "value": "hello", "type": "text"}],
                }
            ],
        )

        findings = await scanner._test_state_changing_forms(page)

        self.assertEqual(findings, [])
        scanner._request_form.assert_not_awaited()

    async def test_state_changing_form_ignores_rejected_low_priv_submission(self):
        engine = _DummyEngine()
        engine.low_priv_cookies = "sid=low"
        scanner = PrivEscScanner(engine)
        scanner._request_form = AsyncMock(return_value=(403, "forbidden"))
        page = _DummyPage(
            "http://fixture.test/admin/users",
            [
                {
                    "method": "POST",
                    "action": "http://fixture.test/admin/users/role",
                    "inputs": [{"name": "role", "value": "admin", "type": "text"}],
                }
            ],
        )

        findings = await scanner._test_state_changing_forms(page)

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
