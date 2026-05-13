import unittest
from unittest.mock import AsyncMock

from wscan.scanners.base import Finding
from wscan.scanners.privesc import PrivEscScanner


class _DummyEngine:
    def __init__(self):
        self.browser = object()
        self.payload_gen = None
        self.proxy = ""
        self.timeout = 30
        self.cookies = ""
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

    async def test_path_idor_ignores_generic_identical_200_page(self):
        scanner = PrivEscScanner(_DummyEngine())
        generic = "<html><h1>Portal</h1><p>Use the left menu to open records.</p></html>" * 3
        scanner._get = AsyncMock(side_effect=[
            (200, generic),
            (200, generic),
            (200, generic),
            (200, generic),
            (200, generic),
        ])

        findings = await scanner._test_horizontal_privesc(
            "http://fixture.test/orders/100",
            "sid=alice",
            timeout=3,
        )

        self.assertEqual(findings, [])

    async def test_path_idor_flags_object_specific_candidate_response(self):
        scanner = PrivEscScanner(_DummyEngine())

        async def fake_get(url, cookies, timeout):
            order_id = url.rsplit("/", 1)[-1]
            if order_id == "100":
                return 200, "<html><h1>Order 100</h1><p>Owner: alice</p><p>Total 12000</p></html>"
            return 200, f"<html><h1>Order {order_id}</h1><p>Owner: bob</p><p>Total 9200</p></html>"

        scanner._get = AsyncMock(side_effect=fake_get)

        findings = await scanner._test_horizontal_privesc(
            "http://fixture.test/orders/100",
            "sid=alice",
            timeout=3,
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].check_type, "privesc_horizontal")
        self.assertEqual(findings[0].response["confidence_reason"], "candidate object identifier is present in response")

    async def test_param_idor_ignores_not_found_200_page(self):
        scanner = PrivEscScanner(_DummyEngine())
        scanner._get = AsyncMock(side_effect=[
            (200, "<html><h1>Invoice 100</h1><p>Owner: alice</p><p>Total 12000</p></html>"),
            (200, "<html><h1>Not found</h1><p>No such record exists.</p></html>"),
            (200, "<html><h1>Not found</h1><p>No such record exists.</p></html>"),
            (200, "<html><h1>Not found</h1><p>No such record exists.</p></html>"),
            (200, "<html><h1>Not found</h1><p>No such record exists.</p></html>"),
        ])

        findings = await scanner._test_param_idor(
            "http://fixture.test/invoices?invoice_id=100",
            "sid=alice",
            timeout=3,
        )

        self.assertEqual(findings, [])

    async def test_scan_page_skips_public_catalog_path_idor(self):
        engine = _DummyEngine()
        engine.cookies = "sid=alice"
        scanner = PrivEscScanner(engine)
        scanner._test_unauth = AsyncMock(return_value=None)
        scanner._test_horizontal_privesc = AsyncMock(return_value=[])
        scanner._test_param_idor = AsyncMock(return_value=[])

        findings = await scanner.scan_page("http://fixture.test/product/100")

        self.assertEqual(findings, [])
        scanner._test_horizontal_privesc.assert_not_awaited()
        scanner._test_param_idor.assert_not_awaited()

    async def test_scan_page_keeps_sensitive_query_idor_probe(self):
        engine = _DummyEngine()
        engine.cookies = "sid=alice"
        scanner = PrivEscScanner(engine)
        scanner._test_unauth = AsyncMock(return_value=None)
        scanner._test_horizontal_privesc = AsyncMock(return_value=[])
        scanner._test_param_idor = AsyncMock(return_value=[])

        await scanner.scan_page("http://fixture.test/view?order_id=100")

        scanner._test_horizontal_privesc.assert_not_awaited()
        scanner._test_param_idor.assert_awaited_once()

    async def test_unauth_verifier_replays_bare_request(self):
        scanner = PrivEscScanner(_DummyEngine())
        scanner._get = AsyncMock(return_value=(200, "<html><h1>Admin reports</h1><p>secret</p></html>"))
        finding = Finding(
            check_type="privesc_unauth",
            severity="high",
            url="http://fixture.test/admin/reports",
            field_name="(URL-level access control)",
            payload="unauthenticated GET",
            evidence="admin reachable without cookies",
            request={"url": "http://fixture.test/admin/reports", "method": "GET", "headers": {}},
        )

        result = await scanner.verify_finding(finding)

        self.assertTrue(result)
        scanner._get.assert_awaited_once_with("http://fixture.test/admin/reports", "", 30.0)

    async def test_unauth_verifier_rejects_login_gate(self):
        scanner = PrivEscScanner(_DummyEngine())
        scanner._get = AsyncMock(return_value=(200, "<html>Please log in to continue</html>"))
        finding = Finding(
            check_type="privesc_unauth",
            severity="high",
            url="http://fixture.test/admin/reports",
            field_name="(URL-level access control)",
            payload="unauthenticated GET",
            evidence="admin reachable without cookies",
            request={"url": "http://fixture.test/admin/reports", "method": "GET", "headers": {}},
        )

        result = await scanner.verify_finding(finding)

        self.assertFalse(result)

    async def test_unauth_verifier_allows_normal_login_nav_link(self):
        scanner = PrivEscScanner(_DummyEngine())
        scanner._get = AsyncMock(return_value=(
            200,
            "<html><nav><a href='/login'>Login</a></nav><main>Admin dashboard secret</main></html>",
        ))
        finding = Finding(
            check_type="privesc_unauth",
            severity="high",
            url="http://fixture.test/admin",
            field_name="(URL-level access control)",
            payload="unauthenticated GET",
            evidence="admin reachable without cookies",
            request={"url": "http://fixture.test/admin", "method": "GET", "headers": {}},
        )

        result = await scanner.verify_finding(finding)

        self.assertTrue(result)

    async def test_emit_does_not_append_directly_to_engine_findings(self):
        engine = _DummyEngine()
        scanner = PrivEscScanner(engine)
        finding = Finding(
            check_type="privesc_unauth",
            severity="medium",
            url="http://fixture.test/admin",
            field_name="(URL-level access control)",
            payload="unauthenticated GET",
            evidence="admin reachable without cookies",
        )

        await scanner._emit(finding)

        self.assertEqual(scanner.findings, [finding])
        self.assertEqual(engine.all_findings, [])

    async def test_param_idor_verifier_replays_candidate_url(self):
        engine = _DummyEngine()
        engine.cookies = "sid=alice"
        scanner = PrivEscScanner(engine)
        scanner._get = AsyncMock(side_effect=[
            (200, "<html><h1>Invoice 100</h1><p>Owner: alice</p><p>Total 12000</p></html>"),
            (200, "<html><h1>Invoice 101</h1><p>Owner: bob</p><p>Total 9200</p></html>"),
        ])
        finding = Finding(
            check_type="privesc_param_idor",
            severity="high",
            url="http://fixture.test/invoices?invoice_id=100",
            field_name="(query param: invoice_id=100)",
            payload="?invoice_id=101",
            evidence="parameter IDOR",
            request={
                "url": "http://fixture.test/invoices?invoice_id=101",
                "method": "GET",
                "headers": {"Cookie": "<session-token>"},
            },
        )

        result = await scanner.verify_finding(finding)

        self.assertTrue(result)
        scanner._get.assert_any_await("http://fixture.test/invoices?invoice_id=100", "sid=alice", 30.0)
        scanner._get.assert_any_await("http://fixture.test/invoices?invoice_id=101", "sid=alice", 30.0)

    async def test_action_verifier_replays_low_priv_form(self):
        engine = _DummyEngine()
        engine.low_priv_cookies = "sid=low"
        scanner = PrivEscScanner(engine)
        scanner._request_form = AsyncMock(return_value=(200, "<html>user promoted</html>"))
        finding = Finding(
            check_type="privesc_action",
            severity="high",
            url="http://fixture.test/admin/users",
            field_name="(state-changing action: POST /admin/users/role)",
            payload="low-privilege session submitted form",
            evidence="low privilege action accepted",
            request={
                "url": "http://fixture.test/admin/users/role",
                "method": "POST",
                "headers": {"Cookie": "<low-privilege-token>"},
                "body": {"user_id": "42", "role": "admin"},
            },
        )

        result = await scanner.verify_finding(finding)

        self.assertTrue(result)
        scanner._request_form.assert_awaited_once_with(
            "POST",
            "http://fixture.test/admin/users/role",
            {"user_id": "42", "role": "admin"},
            "sid=low",
            30.0,
        )


if __name__ == "__main__":
    unittest.main()
