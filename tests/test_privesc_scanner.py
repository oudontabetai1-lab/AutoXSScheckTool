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
        self.allow_state_changing_probes = False


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


    # ------------------------------------------------------------------
    # 401/403 access-control bypass
    # ------------------------------------------------------------------

    async def test_bypass_flags_path_normalisation(self):
        scanner = PrivEscScanner(_DummyEngine())
        admin = "<html><h1>Admin dashboard</h1><p>secret exports here</p></html>"
        home = "<html><body>Public homepage — welcome, browse products.</body></html>"

        async def fake(method, url, timeout, *, headers=None, cookies=""):
            tail = url.split("fixture.test", 1)[-1]
            if "nonexistent" in tail:
                return 404, "not found"          # nonexistent controls
            if tail in ("/", ""):
                return 200, home                 # public-root control
            if tail == "/admin":
                return 403, ""                   # canonical resource blocked
            return 200, admin                    # a normalisation variant serves admin

        scanner._raw_request = AsyncMock(side_effect=fake)

        findings = await scanner._test_forbidden_bypass(
            "http://fixture.test/admin", True, timeout=3,
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].check_type, "privesc_bypass")
        self.assertEqual(findings[0].response["baseline_status"], 403)

    async def test_bypass_path_variant_suppressed_by_public_root(self):
        # A variant like '/admin/..;/' is collapsed by the server to the public
        # root '/'. It only reached the homepage, not the protected resource.
        scanner = PrivEscScanner(_DummyEngine())
        home = "<html><body>Public homepage — welcome, browse our products here.</body></html>"

        async def fake(method, url, timeout, *, headers=None, cookies=""):
            tail = url.split("fixture.test", 1)[-1]
            if "nonexistent" in tail:
                return 404, "not found"          # nonexistent controls 404
            if tail == "/admin":
                return 403, ""                   # canonical resource blocked
            return 200, home                     # root + every variant -> homepage

        scanner._raw_request = AsyncMock(side_effect=fake)

        findings = await scanner._test_forbidden_bypass(
            "http://fixture.test/admin", True, timeout=3,
        )

        self.assertEqual(findings, [])

    async def test_bypass_path_variant_suppressed_by_catchall(self):
        # The server serves a generic 200 page (SPA fallback) for ANY unknown
        # path, including the catch-all control -> path variants must not flag.
        scanner = PrivEscScanner(_DummyEngine())
        spa = "<html><body><div id='app'>Loading the single page app…</div></body></html>"

        async def fake(method, url, timeout, *, headers=None, cookies=""):
            # The /admin route itself is access-controlled and stays blocked
            # regardless of spoofed headers or method.
            if url.rstrip("/").endswith("/admin"):
                return 403, ""
            # Any other (unknown) path -> SPA catch-all 200 (control + variants).
            return 200, spa

        scanner._raw_request = AsyncMock(side_effect=fake)

        findings = await scanner._test_forbidden_bypass(
            "http://fixture.test/admin", True, timeout=3,
        )

        self.assertEqual(findings, [])

    async def test_bypass_does_not_probe_or_report_options(self):
        # A successful OPTIONS response is not evidence of a bypass, so OPTIONS
        # must neither be probed by default nor reported.
        scanner = PrivEscScanner(_DummyEngine())
        cors = "<html><body>CORS preflight OK. Allow: GET, POST, OPTIONS. Move along now.</body></html>"
        seen_methods = []

        async def fake(method, url, timeout, *, headers=None, cookies=""):
            seen_methods.append(method)
            if method == "OPTIONS":
                return 200, cors        # generic handler for every path
            return 403, ""              # GET (baseline + all variants) blocked

        scanner._raw_request = AsyncMock(side_effect=fake)

        findings = await scanner._test_forbidden_bypass(
            "http://fixture.test/admin", True, timeout=3,
        )

        self.assertEqual(findings, [])
        self.assertNotIn("OPTIONS", seen_methods)

    async def test_bypass_spoofed_header_suppressed_by_default_vhost(self):
        # X-Forwarded-Host routes ANY path to a default marketing vhost; the
        # protected resource was never served, so no finding should fire.
        scanner = PrivEscScanner(_DummyEngine())
        vhost = "<html><body>Welcome to the default marketing site — products and pricing.</body></html>"

        async def fake(method, url, timeout, *, headers=None, cookies=""):
            if headers and any(k.lower() == "x-forwarded-host" for k in headers):
                return 200, vhost       # header re-routes every path to the vhost
            return 403, ""

        scanner._raw_request = AsyncMock(side_effect=fake)

        findings = await scanner._test_forbidden_bypass(
            "http://fixture.test/admin", True, timeout=3,
        )

        self.assertEqual(findings, [])

    async def test_bypass_verb_tampering_requires_optin_for_mutating(self):
        # Without opt-in, only OPTIONS is sent (no POST/PUT/PATCH). A server that
        # would serve content on POST must NOT be probed with POST by default.
        engine = _DummyEngine()
        scanner = PrivEscScanner(engine)
        seen_methods = []

        async def fake(method, url, timeout, *, headers=None, cookies=""):
            seen_methods.append(method)
            return 403, ""              # everything blocked -> reach verb stage

        scanner._raw_request = AsyncMock(side_effect=fake)

        await scanner._test_forbidden_bypass(
            "http://fixture.test/admin", True, timeout=3,
        )

        # Nothing is probed by default (OPTIONS removed, mutating verbs gated).
        self.assertNotIn("OPTIONS", seen_methods)
        self.assertNotIn("POST", seen_methods)
        self.assertNotIn("PUT", seen_methods)
        self.assertNotIn("PATCH", seen_methods)

        # With opt-in, mutating verbs are allowed.
        engine.allow_state_changing_probes = True
        seen_methods.clear()
        await scanner._test_forbidden_bypass(
            "http://fixture.test/admin", True, timeout=3,
        )
        self.assertIn("POST", seen_methods)

    async def test_bypass_flags_spoofed_header(self):
        scanner = PrivEscScanner(_DummyEngine())
        good = "<html><h1>Admin dashboard</h1><p>internal only content</p></html>"

        async def fake(method, url, timeout, *, headers=None, cookies=""):
            if not headers:
                # baseline + every path-normalisation variant stay blocked
                return 403, ""
            if any(k.lower().startswith("x-") for k in headers):
                # A genuine bypass: the spoofed header opens the protected URL,
                # but the same header on a nonexistent path still 404s.
                if "nonexistent" in url:
                    return 404, "not found"
                return 200, good
            return 403, ""

        scanner._raw_request = AsyncMock(side_effect=fake)

        findings = await scanner._test_forbidden_bypass(
            "http://fixture.test/admin", True, timeout=3,
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].check_type, "privesc_bypass")
        self.assertIn("header", findings[0].field_name)

    async def test_bypass_skipped_when_baseline_not_blocked(self):
        scanner = PrivEscScanner(_DummyEngine())
        scanner._raw_request = AsyncMock(return_value=(200, "open content here"))

        findings = await scanner._test_forbidden_bypass(
            "http://fixture.test/admin", True, timeout=3,
        )

        self.assertEqual(findings, [])
        scanner._raw_request.assert_awaited_once()

    async def test_bypass_ignores_auth_gate_on_variant(self):
        scanner = PrivEscScanner(_DummyEngine())
        # Baseline blocked, then every probe returns a login gate (200 but gated)
        gate = "<html>Please log in to continue to the admin area</html>"

        async def fake(method, url, timeout, *, headers=None, cookies=""):
            if method == "GET" and url.endswith("/admin") and not headers:
                return 403, ""
            return 200, gate

        scanner._raw_request = AsyncMock(side_effect=fake)

        findings = await scanner._test_forbidden_bypass(
            "http://fixture.test/admin", True, timeout=3,
        )

        self.assertEqual(findings, [])

    async def test_bypass_rewrite_header_suppressed_when_control_equal(self):
        # Proxy ignores X-Original-URL: root keeps serving its public homepage,
        # identical to the control request -> must NOT be flagged.
        scanner = PrivEscScanner(_DummyEngine())
        home = "<html><body>Welcome to our public homepage. Browse products here.</body></html>"

        async def fake(method, url, timeout, *, headers=None, cookies=""):
            if headers and any(h.lower() in ("x-original-url", "x-rewrite-url") for h in headers):
                return 200, home          # header ignored -> homepage
            if headers:
                return 403, ""            # spoofed-IP headers still blocked
            if "/admin" in url.lower():
                return 403, ""            # baseline + path variants blocked
            return 200, home              # control request to '/'

        scanner._raw_request = AsyncMock(side_effect=fake)

        findings = await scanner._test_forbidden_bypass(
            "http://fixture.test/admin", True, timeout=3,
        )

        self.assertEqual(findings, [])

    async def test_bypass_rewrite_header_flagged_when_content_differs(self):
        scanner = PrivEscScanner(_DummyEngine())
        home = "<html><body>Welcome to our public homepage. Browse products here.</body></html>"
        admin = "<html><body>ADMIN PANEL: user list, secret exports, billing settings</body></html>"

        async def fake(method, url, timeout, *, headers=None, cookies=""):
            if headers:
                for h, v in headers.items():
                    if h.lower() in ("x-original-url", "x-rewrite-url"):
                        # Honoured: the protected target serves admin content,
                        # but a nonexistent rewrite target still 404s.
                        if "nonexistent" in v:
                            return 404, "not found"
                        return 200, admin
                return 403, ""
            if "/admin" in url.lower():
                return 403, ""
            return 200, home              # control request to '/'

        scanner._raw_request = AsyncMock(side_effect=fake)

        findings = await scanner._test_forbidden_bypass(
            "http://fixture.test/admin", True, timeout=3,
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].check_type, "privesc_bypass")
        self.assertIn("rewrite header", findings[0].field_name)

    def test_strip_credential_headers_removes_auth_keeps_routing(self):
        from wscan.scanners.privesc import _strip_credential_headers
        stripped = _strip_credential_headers({
            "Authorization": "Bearer xyz",
            "X-API-Key": "secret",
            "X-Auth-Token": "t",
            "Cookie": "sid=1",
            "X-App-Version": "2.0",
            "Accept-Language": "ja",
        })
        self.assertNotIn("Authorization", stripped)
        self.assertNotIn("X-API-Key", stripped)
        self.assertNotIn("X-Auth-Token", stripped)
        self.assertNotIn("Cookie", stripped)
        self.assertEqual(stripped, {"X-App-Version": "2.0", "Accept-Language": "ja"})

    async def test_bypass_verifier_replays_request(self):
        scanner = PrivEscScanner(_DummyEngine())
        admin = "<html><h1>Admin</h1><p>secret content here for the panel</p></html>"

        async def fake(method, url, timeout, *, headers=None, cookies=""):
            if url.rstrip("/").endswith("/admin"):
                return 403, ""              # canonical resource still blocked
            if "nonexistent" in url:
                return 404, "not found"     # control paths
            return 200, admin               # the /admin/. variant serves content

        scanner._raw_request = AsyncMock(side_effect=fake)
        finding = Finding(
            check_type="privesc_bypass",
            severity="high",
            url="http://fixture.test/admin",
            field_name="(access-control bypass: path normalisation '/admin/.')",
            payload="http://fixture.test/admin/.",
            evidence="bypass via path normalisation",
            request={"url": "http://fixture.test/admin/.", "method": "GET", "headers": {}},
        )

        result = await scanner.verify_finding(finding)

        self.assertTrue(result)

    async def test_bypass_verifier_rejects_when_baseline_now_public(self):
        # If the canonical resource is no longer blocked, there is no bypass.
        scanner = PrivEscScanner(_DummyEngine())
        scanner._raw_request = AsyncMock(
            return_value=(200, "<html><h1>Admin</h1><p>now public content</p></html>")
        )
        finding = Finding(
            check_type="privesc_bypass",
            severity="high",
            url="http://fixture.test/admin",
            field_name="(access-control bypass: path normalisation '/admin/.')",
            payload="http://fixture.test/admin/.",
            evidence="bypass via path normalisation",
            request={"url": "http://fixture.test/admin/.", "method": "GET", "headers": {}},
        )

        result = await scanner.verify_finding(finding)

        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
