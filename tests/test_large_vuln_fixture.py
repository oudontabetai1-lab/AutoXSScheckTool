import unittest

import httpx

from tests.fixtures.large_vuln_app import (
    FLAG_ADMIN,
    FLAG_BUNDLE_DISCOVERY,
    FLAG_HOME,
    FLAG_JS_DISCOVERY,
    FLAG_SSTI,
    create_app,
)


class LargeVulnerableFixtureTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.transport = httpx.ASGITransport(app=create_app(page_count=16))
        self.client = httpx.AsyncClient(
            transport=self.transport,
            base_url="http://large-fixture.test",
            follow_redirects=False,
        )

    async def asyncTearDown(self):
        await self.client.aclose()

    async def test_home_exposes_many_crawl_targets_and_public_flag(self):
        resp = await self.client.get("/")

        self.assertEqual(resp.status_code, 200)
        self.assertIn(FLAG_HOME, resp.text)
        self.assertGreaterEqual(resp.text.count("/section/"), 16)

    async def test_reflected_xss_targets_echo_payloads(self):
        payload = "<svg onload=alert(1)>"

        search_resp = await self.client.get("/search", params={"q": payload})
        review_resp = await self.client.get("/product/1/review", params={"comment": payload})

        self.assertIn(payload, search_resp.text)
        self.assertIn(payload, review_resp.text)

    async def test_stored_xss_target_persists_ticket_body(self):
        payload = '<script id="stored-large">alert(1)</script>'

        post_resp = await self.client.post(
            "/support",
            data={"subject": "case", "message": payload},
        )
        tickets_resp = await self.client.get("/tickets")

        self.assertEqual(post_resp.status_code, 303)
        self.assertIn(payload, tickets_resp.text)

    async def test_ssti_target_evaluates_scanner_probe_and_leaks_flag(self):
        resp = await self.client.get(
            "/template",
            params={"name": "{{2654435761*2654435761}}"},
        )

        self.assertIn("7045744422742119121", resp.text)
        self.assertIn(FLAG_SSTI, resp.text)

    async def test_path_traversal_target_returns_passwd_and_flag_files(self):
        passwd_resp = await self.client.get("/download", params={"file": "../../../../etc/passwd"})
        flag_resp = await self.client.get("/download", params={"file": "flag.txt"})

        self.assertIn("root:x:0:0", passwd_resp.text)
        self.assertIn("FLAG{large_fixture_lfi_flag}", flag_resp.text)

    async def test_open_redirect_target_reflects_external_location(self):
        resp = await self.client.get(
            "/go",
            params={"next": "https://evil.wscan-test.example.com"},
        )

        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.headers["location"], "https://evil.wscan-test.example.com")

    async def test_header_injection_target_reflects_injected_header(self):
        resp = await self.client.get(
            "/header-echo",
            params={"ref": "%0d%0aX-WscanHdrInject:%201"},
        )

        self.assertEqual(resp.headers["x-wscanhdrinject"], "1")

    async def test_fetch_url_simulates_ssrf_metadata_response(self):
        baseline_resp = await self.client.get(
            "/fetch",
            params={"url": "http://wscan-baseline-test.invalid/"},
        )
        metadata_resp = await self.client.get(
            "/fetch",
            params={"url": "http://169.254.169.254/latest/meta-data/"},
        )

        self.assertNotIn("instance-id", baseline_resp.text)
        self.assertIn("instance-id", metadata_resp.text)
        self.assertIn("local-ipv4", metadata_resp.text)

    async def test_graphql_endpoint_exposes_schema_batch_and_injection_signals(self):
        schema_resp = await self.client.post(
            "/graphql",
            json={"query": "{ __schema { queryType { name } types { name } } }"},
        )
        batch_resp = await self.client.post(
            "/graphql",
            json=[{"query": "{ __typename }"}, {"query": "{ __typename }"}],
        )
        injection_resp = await self.client.post(
            "/graphql",
            json={"query": '{ search(query: "{{7*7}}") }'},
        )

        self.assertIn("__schema", schema_resp.text)
        self.assertTrue(batch_resp.text.strip().startswith("["))
        self.assertIn("49", injection_resp.text)

    async def test_jwt_lab_exposes_weak_unsigned_payload_signals(self):
        resp = await self.client.get("/jwt-lab")

        self.assertIn("eyJ", resp.text)
        self.assertIn("token=", resp.headers["set-cookie"])

    async def test_cors_fixture_exposes_reflection_and_wildcard_misconfigs(self):
        reflect_resp = await self.client.get(
            "/cors-reflect",
            headers={"Origin": "https://evil.wscan-test.example.com"},
        )
        wildcard_resp = await self.client.get("/cors-wildcard")

        self.assertEqual(
            reflect_resp.headers["access-control-allow-origin"],
            "https://evil.wscan-test.example.com",
        )
        self.assertEqual(reflect_resp.headers["access-control-allow-credentials"], "true")
        self.assertEqual(wildcard_resp.headers["access-control-allow-origin"], "*")
        self.assertEqual(wildcard_resp.headers["access-control-allow-credentials"], "true")

    async def test_host_header_fixture_builds_reset_link_from_forwarded_host(self):
        resp = await self.client.get(
            "/host-reset",
            headers={"X-Forwarded-Host": "evil.wscan-test.example.com"},
        )

        self.assertIn("https://evil.wscan-test.example.com/reset/confirm", resp.text)

    async def test_env_fixture_exposes_sensitive_config(self):
        resp = await self.client.get("/.env")

        self.assertIn("DB_PASSWORD=fixture-password", resp.text)
        self.assertEqual(resp.headers["content-type"].split(";", 1)[0], "text/plain")

    async def test_os_command_target_returns_command_like_output(self):
        resp = await self.client.get("/ping", params={"host": "127.0.0.1; ls -la"})

        self.assertIn("total 8", resp.text)
        self.assertIn("drwxr-xr-x", resp.text)

    async def test_login_target_allows_sqli_auth_bypass_to_admin_flag(self):
        login_resp = await self.client.post(
            "/login",
            data={"username": "' OR '1'='1", "password": "x"},
        )
        admin_resp = await self.client.get(login_resp.headers["location"])

        self.assertEqual(login_resp.status_code, 302)
        self.assertIn(FLAG_ADMIN, admin_resp.text)

    async def test_nosql_login_expands_results_for_operator_payload(self):
        baseline_resp = await self.client.post(
            "/nosql-login",
            data={"username": "baseline_value_wscan", "password": "x"},
        )
        injection_resp = await self.client.post(
            "/nosql-login",
            data={"username": '{"$ne": ""}', "password": "x"},
        )

        self.assertIn("invalid login", baseline_resp.text)
        self.assertIn(FLAG_ADMIN, injection_resp.text)
        self.assertGreater(len(injection_resp.text) - len(baseline_resp.text), 500)

    async def test_deserialize_endpoint_returns_probe_only_error(self):
        baseline_resp = await self.client.post(
            "/deserialize",
            data={"data": "wscan_deser_baseline"},
        )
        probe_resp = await self.client.post(
            "/deserialize",
            data={"data": 'O:1:"A":1:{s:1:"a";R:99999999;}'},
        )

        self.assertNotIn("unserialize()", baseline_resp.text)
        self.assertIn("unserialize()", probe_resp.text)

    async def test_ldap_login_returns_probe_only_success_or_error(self):
        baseline_resp = await self.client.post(
            "/ldap-login",
            data={"username": "normaluser", "password": "x"},
        )
        bypass_resp = await self.client.post(
            "/ldap-login",
            data={"username": "*))(|(objectClass=*", "password": "x"},
        )
        error_resp = await self.client.post(
            "/ldap-login",
            data={"username": ")(invalid", "password": "x"},
        )

        self.assertIn("invalid login", baseline_resp.text)
        self.assertIn(FLAG_ADMIN, bypass_resp.text)
        self.assertIn("bad search filter", error_resp.text)

    async def test_xml_endpoint_returns_probe_only_file_marker(self):
        baseline_resp = await self.client.post(
            "/xml",
            content='<?xml version="1.0"?><root>wscan_xxe_baseline</root>',
            headers={"Content-Type": "application/xml"},
        )
        probe_resp = await self.client.post(
            "/xml",
            content='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
            headers={"Content-Type": "application/xml"},
        )

        self.assertNotIn("root:x:0:0", baseline_resp.text)
        self.assertIn("root:x:0:0", probe_resp.text)

    async def test_upload_endpoint_executes_probe_file(self):
        resp = await self.client.post(
            "/upload",
            files={"file": ("wscan_probe.php", b"<?php echo 'wscan-probe-' . phpversion(); ?>", "image/jpeg")},
        )

        self.assertIn("wscan-probe-8.2", resp.text)

    async def test_coupon_endpoint_allows_parallel_successes(self):
        import asyncio

        await self.client.get("/coupon")
        responses = await asyncio.gather(
            *[
                self.client.post("/coupon/apply", data={"coupon": "SAVE100"})
                for _ in range(4)
            ]
        )

        self.assertGreaterEqual(
            sum("success coupon accepted" in resp.text for resp in responses),
            2,
        )

    async def test_websocket_lab_exposes_echo_endpoint(self):
        resp = await self.client.get("/ws-lab")

        self.assertIn("new WebSocket", resp.text)
        self.assertIn("/ws/echo", resp.text)

    async def test_admin_action_form_allows_low_privilege_role_change(self):
        form_resp = await self.client.get("/admin/actions")
        action_resp = await self.client.post(
            "/admin/users/role",
            data={"user_id": "42", "role": "admin"},
            headers={"Cookie": "session=lowpriv"},
        )

        self.assertIn("/admin/users/role", form_resp.text)
        self.assertEqual(action_resp.status_code, 200)
        self.assertIn(FLAG_ADMIN, action_resp.text)

    async def test_ctf_route_exposes_standard_flag_format(self):
        resp = await self.client.get("/ctf/public")

        self.assertIn("CTF{large_fixture_ctf_public}", resp.text)

    async def test_js_discovered_ctf_route_requires_script_url(self):
        home_resp = await self.client.get("/")
        flag_resp = await self.client.get("/ctf/js-hidden", params={"token": "from-script"})

        self.assertIn("/ctf/js-hidden?token=from-script", home_resp.text)
        self.assertIn(FLAG_JS_DISCOVERY, flag_resp.text)

    async def test_bundle_discovered_ctf_route_requires_loaded_script_url(self):
        js_resp = await self.client.get("/static/app.js")
        flag_resp = await self.client.get("/ctf/bundle-hidden", params={"token": "from-bundle"})

        self.assertIn("/ctf/bundle-hidden?token=from-bundle", js_resp.text)
        self.assertIn(FLAG_BUNDLE_DISCOVERY, flag_resp.text)


if __name__ == "__main__":
    unittest.main()
