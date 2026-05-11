import unittest

import httpx

from tests.fixtures.large_vuln_app import FLAG_ADMIN, FLAG_HOME, FLAG_SSTI, create_app


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

    async def test_ctf_route_exposes_standard_flag_format(self):
        resp = await self.client.get("/ctf/public")

        self.assertIn("CTF{large_fixture_ctf_public}", resp.text)


if __name__ == "__main__":
    unittest.main()
