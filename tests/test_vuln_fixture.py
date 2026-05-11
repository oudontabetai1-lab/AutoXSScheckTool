import unittest

import httpx

from tests.fixtures.vuln_app import create_app


class VulnerableFixtureTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.transport = httpx.ASGITransport(app=create_app())
        self.client = httpx.AsyncClient(
            transport=self.transport,
            base_url="http://fixture.test",
            follow_redirects=False,
        )

    async def asyncTearDown(self):
        await self.client.aclose()

    async def test_search_reflects_payload_for_xss_regression(self):
        payload = "<svg onload=alert(1)>"
        resp = await self.client.get("/search", params={"q": payload})

        self.assertEqual(resp.status_code, 200)
        self.assertIn(payload, resp.text)

    async def test_dom_fixture_moves_query_value_to_inner_html(self):
        payload = "<img src=x onerror=alert(1)>"
        resp = await self.client.get("/dom", params={"next": payload})

        self.assertEqual(resp.status_code, 200)
        self.assertIn("innerHTML", resp.text)
        self.assertIn(payload, resp.text)

    async def test_feedback_fixture_persists_comment_for_stored_xss(self):
        payload = '<script id="wsxssfixture">alert(1)</script>'

        post_resp = await self.client.post("/feedback", data={"message": payload})
        comments_resp = await self.client.get("/comments")

        self.assertEqual(post_resp.status_code, 303)
        self.assertEqual(post_resp.headers["location"], "/comments")
        self.assertIn(payload, comments_resp.text)

    async def test_login_fixture_has_sqli_auth_bypass_signal(self):
        resp = await self.client.post(
            "/login",
            data={"username": "' OR '1'='1", "password": "x"},
        )

        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.headers["location"], "/admin")


if __name__ == "__main__":
    unittest.main()
