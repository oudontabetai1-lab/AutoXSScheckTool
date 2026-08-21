import unittest

import httpx

from tests.fixtures.spa_app import EXPECTED_FINDINGS, SAFE_ENDPOINTS, app


class SpaFixtureTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.transport = httpx.ASGITransport(app=app)
        self.client = httpx.AsyncClient(
            transport=self.transport,
            base_url="http://spa-fixture.test",
            follow_redirects=False,
        )

    async def asyncTearDown(self):
        await self.client.aclose()

    async def test_ground_truth_exposes_vulnerable_and_safe_twin(self):
        self.assertEqual(EXPECTED_FINDINGS, [
            {"endpoint": "/rest/products/search", "param": "q", "check": "xss"},
            {"endpoint": "/api/login", "pointer": "/email", "check": "sqli"},
        ])
        self.assertEqual(SAFE_ENDPOINTS, [
            {"endpoint": "/rest/products/safe-search", "param": "q", "check": "xss"},
            {"endpoint": "/api/login_safe", "pointer": "/email", "check": "sqli"},
        ])

    async def test_root_is_csr_shell_that_fetches_and_renders_json(self):
        response = await self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("<app-root></app-root>", response.text)
        self.assertIn("fetch('/rest/products/search?q='", response.text)
        self.assertIn("fetch('/api/login', {method: 'POST'", response.text)
        self.assertIn("fetch('/api/login_safe', {method: 'POST'", response.text)
        self.assertIn("result.html", response.text)

    async def test_search_reflects_xss_and_safe_twin_escapes_it(self):
        payload = "<script>alert(1)</script>"

        vulnerable = await self.client.get(
            "/rest/products/search", params={"q": payload}
        )
        safe = await self.client.get(
            "/rest/products/safe-search", params={"q": payload}
        )

        self.assertEqual(vulnerable.status_code, 200)
        self.assertIn(payload, vulnerable.text)
        self.assertEqual(vulnerable.json()["html"], f"<section>Search result: {payload}</section>")

        self.assertEqual(safe.status_code, 200)
        self.assertNotIn(payload, safe.text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", safe.text)

    async def test_json_login_exposes_sql_error_and_safe_twin_stays_fixed(self):
        payload = "a@b.test'"

        vulnerable = await self.client.post(
            "/api/login", json={"email": payload, "password": "x"}
        )
        safe = await self.client.post(
            "/api/login_safe", json={"email": payload, "password": "x"}
        )

        self.assertEqual(vulnerable.status_code, 500)
        self.assertIn("You have an error in your SQL syntax", vulnerable.text)
        self.assertEqual(safe.status_code, 200)
        self.assertEqual(safe.json(), {"authenticated": False})


if __name__ == "__main__":
    unittest.main()
