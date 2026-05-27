import unittest

import httpx

from tests.fixtures.header_matrix_app import SAFE_HEADERS, create_app


class HeaderMatrixFixtureTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.transport = httpx.ASGITransport(app=create_app())
        self.client = httpx.AsyncClient(
            transport=self.transport,
            base_url="http://header-matrix.test",
            follow_redirects=False,
        )

    async def asyncTearDown(self):
        await self.client.aclose()

    async def test_safe_page_has_all_required_security_headers(self):
        resp = await self.client.get("/safe")

        self.assertEqual(resp.status_code, 200)
        for header, expected in SAFE_HEADERS.items():
            self.assertEqual(resp.headers[header.lower()], expected)

    async def test_missing_page_removes_only_permissions_policy(self):
        resp = await self.client.get("/missing")

        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("permissions-policy", resp.headers)
        for header, expected in SAFE_HEADERS.items():
            if header == "Permissions-Policy":
                continue
            self.assertEqual(resp.headers[header.lower()], expected)

    async def test_unsafe_csp_keeps_header_but_allows_inline_script(self):
        resp = await self.client.get("/unsafe-csp")

        self.assertEqual(resp.status_code, 200)
        self.assertIn("'unsafe-inline'", resp.headers["content-security-policy"])
        self.assertEqual(resp.headers["strict-transport-security"], SAFE_HEADERS["Strict-Transport-Security"])

    async def test_short_hsts_keeps_header_with_low_max_age(self):
        resp = await self.client.get("/short-hsts")

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers["strict-transport-security"], "max-age=60")
        self.assertEqual(resp.headers["content-security-policy"], SAFE_HEADERS["Content-Security-Policy"])


if __name__ == "__main__":
    unittest.main()
