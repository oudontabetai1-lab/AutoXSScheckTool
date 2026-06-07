import unittest

import httpx

from tests.fixtures.realistic_api import (
    EXPECTED_FINDINGS,
    SAFE_ENDPOINTS,
    SECURITY_HEADERS,
    create_app,
    form_has_csrf_token,
)
from wscan.scanners.jwt_scanner import _parse_jwt, _verify_hs
from wscan.scanners.secret_leak import scan_text_for_secrets


CANARY_ORIGIN = "https://evil.wscan-test.example.com"
ALLOWLISTED_ORIGIN = "https://app.acme-cloud.test"


class RealisticAPIFixtureTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.transport = httpx.ASGITransport(app=create_app())
        self.client = httpx.AsyncClient(
            transport=self.transport,
            base_url="http://acme-console.test",
            follow_redirects=False,
        )

    async def asyncTearDown(self):
        await self.client.aclose()

    async def test_ground_truth_pairs_are_complete(self):
        expected = {(item["check"], item["path"], item["field"]) for item in EXPECTED_FINDINGS}
        safe = {(item["check"], item["path"], item["field"]) for item in SAFE_ENDPOINTS}

        self.assertEqual(len(expected), len(EXPECTED_FINDINGS))
        self.assertEqual(len(safe), len(SAFE_ENDPOINTS))
        self.assertEqual(
            {item["check"] for item in EXPECTED_FINDINGS},
            {item["check"] for item in SAFE_ENDPOINTS},
        )
        self.assertIn(("jwt_weak_secret", "/api/v1/session/bootstrap", None), expected)

    async def test_home_links_to_console_and_api_surfaces(self):
        resp = await self.client.get("/")

        self.assertEqual(resp.status_code, 200)
        for entry in EXPECTED_FINDINGS + SAFE_ENDPOINTS:
            if entry["path"].endswith(".env"):
                continue
            with self.subTest(path=entry["path"]):
                self.assertIn(f'href="{entry["path"]}"', resp.text)

    async def test_security_headers_vulnerability_and_safe_twin(self):
        vulnerable = await self.client.get("/console/insecure")
        safe = await self.client.get("/console/secure")

        missing = [
            name
            for name in SECURITY_HEADERS
            if name.lower() not in vulnerable.headers
            and name.lower() != "x-frame-options"
            and name.lower() != "cross-origin-resource-policy"
        ]
        self.assertGreaterEqual(len(missing), 5)
        self.assertNotIn("content-security-policy", vulnerable.headers)
        self.assertEqual(vulnerable.headers["x-frame-options"], "DENY")
        for name, value in SECURITY_HEADERS.items():
            self.assertEqual(safe.headers[name.lower()], value)

    async def test_clickjacking_vulnerability_and_safe_twin(self):
        vulnerable = await self.client.get("/console/embed")
        safe = await self.client.get("/console/embed-safe")

        self.assertNotIn("x-frame-options", vulnerable.headers)
        self.assertIn("content-security-policy", vulnerable.headers)
        self.assertNotIn("frame-ancestors", vulnerable.headers["content-security-policy"].lower())
        self.assertEqual(safe.headers["x-frame-options"], "DENY")
        self.assertIn("frame-ancestors 'none'", safe.headers["content-security-policy"])

    async def test_cors_reflects_canary_origin_and_safe_twin_blocks_it(self):
        vulnerable = await self.client.get(
            "/api/v1/reports/export",
            headers={"Origin": CANARY_ORIGIN},
        )
        safe_canary = await self.client.get(
            "/api/v1/reports/export-safe",
            headers={"Origin": CANARY_ORIGIN},
        )
        safe_allowed = await self.client.get(
            "/api/v1/reports/export-safe",
            headers={"Origin": ALLOWLISTED_ORIGIN},
        )

        self.assertEqual(vulnerable.headers["access-control-allow-origin"], CANARY_ORIGIN)
        self.assertEqual(vulnerable.headers["access-control-allow-credentials"], "true")
        self.assertNotIn("access-control-allow-origin", safe_canary.headers)
        self.assertNotIn("access-control-allow-credentials", safe_canary.headers)
        self.assertEqual(safe_allowed.headers["access-control-allow-origin"], ALLOWLISTED_ORIGIN)
        self.assertEqual(safe_allowed.headers["access-control-allow-credentials"], "true")

    async def test_session_cookie_attributes_and_safe_twin(self):
        vulnerable = await self.client.get("/api/v1/session/issue")
        safe = await self.client.get("/api/v1/session/issue-safe")

        weak_cookie = vulnerable.headers["set-cookie"]
        strong_cookie = safe.headers["set-cookie"]
        self.assertIn("acme_session=", weak_cookie)
        self.assertNotIn("Secure", weak_cookie)
        self.assertNotIn("HttpOnly", weak_cookie)
        self.assertNotIn("SameSite", weak_cookie)
        self.assertIn("Secure", strong_cookie)
        self.assertIn("HttpOnly", strong_cookie)
        self.assertIn("SameSite=Lax", strong_cookie)

    async def test_csrf_form_omits_token_and_safe_twin_includes_it(self):
        vulnerable = await self.client.get("/console/billing/payment-method")
        safe = await self.client.get("/console/billing/payment-method-safe")

        self.assertIn('method="post"', vulnerable.text.lower())
        self.assertFalse(form_has_csrf_token(vulnerable.text))
        self.assertIn('method="post"', safe.text.lower())
        self.assertTrue(form_has_csrf_token(safe.text))
        self.assertIn('name="csrf_token"', safe.text)

    async def test_env_disclosure_and_safe_twin(self):
        vulnerable = await self.client.get("/.env")
        safe = await self.client.get("/safe/.env")

        self.assertEqual(vulnerable.status_code, 200)
        self.assertIn("DB_PASSWORD=fixture-prod-password", vulnerable.text)
        self.assertIn("SECRET_KEY=fixture-secret-key", vulnerable.text)
        self.assertEqual(safe.status_code, 404)
        self.assertNotIn("DB_PASSWORD", safe.text)
        self.assertNotIn("SECRET_KEY", safe.text)

    async def test_traceback_disclosure_and_safe_twin(self):
        vulnerable = await self.client.get("/console/debug-error")
        safe = await self.client.get("/console/safe-error")

        self.assertIn("Traceback (most recent call last)", vulnerable.text)
        self.assertIn('File "/srv/acme/console/views.py"', vulnerable.text)
        self.assertNotIn("Traceback (most recent call last)", safe.text)
        self.assertNotIn("/srv/acme", safe.text)
        self.assertIn("Please retry later", safe.text)

    async def test_secret_leak_bundle_and_safe_twin(self):
        vulnerable = await self.client.get("/static/console.js")
        safe = await self.client.get("/static/console.safe.js")

        vulnerable_hits = scan_text_for_secrets(vulnerable.text)
        safe_hits = scan_text_for_secrets(safe.text)
        labels = {hit["label"] for hit in vulnerable_hits}
        self.assertIn("AWS Access Key ID", labels)
        self.assertIn("GitHub Personal Access Token", labels)
        self.assertIn("Stripe Secret Key", labels)
        self.assertEqual(safe_hits, [])
        self.assertIn("YOUR_KEY_HERE", safe.text)
        self.assertIn("AKIAEXAMPLE", safe.text)

    async def test_jwt_weak_secret_and_safe_twin(self):
        vulnerable = await self.client.get("/api/v1/session/bootstrap")
        safe = await self.client.get("/api/v1/session/bootstrap-safe")

        weak_token = vulnerable.json()["access_token"]
        strong_token = safe.json()["access_token"]
        weak_parsed = _parse_jwt(weak_token)
        strong_parsed = _parse_jwt(strong_token)
        self.assertIsNotNone(weak_parsed)
        self.assertIsNotNone(strong_parsed)

        weak_header, weak_payload, _weak_sig = weak_parsed
        strong_header, strong_payload, _strong_sig = strong_parsed
        self.assertEqual(weak_header["alg"], "HS256")
        self.assertIn("exp", weak_payload)
        self.assertEqual(weak_payload["role"], "analyst")
        self.assertTrue(_verify_hs(weak_token, "secret"))
        self.assertFalse(_verify_hs(strong_token, "secret"))
        self.assertEqual(strong_header["alg"], "HS256")
        self.assertIn("exp", strong_payload)


if __name__ == "__main__":
    unittest.main()
