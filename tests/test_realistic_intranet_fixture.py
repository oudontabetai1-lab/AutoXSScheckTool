"""
realistic_intranet フィクスチャの自己検証テスト（ブラウザ不要）。

httpx.ASGITransport でアプリへ直接リクエストし、「仕込んだ脆弱挙動が実際に
出る／安全ツインでは出ない」ことを確認する。スキャナ本体の検出は opt-in の
E2E（tests/test_end_to_end_scan_extra.py）が担うが、ここではフィクスチャ自体が
意図どおり振る舞うことを高速に保証する。
"""
import re
import time
import unittest

import httpx

from tests.fixtures.realistic_intranet import (
    EXPECTED_FINDINGS,
    SAFE_ENDPOINTS,
    create_app,
)


class RealisticIntranetFixtureTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.transport = httpx.ASGITransport(app=create_app())
        self.client = httpx.AsyncClient(
            transport=self.transport,
            base_url="http://intranet.test",
            follow_redirects=False,
        )

    async def asyncTearDown(self):
        await self.client.aclose()

    # ── 正解データの整合性 ────────────────────────────────────────────────
    async def test_ground_truth_paths_are_reachable(self):
        for spec in EXPECTED_FINDINGS + SAFE_ENDPOINTS:
            # GET で 200/POSTフォームGET表示 が返ること（POST専用は GET フォーム表示）
            resp = await self.client.get(spec["path"])
            self.assertIn(
                resp.status_code, (200, 405),
                f"{spec['path']} unreachable: {resp.status_code}",
            )

    # ── OSコマンド注入 ────────────────────────────────────────────────────
    async def test_os_injection_output_based(self):
        resp = await self.client.get("/tools/ping", params={"host": "; id"})
        self.assertRegex(resp.text, r"uid=\d+", "id 出力が観測できない")

    async def test_os_injection_passwd(self):
        resp = await self.client.get("/tools/ping", params={"host": "; cat /etc/passwd"})
        self.assertIn("root:x:0:0", resp.text)

    async def test_os_injection_time_based(self):
        start = time.monotonic()
        resp = await self.client.get(
            "/tools/ping", params={"host": "; sleep 1"}, timeout=10
        )
        elapsed = time.monotonic() - start
        self.assertGreater(elapsed, 0.8, "sleep 注入で遅延が発生していない")
        self.assertEqual(resp.status_code, 200)

    async def test_os_injection_clean_host_has_no_command_output(self):
        resp = await self.client.get("/tools/ping", params={"host": "127.0.0.1"})
        self.assertNotRegex(resp.text, r"uid=\d+")
        self.assertNotIn("root:x:0:0", resp.text)

    async def test_os_safe_twin_rejects_metacharacters(self):
        # 安全ツイン：メタ文字入りは弾かれ、出力/遅延も無い
        start = time.monotonic()
        resp = await self.client.get("/tools/dns-lookup", params={"name": "; sleep 3"})
        elapsed = time.monotonic() - start
        self.assertIn("invalid hostname", resp.text)
        self.assertLess(elapsed, 0.8)
        self.assertNotRegex(resp.text, r"uid=\d+")

    # ── SSRF ──────────────────────────────────────────────────────────────
    async def test_ssrf_aws_metadata(self):
        resp = await self.client.get(
            "/integrations/webhook-test",
            params={"url": "http://169.254.169.254/latest/meta-data/"},
        )
        self.assertRegex(resp.text, r"instance-id|ami-id|local-ipv4")

    async def test_ssrf_file_scheme(self):
        resp = await self.client.get(
            "/integrations/webhook-test",
            params={"url": "file:///etc/passwd"},
        )
        self.assertRegex(resp.text, r"root:.*:/bin/")

    async def test_ssrf_baseline_has_no_internal_markers(self):
        resp = await self.client.get(
            "/integrations/webhook-test",
            params={"url": "http://wscan-baseline-test.invalid/"},
        )
        self.assertNotRegex(resp.text, r"instance-id|root:.*:/bin/|nginx")

    async def test_ssrf_safe_twin_blocks_internal(self):
        # 安全ツイン：内部宛先は拒否、内部マーカーは出ない
        for target in (
            "http://169.254.169.254/latest/meta-data/",
            "https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1/",
        ):
            resp = await self.client.get(
                "/integrations/avatar-fetch", params={"image_url": target}
            )
            self.assertIn("blocked", resp.text, f"{target} が拒否されていない")
            self.assertNotRegex(resp.text, r"instance-id|root:.*:/bin/")

    # ── NoSQL注入 ─────────────────────────────────────────────────────────
    async def test_nosql_operator_leaks_mongo_error(self):
        resp = await self.client.post(
            "/admin/login",
            data={"username": '{"$ne": ""}', "password": "x"},
        )
        self.assertRegex(resp.text, r"MongoServerError|BSON")

    async def test_nosql_normal_login_has_no_error(self):
        resp = await self.client.post(
            "/admin/login",
            data={"username": "alice", "password": "wrong"},
        )
        self.assertNotRegex(resp.text, r"MongoServerError|BSON")

    async def test_nosql_safe_twin_no_mongo_error(self):
        resp = await self.client.post(
            "/portal/signin",
            data={"username": '{"$ne": ""}', "password": '{"$ne": ""}'},
        )
        self.assertNotRegex(resp.text, r"MongoServerError|BSON")
        # 応答サイズが急増しない（boolean-based 誤検知の回避）
        normal = await self.client.post(
            "/portal/signin", data={"username": "alice", "password": "x"}
        )
        self.assertLess(abs(len(resp.text) - len(normal.text)), 200)

    # ── DOM-based XSS ─────────────────────────────────────────────────────
    async def test_dom_xss_widget_writes_param_to_innerhtml(self):
        resp = await self.client.get("/dashboard/widget", params={"tab": "overview"})
        # クライアント側の脆弱な sink 配線が存在する
        self.assertIn("innerHTML", resp.text)
        self.assertIn("location.search", resp.text)

    async def test_dom_xss_server_does_not_reflect_param(self):
        # サーバ側に反射型XSSシグナルを出さない（dom_xss 単独で正解にするため）
        marker = "<svg/onload=alert(1)>"
        resp = await self.client.get("/dashboard/widget", params={"tab": marker})
        self.assertNotIn(marker, resp.text)

    async def test_dom_safe_twin_uses_textcontent(self):
        resp = await self.client.get("/dashboard/profile", params={"bio": "hi"})
        self.assertIn("textContent", resp.text)
        # 安全ツインは innerHTML を使わない
        self.assertNotIn("innerHTML", resp.text)


if __name__ == "__main__":
    unittest.main()
