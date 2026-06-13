"""
realistic_healthcare フィクスチャの自己検証テスト（ブラウザ不要）。

httpx.ASGITransport でアプリへ直接リクエストし、「仕込んだ脆弱挙動が実際に出る／
安全ツインでは出ない」ことを高速に確認する。スキャナ本体の検出は opt-in の E2E が
担うが、ここではフィクスチャ自体が難易度ごとに意図どおり振る舞うことを保証する。

判定にはできる限り**スキャナの純粋関数/検出パターンそのもの**を流用し、フィクスチャと
スキャナの整合をテスト側で固定する（誤検知ガードを兼ねる）。
"""
import re
import time
import unittest

import httpx

from tests.fixtures.realistic_healthcare import (
    EXPECTED_FINDINGS,
    SAFE_ENDPOINTS,
    create_app,
)
from wscan.scanners.host_header import _CANARY_HOST, _CANARY_RE
from wscan.scanners.ldap_injection import _ERROR_RE, _LDAP_PAYLOADS
from wscan.scanners.secret_leak import scan_text_for_secrets
from wscan.scanners.sri import find_unprotected_externals
from wscan.scanners.sqli import SQL_ERROR_PATTERNS, _is_time_based_sql
from wscan.scanners.jwt_scanner import _parse_jwt, _verify_hs
from wscan.scanners.xxe import _PASSWD_RE
from wscan.js_analysis import analyze_js, extract_external_script_srcs

CANARY_ORIGIN = "https://evil.wscan-test.example.com"
ALLOWLISTED_ORIGIN = "https://app.cedarvalley.test"

_SQL_ERROR_RE = re.compile("|".join(SQL_ERROR_PATTERNS), re.IGNORECASE | re.DOTALL)
_XXE_PASSWD = (
    '<?xml version="1.0"?><!DOCTYPE foo '
    '[<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
)
_XXE_BASELINE = '<?xml version="1.0"?><root>baseline</root>'


class RealisticHealthcareFixtureTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.transport = httpx.ASGITransport(app=create_app())
        self.client = httpx.AsyncClient(
            transport=self.transport,
            base_url="http://portal.cedarvalley.test",
            follow_redirects=False,
        )

    async def asyncTearDown(self):
        await self.client.aclose()

    # ── 正解データの整合性 ────────────────────────────────────────────────
    async def test_ground_truth_pairs_are_unique(self):
        expected = {(s["check"], s["path"], s["field"]) for s in EXPECTED_FINDINGS}
        safe = {(s["check"], s["path"], s["field"]) for s in SAFE_ENDPOINTS}
        self.assertEqual(len(expected), len(EXPECTED_FINDINGS))
        self.assertEqual(len(safe), len(SAFE_ENDPOINTS))
        # 仕込んだ各クラスに少なくとも 1 つの安全ツインがある（FP ガード）。
        self.assertTrue({s["check"] for s in EXPECTED_FINDINGS} <= {s["check"] for s in SAFE_ENDPOINTS})

    async def test_difficulty_spectrum_is_covered(self):
        levels = {s.get("difficulty") for s in EXPECTED_FINDINGS}
        self.assertEqual(levels, {"low", "medium", "high", "ultra"})

    async def test_all_paths_are_reachable(self):
        for spec in EXPECTED_FINDINGS + SAFE_ENDPOINTS:
            resp = await self.client.get(spec["path"])
            self.assertIn(
                resp.status_code, (200, 302, 303, 400, 404, 405),
                f"{spec['path']} unreachable: {resp.status_code}",
            )

    async def test_home_links_to_every_endpoint(self):
        resp = await self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        for spec in EXPECTED_FINDINGS + SAFE_ENDPOINTS:
            with self.subTest(path=spec["path"]):
                # パラメータ系はクロール用に ?field=... 付きでリンクされる。
                self.assertTrue(
                    f'href="{spec["path"]}"' in resp.text
                    or f'href="{spec["path"]}?' in resp.text,
                    f'{spec["path"]} not linked from home',
                )

    async def test_parameterized_get_endpoints_link_their_field(self):
        # GET パラメータ系の脆弱エンドポイントは、クローラがパラメータ名を拾えるよう
        # クエリ文字列付きでリンクされていること（E2E の false negative 回避）。
        resp = await self.client.get("/")
        for spec in EXPECTED_FINDINGS:
            field = spec.get("field")
            if field and field.replace("_", "").isalnum() and not field.startswith("form"):
                with self.subTest(path=spec["path"], field=field):
                    self.assertIn(f'href="{spec["path"]}?{field}=', resp.text)

    # ── LOW ────────────────────────────────────────────────────────────────
    async def test_low_reflected_xss(self):
        marker = "<svg/onload=alert(1)>"
        vuln = await self.client.get("/portal/search", params={"q": marker})
        safe = await self.client.get("/portal/help", params={"q": marker})
        self.assertIn(marker, vuln.text)
        self.assertNotIn(marker, safe.text)
        self.assertIn("&lt;svg", safe.text)

    async def test_low_error_based_sqli(self):
        vuln = await self.client.get("/billing/invoice", params={"ref": "INV'"})
        base = await self.client.get("/billing/invoice", params={"ref": "INV-1001"})
        safe = await self.client.get("/billing/history", params={"sort": "amount'--"})
        self.assertRegex(vuln.text, _SQL_ERROR_RE)
        self.assertNotRegex(base.text, _SQL_ERROR_RE)
        self.assertNotRegex(safe.text, _SQL_ERROR_RE)

    async def test_low_open_redirect(self):
        vuln = await self.client.get("/auth/logout", params={"next": "https://evil.example.com"})
        safe = await self.client.get("/auth/exit", params={"to": "https://evil.example.com"})
        self.assertEqual(vuln.status_code, 302)
        self.assertEqual(vuln.headers["location"], "https://evil.example.com")
        self.assertEqual(safe.headers["location"], "/")

    async def test_low_security_headers(self):
        vuln = await self.client.get("/legacy/status")
        safe = await self.client.get("/legacy/status-secure")
        self.assertNotIn("content-security-policy", vuln.headers)
        self.assertNotIn("strict-transport-security", vuln.headers)
        self.assertIn("content-security-policy", safe.headers)
        self.assertIn("strict-transport-security", safe.headers)

    async def test_low_info_disclosure(self):
        vuln = await self.client.get("/.env")
        safe = await self.client.get("/config/env-public")
        self.assertIn("DB_PASSWORD=fixture-prod-password", vuln.text)
        self.assertIn("SECRET_KEY=fixture-secret-key", vuln.text)
        self.assertEqual(safe.status_code, 404)
        self.assertNotIn("DB_PASSWORD", safe.text)

    async def test_low_clickjacking(self):
        vuln = await self.client.get("/portal/embed")
        safe = await self.client.get("/portal/embed-safe")
        # framing 保護だけが欠ける（他ヘッダは揃え security_headers は発火させない）。
        self.assertNotIn("x-frame-options", vuln.headers)
        self.assertIn("content-security-policy", vuln.headers)
        self.assertNotIn("frame-ancestors", vuln.headers["content-security-policy"].lower())
        self.assertIn("strict-transport-security", vuln.headers)  # 他ヘッダは完備
        self.assertEqual(safe.headers["x-frame-options"], "DENY")
        self.assertIn("frame-ancestors 'none'", safe.headers["content-security-policy"])

    # ── MEDIUM ───────────────────────────────────────────────────────────────
    async def test_medium_ldap_injection(self):
        base = await self.client.get("/directory/lookup", params={"user": "jsmith"})
        vuln = await self.client.get("/directory/lookup", params={"user": _LDAP_PAYLOADS[0]})
        safe = await self.client.get("/directory/search", params={"name": _LDAP_PAYLOADS[0]})
        self.assertTrue(_ERROR_RE.search(vuln.text), "LDAP error not leaked")
        self.assertIsNone(_ERROR_RE.search(base.text))
        self.assertIsNone(_ERROR_RE.search(safe.text))

    async def test_medium_xxe_file_read(self):
        headers = {"Content-Type": "application/xml"}
        vuln = await self.client.post("/records/import", content=_XXE_PASSWD, headers=headers)
        base = await self.client.post("/records/import", content=_XXE_BASELINE, headers=headers)
        safe = await self.client.post("/records/import-safe", content=_XXE_PASSWD, headers=headers)
        self.assertTrue(_PASSWD_RE.search(vuln.text), "/etc/passwd not reflected")
        self.assertIsNone(_PASSWD_RE.search(base.text))
        self.assertIsNone(_PASSWD_RE.search(safe.text))

    async def test_medium_host_header_injection(self):
        vuln = await self.client.get("/account/reset", headers={"Host": _CANARY_HOST})
        safe = await self.client.get("/account/reset-safe", headers={"Host": _CANARY_HOST})
        self.assertTrue(_CANARY_RE.search(vuln.text), "canary host not reflected")
        self.assertIsNone(_CANARY_RE.search(safe.text))

    async def test_medium_sri_missing(self):
        vuln = await self.client.get("/portal/insights")
        safe = await self.client.get("/portal/insights-safe")
        vuln_hits = find_unprotected_externals(vuln.text, "http://portal.cedarvalley.test/portal/insights")
        safe_hits = find_unprotected_externals(safe.text, "http://portal.cedarvalley.test/portal/insights-safe")
        self.assertTrue(any(h["host"] == "cdn.jsdelivr.net" for h in vuln_hits))
        self.assertEqual(safe_hits, [])

    async def test_medium_js_static_source_to_sink(self):
        page = await self.client.get("/portal/notice")
        self.assertIn("/static/portal.js", extract_external_script_srcs(page.text))
        vuln_js = (await self.client.get("/static/portal.js")).text
        safe_js = (await self.client.get("/static/portal.safe.js")).text
        vuln_risks = analyze_js(vuln_js)
        safe_risks = analyze_js(safe_js)
        self.assertTrue(any(r.sink == "innerHTML" and r.tainted for r in vuln_risks))
        self.assertEqual([r for r in safe_risks if r.tainted], [])

    async def test_medium_ssti(self):
        probe = "{{2654435761*2654435761}}"
        vuln = await self.client.get("/messages/preview", params={"name": probe})
        safe = await self.client.get("/messages/draft", params={"name": probe})
        self.assertIn("7045744422742119121", vuln.text)
        self.assertNotIn("7045744422742119121", safe.text)

    async def test_medium_path_traversal(self):
        vuln = await self.client.get("/documents/view", params={"doc": "../../../../etc/passwd"})
        safe = await self.client.get("/documents/manual", params={"name": "../../../../etc/passwd"})
        self.assertIn("root:x:0:0", vuln.text)
        self.assertNotIn("root:x:0:0", safe.text)

    async def test_medium_cors(self):
        vuln = await self.client.get("/api/v1/records/export", headers={"Origin": CANARY_ORIGIN})
        safe_canary = await self.client.get("/api/v1/records/export-safe", headers={"Origin": CANARY_ORIGIN})
        safe_allow = await self.client.get("/api/v1/records/export-safe", headers={"Origin": ALLOWLISTED_ORIGIN})
        self.assertEqual(vuln.headers["access-control-allow-origin"], CANARY_ORIGIN)
        self.assertEqual(vuln.headers["access-control-allow-credentials"], "true")
        self.assertNotIn("access-control-allow-origin", safe_canary.headers)
        self.assertEqual(safe_allow.headers["access-control-allow-origin"], ALLOWLISTED_ORIGIN)

    async def test_medium_csrf(self):
        vuln = await self.client.get("/account/email-change")
        safe = await self.client.get("/account/email-change-safe")
        self.assertIn('method="post"', vuln.text.lower())
        self.assertNotIn("csrf", vuln.text.lower())
        self.assertIn('name="csrf_token"', safe.text)

    async def test_medium_session_cookie_flags(self):
        weak = (await self.client.get("/api/v1/auth/session")).headers["set-cookie"]
        strong = (await self.client.get("/api/v1/auth/session-safe")).headers["set-cookie"]
        self.assertNotIn("Secure", weak)
        self.assertNotIn("HttpOnly", weak)
        self.assertIn("Secure", strong)
        self.assertIn("HttpOnly", strong)
        self.assertIn("SameSite=Lax", strong)

    async def test_medium_secret_leak(self):
        vuln = (await self.client.get("/static/vendor.js")).text
        safe = (await self.client.get("/static/vendor.safe.js")).text
        labels = {hit["label"] for hit in scan_text_for_secrets(vuln)}
        self.assertIn("AWS Access Key ID", labels)
        self.assertIn("Stripe Secret Key", labels)
        self.assertEqual(scan_text_for_secrets(safe), [])

    async def test_medium_jwt_weak_secret(self):
        weak = (await self.client.get("/api/v1/auth/token")).json()["access_token"]
        strong = (await self.client.get("/api/v1/auth/token-safe")).json()["access_token"]
        self.assertIsNotNone(_parse_jwt(weak))
        self.assertTrue(_verify_hs(weak, "secret"))
        self.assertFalse(_verify_hs(strong, "secret"))

    async def test_medium_nosql_injection(self):
        vuln = await self.client.post("/api/v1/auth/login", data={"username": '{"$ne": ""}', "password": "x"})
        safe = await self.client.post("/portal/signin", data={"username": '{"$ne": ""}', "password": '{"$ne": ""}'})
        self.assertRegex(vuln.text, r"MongoServerError|BSON")
        self.assertNotRegex(safe.text, r"MongoServerError|BSON")

    async def test_medium_header_injection(self):
        payload = "ja-JP%0d%0aX-WscanHdrInject:%201"
        vuln = await self.client.get(f"/portal/locale?lang={payload}")
        safe = await self.client.get(f"/portal/locale-safe?lang={payload}")
        self.assertIn("x-wscanhdrinject", vuln.headers)
        self.assertNotIn("x-wscanhdrinject", safe.headers)

    async def test_medium_dom_xss(self):
        page = await self.client.get("/portal/dashboard", params={"tab": "overview"})
        safe = await self.client.get("/portal/dashboard-safe", params={"tab": "overview"})
        self.assertIn("innerHTML", page.text)
        self.assertIn("location.search", page.text)
        self.assertNotIn("innerHTML", safe.text)
        self.assertIn("textContent", safe.text)
        # サーバは反射型 XSS シグナルを出さない。
        marker = "<svg/onload=alert(1)>"
        reflected = await self.client.get("/portal/dashboard", params={"tab": marker})
        self.assertNotIn(marker, reflected.text)

    # ── HIGH ─────────────────────────────────────────────────────────────────
    async def test_high_boolean_blind_sqli(self):
        baseline = await self.client.get("/pharmacy/refill", params={"rx": "baseline_test"})
        true_resp = await self.client.get("/pharmacy/refill", params={"rx": "1 AND 1=1"})
        false_resp = await self.client.get("/pharmacy/refill", params={"rx": "1 AND 1=2"})
        # 真条件はベースラインに酷似、偽条件は大きく短くなる。
        self.assertGreater(len(true_resp.text) - len(false_resp.text), 200)
        self.assertLess(abs(len(true_resp.text) - len(baseline.text)), 50)
        # エラー文言は出さない（boolean blind 単独シグナル）。
        self.assertNotRegex(false_resp.text, _SQL_ERROR_RE)

    async def test_high_boolean_blind_safe_twin(self):
        true_resp = await self.client.get("/pharmacy/catalog", params={"drug": "1 AND 1=1"})
        false_resp = await self.client.get("/pharmacy/catalog", params={"drug": "1 AND 1=2"})
        self.assertLess(abs(len(true_resp.text) - len(false_resp.text)), 50)

    async def test_high_time_based_sqli(self):
        self.assertTrue(_is_time_based_sql("1' AND SLEEP(3)--"))
        start = time.monotonic()
        resp = await self.client.get("/pharmacy/interactions", params={"drug": "1' AND SLEEP(3)--"}, timeout=10)
        elapsed = time.monotonic() - start
        self.assertGreater(elapsed, 2.5)
        self.assertEqual(resp.status_code, 200)
        # 通常入力は遅延しない。
        start = time.monotonic()
        await self.client.get("/pharmacy/interactions", params={"drug": "apixaban"})
        self.assertLess(time.monotonic() - start, 1.0)

    async def test_high_stored_xss(self):
        marker = "<img src=x onerror=alert(7)>"
        await self.client.post("/community/posts", data={"comment": marker})
        listing = await self.client.get("/community/posts")
        self.assertIn(marker, listing.text)
        # 安全ツインはエスケープして格納・描画。
        await self.client.post("/community/announcements", data={"comment": marker})
        safe_listing = await self.client.get("/community/announcements")
        self.assertNotIn(marker, safe_listing.text)
        self.assertIn("&lt;img", safe_listing.text)

    async def test_high_blind_os_injection(self):
        start = time.monotonic()
        resp = await self.client.get("/tools/nslookup", params={"host": "127.0.0.1; sleep 1"}, timeout=10)
        elapsed = time.monotonic() - start
        self.assertGreater(elapsed, 0.8)
        # blind: コマンド出力は返さない。
        out = await self.client.get("/tools/nslookup", params={"host": "127.0.0.1; id"})
        self.assertNotRegex(out.text, r"uid=\d+")
        # 安全ツインはメタ文字を弾き、遅延しない。
        start = time.monotonic()
        safe = await self.client.get("/tools/resolve", params={"name": "127.0.0.1; sleep 3"})
        self.assertLess(time.monotonic() - start, 0.8)
        self.assertIn("invalid hostname", safe.text)

    async def test_high_ssrf(self):
        vuln = await self.client.get("/integrations/fetch", params={"url": "http://169.254.169.254/latest/meta-data/"})
        safe = await self.client.get("/integrations/avatar", params={"image_url": "http://169.254.169.254/latest/meta-data/"})
        self.assertRegex(vuln.text, r"instance-id|ami-id|local-ipv4")
        self.assertIn("blocked", safe.text)

    # ── ULTRA ──────────────────────────────────────────────────────────────
    async def test_ultra_xss_waf_bypass(self):
        # 素朴な <script> 除去はイベントハンドラを止められない。
        bypass = "<svg/onload=alert(1)>"
        blocked = "<script>alert(1)</script>"
        vuln = await self.client.get("/reviews/new", params={"text": bypass})
        naive = await self.client.get("/reviews/new", params={"text": blocked})
        safe = await self.client.get("/reviews/preview", params={"text": bypass})
        self.assertIn(bypass, vuln.text)             # バイパスは素通り
        self.assertNotIn("<script>alert(1)", naive.text)  # <script> は除去される
        self.assertNotIn(bypass, safe.text)          # 安全ツインは全エスケープ

    async def test_ultra_double_decode_sqli(self):
        # 生のシングルクォートは WAF が遮断する。
        blocked = await self.client.get("/trials/search", params={"ref": "'"})
        self.assertIn("blocked by WAF", blocked.text)
        self.assertNotRegex(blocked.text, _SQL_ERROR_RE)
        # 二重エンコードした %2527 は WAF を素通りし、アプリの再デコードで ' に戻る。
        vuln = await self.client.get("/trials/search?ref=%2527")
        self.assertRegex(vuln.text, _SQL_ERROR_RE)
        # 安全ツインはプレースホルダなのでエラーは出ない。
        safe = await self.client.get("/trials/browse", params={"ref": "'"})
        self.assertNotRegex(safe.text, _SQL_ERROR_RE)

    async def test_ultra_double_encode_path_traversal(self):
        # 素朴な防御（'..' 禁止 + .pdf 限定）は単純な traversal を弾く。
        naive = await self.client.get("/vault/file", params={"name": "../../../../etc/passwd"})
        self.assertEqual(naive.status_code, 400)
        # 二重エンコード + NULL バイトで両ゲートをすり抜ける。
        vuln = await self.client.get("/vault/file?name=%252e%252e%252fetc%252fpasswd%2500.pdf")
        self.assertIn("root:x:0:0", vuln.text)
        # 安全ツインは allow-list なので到達不能。
        safe = await self.client.get("/vault/manual", params={"name": "../../../../etc/passwd"})
        self.assertNotIn("root:x:0:0", safe.text)

    async def test_ultra_backslash_open_redirect(self):
        # // と http(s):// は弾かれる。
        blocked = await self.client.get("/sso/return", params={"dest": "//evil.example.com"})
        self.assertEqual(blocked.headers["location"], "/portal/search")
        # '/\' はフィルタを素通りし、攻撃者ドメインを指す Location が返る
        # （ブラウザは '/\' を '//' に正規化して外部遷移になる）。
        vuln = await self.client.get("/sso/return", params={"dest": "/\\evil.example.com"})
        location = vuln.headers["location"]
        self.assertNotEqual(location, "/portal/search")
        self.assertIn("evil.example.com", location)
        # 安全ツインは '/\' も弾く。
        safe = await self.client.get("/sso/continue", params={"dest": "/\\evil.example.com"})
        self.assertEqual(safe.headers["location"], "/portal/search")

    async def test_ultra_alternate_syntax_ssti(self):
        # {{ }} はブロックされる。
        blocked = await self.client.get("/reports/render", params={"title": "{{2654435761*2654435761}}"})
        self.assertIn("Blocked template syntax", blocked.text)
        self.assertNotIn("7045744422742119121", blocked.text)
        # 代替構文 ${ } は評価される。
        vuln = await self.client.get("/reports/render", params={"title": "${2654435761*2654435761}"})
        self.assertIn("7045744422742119121", vuln.text)
        # 安全ツインは描画しない。
        safe = await self.client.get("/reports/title-safe", params={"title": "${2654435761*2654435761}"})
        self.assertNotIn("7045744422742119121", safe.text)


if __name__ == "__main__":
    unittest.main()
