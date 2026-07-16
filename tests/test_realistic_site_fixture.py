"""
realistic_site フィクスチャの自己検証テスト（ブラウザ不要）。

httpx.ASGITransport でアプリへ直接リクエストし、「仕込んだ脆弱挙動が実際に
出る／安全ツインでは出ない」ことを高速に確認する。スキャナ本体の検出は
opt-in の E2E（tests/test_end_to_end_scan.py）が担う。

ここでの主眼は、発火トリガ層（browser.trigger_injected_handlers）が新設された
インタラクション必須 XSS（/track）が、意図どおり「アングルブラケットは除去され
つつクォートは通る＝属性ブレイクアウトのイベントハンドラが生に出る」ことと、
安全ツイン（/track/safe）では一切ブレイクアウトしないことの回帰固定。
"""
import html
import unittest

import httpx

from tests.fixtures.realistic_site import (
    EXPECTED_FINDINGS,
    SAFE_ENDPOINTS,
    create_app,
)


class RealisticSiteFixtureTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.transport = httpx.ASGITransport(app=create_app())
        self.client = httpx.AsyncClient(
            transport=self.transport,
            base_url="http://shop.test",
            follow_redirects=False,
        )

    async def asyncTearDown(self):
        await self.client.aclose()

    # ── 正解データの整合性 ────────────────────────────────────────────────
    async def test_ground_truth_paths_are_reachable(self):
        for spec in EXPECTED_FINDINGS + SAFE_ENDPOINTS:
            resp = await self.client.get(spec["path"])
            self.assertIn(
                resp.status_code, (200, 302, 405),
                f"{spec['path']} unreachable: {resp.status_code}",
            )

    # ── 反射XSS（body 直挿し・自動発火）─────────────────────────────────────
    async def test_search_reflects_script_raw(self):
        resp = await self.client.get("/search", params={"q": "<script>alert(1)</script>"})
        self.assertIn("<script>alert(1)</script>", resp.text)

    # ── インタラクション必須XSS（属性ブレイクアウト）───────────────────────
    async def test_track_strips_tags_but_keeps_quote_breakout(self):
        """アングルブラケットは除去されるが、クォートによる属性ブレイクアウトで
        onmouseover ハンドラが生のまま属性として現れる（＝発火トリガ層が撃てる）。"""
        payload = '" onmouseover=alert(1) x="'
        resp = await self.client.get("/track", params={"ref": payload})
        # 生ハンドラが属性として出る（value 閉じ→ onmouseover=alert(1) が独立属性）
        self.assertIn('value="" onmouseover=alert(1) x=""', resp.text)

    async def test_track_strips_angle_brackets(self):
        resp = await self.client.get("/track", params={"ref": "<img src=x onerror=alert(1)>"})
        # 注入由来の生タグは形成されない（< > 除去）。value 内にテキストとして残るのみ。
        body_after_h1 = resp.text.split("Order tracking</h1>")[-1]
        self.assertNotIn("<img", body_after_h1.lower())

    async def test_track_safe_escapes_quote_breakout(self):
        """安全ツイン: クォートがエスケープされ、属性ブレイクアウトが成立しない。"""
        payload = '" onmouseover=alert(1) x="'
        resp = await self.client.get("/track/safe", params={"ref": payload})
        # クォートがエスケープされ、value を閉じられない＝生ハンドラのブレイクアウトが
        # 成立しない（onmouseover は value 内のテキストとして残るだけで、独立属性化しない）。
        self.assertNotIn('value="" onmouseover=alert(1)', resp.text)
        # エスケープ済みの形（&quot;）で反射している
        self.assertIn(html.escape(payload), resp.text)


if __name__ == "__main__":
    unittest.main()
