import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from wscan.manual_crawl import (
    ManualCrawlSession,
    build_seed_payload,
    coerce_input_event,
    load_manual_crawl_seed,
    parse_url_list,
    pick_active_page,
    save_seed_payload,
    scale_point,
)


class _FakeKeyboard:
    def __init__(self):
        self.press = AsyncMock()
        self.type = AsyncMock()
        self.insert_text = AsyncMock()


class _FakePage:
    def __init__(self, url="http://example.test/"):
        self.url = url
        self.main_frame = object()
        self.mouse = Mock()
        self.keyboard = _FakeKeyboard()
        self.handlers = {}
        self.exposed = []
        self.init_scripts = []
        self.evaluated = []
        self.fill = AsyncMock()
        self.focus = AsyncMock()

    async def expose_function(self, name, callback):
        self.exposed.append((name, callback))

    async def add_init_script(self, script):
        self.init_scripts.append(script)

    async def evaluate(self, script, arg=None):
        self.evaluated.append((script, arg))
        return "#otp"

    def on(self, event, callback):
        self.handlers[event] = callback


class _FakeCdp:
    def __init__(self):
        self.handlers = {}
        self.sent = []
        self.detached = False

    def on(self, event, callback):
        self.handlers[event] = callback

    async def send(self, method, params=None):
        self.sent.append((method, params))

    async def detach(self):
        self.detached = True


class _FakeContext:
    def __init__(self, pages):
        self.pages = pages
        self.cdp_targets = []
        self.cdps = []

    async def new_cdp_session(self, page):
        self.cdp_targets.append(page)
        cdp = _FakeCdp()
        self.cdps.append(cdp)
        return cdp


class ManualCrawlSeedTests(unittest.TestCase):
    def test_load_manual_crawl_seed_normalizes_same_origin_urls(self):
        data = {
            "seed_urls": [
                "http://example.test/",
                "http://example.test/profile#top",
                "https://other.test/out",
            ],
            "events": [
                {"type": "url", "url": "http://example.test/profile"},
                {"type": "url", "url": "http://example.test/settings"},
            ],
            "cookies": [{"name": "session", "value": "abc", "domain": "example.test", "path": "/"}],
            "forms_by_url": {"http://example.test/profile": [{"inputs": [{"name": "bio"}]}]},
            "steps": [{"action": "click", "selector": "a"}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manual.json"
            path.write_text(json.dumps(data), encoding="utf-8")

            seed = load_manual_crawl_seed(str(path), "http://example.test/")

        self.assertEqual(
            seed.urls,
            [
                "http://example.test/",
                "http://example.test/profile",
                "http://example.test/settings",
            ],
        )
        self.assertEqual(seed.cookies[0]["name"], "session")
        self.assertIn("http://example.test/profile", seed.forms_by_url)
        self.assertEqual(seed.steps[0]["action"], "click")

    def test_load_manual_crawl_seed_keeps_allowed_support_scope(self):
        data = {
            "seed_urls": [
                "http://example.test/",
                "https://auth.example.test/login",
                "https://untrusted.example.test/out",
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manual.json"
            path.write_text(json.dumps(data), encoding="utf-8")

            seed = load_manual_crawl_seed(
                str(path),
                "http://example.test/",
                allowed_scopes=["https://auth.example.test"],
            )

        self.assertEqual(
            seed.urls,
            [
                "http://example.test/",
                "https://auth.example.test/login",
            ],
        )


class ManualUrlImportTests(unittest.TestCase):
    def test_parse_url_list_mixed_separators_and_dedup(self):
        text = (
            "http://example.test/a\n"
            "http://example.test/b , https://example.test/c\n"
            "not-a-url\n"
            "http://example.test/a#frag\n"  # 重複（fragment 除去後）
        )
        self.assertEqual(
            parse_url_list(text),
            [
                "http://example.test/a",
                "http://example.test/b",
                "https://example.test/c",
            ],
        )

    def test_parse_url_list_preserves_spa_hash_routes(self):
        # SPA の hash ルート（#/admin 等）は別ページなので保持。単純なページ内
        # アンカー（#section）のみ除去する。
        text = (
            "https://app.test/#/admin\n"
            "https://app.test/#!/users/1\n"
            "https://app.test/page#section\n"
        )
        self.assertEqual(
            parse_url_list(text),
            [
                "https://app.test/#/admin",
                "https://app.test/#!/users/1",
                "https://app.test/page",
            ],
        )

    def test_parse_url_list_accepts_list_input(self):
        self.assertEqual(
            parse_url_list(["http://x.test/1", "javascript:alert(1)", "https://x.test/2"]),
            ["http://x.test/1", "https://x.test/2"],
        )

    def test_seed_payload_preserves_spa_hash_routes(self):
        # _unique_urls による正規化でも SPA hash ルートを保持する（seed が / に
        # 潰れて巡回対象から落ちないこと）。
        payload = build_seed_payload(
            "https://app.test/",
            ["https://app.test/#/admin", "https://app.test/dash#section"],
        )
        self.assertEqual(
            payload["seed_urls"],
            ["https://app.test/#/admin", "https://app.test/dash"],
        )

    def test_seed_payload_keeps_allowed_cross_host_urls(self):
        # 許可ホストにまたがる URL（SSO/コールバック等）は seed から落とさない。
        payload = build_seed_payload(
            "https://app.example.com/",
            [
                "https://app.example.com/dash",
                "https://auth.example.com/callback",  # 別ホストだが許可スコープ内
                "https://evil.example.org/x",  # スコープ外は除去
            ],
            allowed_scopes=["app.example.com", "auth.example.com"],
        )
        self.assertEqual(
            payload["seed_urls"],
            [
                "https://app.example.com/dash",
                "https://auth.example.com/callback",
            ],
        )

    def test_build_seed_payload_is_loadable_as_seed(self):
        payload = build_seed_payload(
            "http://example.test/",
            [
                "http://example.test/orders?id=1",
                "http://example.test/orders?id=1",  # 重複は seed で除去
                "https://other.test/out",  # スコープ外は seed で除去
            ],
        )
        self.assertEqual(payload["source"], "manual_url_import")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "flows" / "manual.json"
            saved = save_seed_payload(str(path), payload)
            self.assertTrue(saved.exists())
            seed = load_manual_crawl_seed(str(saved), "http://example.test/")
        self.assertEqual(seed.urls, ["http://example.test/orders?id=1"])

    def test_seed_reload_keeps_cross_host_via_persisted_scopes(self):
        # 取込時の許可スコープが seed に残り、再読込（同一オリジン正規化）でも
        # クロスホストの許可 URL が落ちないこと（end-to-end の回帰防止）。
        payload = build_seed_payload(
            "https://app.example.com/",
            ["https://app.example.com/dash", "https://auth.example.com/callback"],
            allowed_scopes=["app.example.com", "auth.example.com"],
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "flows" / "manual.json"
            saved = save_seed_payload(str(path), payload)
            # engine と同様、target/access スコープのみ渡して再読込（auth は未指定）。
            seed = load_manual_crawl_seed(
                str(saved),
                "https://app.example.com/",
                allowed_scopes=["https://app.example.com/"],
            )
        self.assertIn("https://auth.example.com/callback", seed.urls)
        self.assertIn("https://app.example.com/dash", seed.urls)


class RemoteInputTests(unittest.TestCase):
    def test_click_normalized_and_button_defaulted(self):
        ev = coerce_input_event({"type": "click", "nx": 0.5, "ny": 0.25, "button": "weird"})
        self.assertEqual(ev, {"type": "click", "nx": 0.5, "ny": 0.25, "button": "left"})

    def test_coords_clamped_to_unit_range(self):
        ev = coerce_input_event({"type": "move", "nx": 1.7, "ny": -3})
        self.assertEqual(ev, {"type": "move", "nx": 1.0, "ny": 0.0})

    def test_scroll_clamped(self):
        self.assertEqual(coerce_input_event({"type": "scroll", "dy": 99999}),
                         {"type": "scroll", "dy": 2000.0})

    def test_text_length_capped(self):
        ev = coerce_input_event({"type": "text", "text": "a" * 1000})
        self.assertEqual(len(ev["text"]), 500)

    def test_key_whitelist(self):
        self.assertEqual(coerce_input_event({"type": "key", "key": "Enter"}),
                         {"type": "key", "key": "Enter"})
        # 任意のキー（例: 'F1' や 'Meta'）は拒否。
        self.assertIsNone(coerce_input_event({"type": "key", "key": "F1"}))

    def test_navigate_requires_http(self):
        self.assertIsNone(coerce_input_event({"type": "navigate", "url": "file:///etc/passwd"}))
        self.assertEqual(
            coerce_input_event({"type": "navigate", "url": "http://x.test/a"}),
            {"type": "navigate", "url": "http://x.test/a"},
        )

    def test_unknown_type_rejected(self):
        self.assertIsNone(coerce_input_event({"type": "drag"}))
        self.assertIsNone(coerce_input_event("notadict"))

    def test_scale_point_maps_to_viewport(self):
        self.assertEqual(scale_point(0.5, 0.5, 1280, 800), (640.0, 400.0))
        self.assertEqual(scale_point(2.0, -1.0, 1280, 800), (1280.0, 0.0))


class ActivePagePolicyTests(unittest.TestCase):
    def test_pick_active_page_returns_latest_remaining_page(self):
        first, middle, closed = object(), object(), object()
        self.assertIs(pick_active_page([first, middle, closed], closed), middle)
        self.assertIsNone(pick_active_page([closed], closed))


class ManualCrawlRemoteBrowserTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _session(page, context):
        session = ManualCrawlSession()
        session.running = True
        session.streaming = True
        session.start_url = "http://example.test/"
        session._page = page
        session._context = context
        session._fill_fn = "__fill__"
        session._click_fn = "__click__"
        session._recorder_script = "window.__guard = true"
        return session

    async def test_new_page_becomes_active_and_rebinds_screencast(self):
        old_page = _FakePage()
        popup = _FakePage("http://example.test/popup")
        context = _FakeContext([old_page, popup])
        session = self._session(old_page, context)
        old_cdp = _FakeCdp()
        session._cdp = old_cdp

        await session._activate_page(popup, "new_page")

        self.assertIs(session._page, popup)
        self.assertIs(context.cdp_targets[-1], popup)
        self.assertIn(("Page.stopScreencast", None), old_cdp.sent)
        self.assertTrue(old_cdp.detached)
        self.assertIn("framenavigated", popup.handlers)
        self.assertIn("requestfinished", popup.handlers)
        self.assertIn("close", popup.handlers)
        self.assertEqual(len(popup.init_scripts), 1)
        self.assertEqual(len(popup.evaluated), 1)
        self.assertIn("http://example.test/popup", session.urls)

    async def test_active_page_close_falls_back_to_latest_remaining_page(self):
        first = _FakePage("http://example.test/first")
        latest = _FakePage("http://example.test/latest")
        closed = _FakePage("http://example.test/closed")
        context = _FakeContext([first, latest])
        session = self._session(closed, context)
        session._cdp = _FakeCdp()
        session._bound_pages.extend([first, latest, closed])

        await session._handle_page_closed(closed)

        self.assertIs(session._page, latest)
        self.assertIs(context.cdp_targets[-1], latest)

    async def test_fill_totp_writes_known_code_without_returning_it(self):
        page = _FakePage("http://example.test/mfa")
        session = self._session(page, _FakeContext([page]))
        session.totp_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        session.totp_digits = 8
        session.totp_period = 30
        session.totp_algorithm = "SHA1"

        with patch("wscan.manual_crawl.time.time", return_value=59), patch(
            "wscan.manual_crawl.asyncio.sleep", new=AsyncMock()
        ):
            result = await session.fill_totp("#otp")

        page.fill.assert_awaited_once_with("#otp", "94287082")
        self.assertEqual(result, {"ok": True, "filled": True, "digits": 8})
        self.assertNotIn("94287082", json.dumps(result))
        self.assertEqual(session.steps[-1]["selector"], "#otp")
        self.assertNotIn("value", session.steps[-1])

    async def test_fill_totp_reports_missing_configuration(self):
        page = _FakePage("http://example.test/mfa")
        session = self._session(page, _FakeContext([page]))
        self.assertEqual(
            await session.fill_totp("#otp"),
            {"ok": False, "error": "TOTP が設定されていません"},
        )


if __name__ == "__main__":
    unittest.main()
