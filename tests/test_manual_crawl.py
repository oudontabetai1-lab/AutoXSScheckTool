import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from wscan.manual_crawl import (
    ManualCrawlSession,
    _cookie_host_matches,
    _same_origin,
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
    def __init__(self, url="http://example.test/", forms=None):
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
        self._forms = forms or []

    async def eval_on_selector_all(self, selector, script):
        return self._forms

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
    def test_load_honors_persisted_effective_origin_after_redirect(self):
        # target が http だが保存は https（起動時リダイレクト後・同一ホスト）のとき、
        # 厳密 origin 判定で scheme 差により seed を落とさない（保存 origin を優先・Codex #153）。
        data = {
            "start_url": "https://example.test/",
            "seed_urls": ["https://example.test/", "https://example.test/app"],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manual.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            seed = load_manual_crawl_seed(str(path), "http://example.test/")
        self.assertIn("https://example.test/app", seed.urls)

    def test_load_does_not_promote_cross_host_saved_origin(self):
        # 保存 start_url が別ホストでも、caller の same_origin_as（別ホスト）へは昇格しない。
        data = {
            "start_url": "https://sso.evil.test/",
            "seed_urls": ["https://sso.evil.test/cb", "http://example.test/ok"],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manual.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            seed = load_manual_crawl_seed(str(path), "http://example.test/")
        self.assertIn("http://example.test/ok", seed.urls)
        self.assertNotIn("https://sso.evil.test/cb", seed.urls)

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

    async def test_fill_totp_omits_cross_origin_url_from_steps(self):
        # cross-origin SSO ページで TOTP を入力しても、page.url（OAuth の state/code/token 含む）を
        # steps に残さない（save() がスコープ無しで永続化するため・Codex #153 P2）。
        page = _FakePage("https://sso.evil.test/authorize?code=SECRET&state=xyz")
        session = self._session(page, _FakeContext([page]))
        session.totp_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        session.totp_digits = 8

        with patch("wscan.manual_crawl.time.time", return_value=59), patch(
            "wscan.manual_crawl.asyncio.sleep", new=AsyncMock()
        ):
            result = await session.fill_totp("#otp")

        self.assertTrue(result["ok"])  # 入力自体は成功
        # cross-origin の TOTP 入力 step は丸ごと省略（selector 含め残さない）。
        self.assertEqual(session.steps, [])
        self.assertFalse(any("evil.test" in json.dumps(s) for s in session.steps))

    async def test_fill_totp_reports_missing_configuration(self):
        page = _FakePage("http://example.test/mfa")
        session = self._session(page, _FakeContext([page]))
        self.assertEqual(
            await session.fill_totp("#otp"),
            {"ok": False, "error": "TOTP が設定されていません"},
        )

    async def test_activated_popup_is_snapshotted_for_forms(self):
        # popup の初期 document が commit 済みでも、有効化直後の snapshot で forms を取得する
        # （URL のみ記録では input surface を取り逃す・Codex #153 P1）。
        forms = [{"index": 0, "action": "http://example.test/popup", "method": "post",
                  "inputs": [{"name": "q", "type": "text"}]}]
        old_page = _FakePage()
        popup = _FakePage("http://example.test/popup", forms=forms)
        session = self._session(old_page, _FakeContext([old_page, popup]))
        session._cdp = _FakeCdp()

        await session._activate_page(popup, "new_page")

        self.assertIn("http://example.test/popup", session.forms_by_url)
        self.assertEqual(session.forms_by_url["http://example.test/popup"], forms)

    async def test_record_fill_drops_cross_origin_step_entirely(self):
        # cross-origin の fill step は URL だけでなく selector/name/type も含め丸ごと省略する
        # （IdP のアカウント選択等が steps に残らない・Codex #153）。
        page = _FakePage("http://example.test/login")
        session = self._session(page, _FakeContext([page]))
        session._record_fill({"selector": "#u", "name": "user@corp.example", "type": "text",
                              "url": "https://sso.evil.test/authorize?code=SECRET"})
        self.assertEqual(session.steps, [])  # step 自体が記録されない
        # same-origin はそのまま残す。
        session._record_fill({"selector": "#p", "name": "pw", "type": "password",
                              "url": "http://example.test/login?next=/home"})
        self.assertEqual(session.steps[-1]["url"], "http://example.test/login?next=/home")

    async def test_record_click_drops_cross_origin_step_entirely(self):
        page = _FakePage("http://example.test/")
        session = self._session(page, _FakeContext([page]))
        session._record_click({"selector": "button.account", "text": "user@corp.example",
                               "href": "https://sso.evil.test/authorize?state=xyz",
                               "url": "https://sso.evil.test/authorize?state=xyz"})
        self.assertEqual(session.steps, [])  # selector/text も含め丸ごと残さない
        self.assertFalse(any("evil.test" in json.dumps(s) for s in session.steps))
        self.assertFalse(any("corp.example" in json.dumps(s) for s in session.steps))
        self.assertNotIn("https://sso.evil.test/authorize?state=xyz", session.urls)

    async def test_background_tab_navigation_is_snapshotted(self):
        # 背景タブ（非アクティブ）の same-origin ナビゲーションでも form を snapshot する
        # （active のみだと背景タブの新フォームが forms_by_url に残らない・Codex #153 P2）。
        active = _FakePage("http://example.test/active")
        background = _FakePage("http://example.test/bg")
        session = self._session(active, _FakeContext([active, background]))
        scheduled = []
        session._schedule_snapshot = lambda reason, page=None: scheduled.append(page)
        await session._bind_page(background)   # 背景タブをバインド（active は別ページ）
        on_nav = background.handlers["framenavigated"]
        background.url = "http://example.test/bg/form"
        on_nav(background.main_frame)
        self.assertIn(background, scheduled)   # active でなくても snapshot がスケジュールされる
        self.assertIn("http://example.test/bg/form", session.urls)

    async def test_background_tab_cross_origin_not_snapshotted(self):
        # 背景タブでも cross-origin なら URL も snapshot も残さない。
        active = _FakePage("http://example.test/active")
        evil = _FakePage("https://sso.evil.test/cb?token=x")
        session = self._session(active, _FakeContext([active, evil]))
        scheduled = []
        session._schedule_snapshot = lambda reason, page=None: scheduled.append(page)
        await session._bind_page(evil)
        evil.handlers["framenavigated"](evil.main_frame)
        self.assertEqual(scheduled, [])
        self.assertFalse(any("evil.test" in u for u in session.urls))

    async def test_stop_filters_cookies_by_target_host_not_path(self):
        # 保存 cookie は target ホスト一致で絞る（path に依らず保持・別ホスト IdP は除外・Codex #153）。
        session = self._session(_FakePage("http://example.test/login"), None)
        session.running = True
        session.start_url = "http://example.test/login"

        class _Ctx:
            async def cookies(self, urls=None):
                # 認証で /app にスコープされた cookie と、別ホスト IdP の cookie が混在。
                return [
                    {"name": "app_session", "value": "1", "domain": "example.test", "path": "/app"},
                    {"name": "idp", "value": "x", "domain": "sso.evil.test", "path": "/"},
                ]
        session._context = _Ctx()

        async def _noop(*a, **k):
            return None
        session.snapshot = _noop
        session._cleanup_browser = _noop
        session.save = lambda: None

        await session.stop()
        names = {c["name"] for c in session.cookies}
        self.assertIn("app_session", names)   # path=/app でも同一ホストなら保持
        self.assertNotIn("idp", names)         # 別ホストは除外

    async def test_stop_flushes_bound_background_tab_forms(self):
        # 背景タブの遅延 snapshot が未発火でも、stop() が cleanup 前に bound page を
        # flush して forms を取りこぼさない（cleanup がタスクを cancel する前・Codex #153 P2）。
        active = _FakePage("http://example.test/active")
        bg_forms = [{"index": 0, "action": "http://example.test/bg", "method": "post",
                     "inputs": [{"name": "q", "type": "text"}]}]
        background = _FakePage("http://example.test/bg", forms=bg_forms)
        session = self._session(active, _FakeContext([active, background]))
        session._bound_pages = [active, background]

        async def _noop(*a, **k):
            return None
        session._cleanup_browser = _noop
        session.save = lambda: None

        await session.stop()
        # 背景タブの forms が flush で保存される。
        self.assertIn("http://example.test/bg", session.forms_by_url)
        self.assertEqual(session.forms_by_url["http://example.test/bg"], bg_forms)

    async def test_stop_flush_skips_cross_origin_bound_page(self):
        # flush でも cross-origin の bound page の forms は残さない（snapshot が same-origin 再確認）。
        active = _FakePage("http://example.test/active")
        evil = _FakePage("https://sso.evil.test/cb",
                         forms=[{"index": 0, "inputs": [{"name": "pw"}]}])
        session = self._session(active, _FakeContext([active, evil]))
        session._bound_pages = [active, evil]

        async def _noop(*a, **k):
            return None
        session._cleanup_browser = _noop
        session.save = lambda: None

        await session.stop()
        self.assertNotIn("https://sso.evil.test/cb", session.forms_by_url)

    async def test_start_screencast_failure_does_not_leak_cdp(self):
        # startScreencast 失敗時に死んだ CDP を self._cdp に残さず detach する（Codex #153 P2）。
        class _FailCdp(_FakeCdp):
            async def send(self, method, params=None):
                self.sent.append((method, params))
                if method == "Page.startScreencast":
                    raise RuntimeError("screencast start failed")

        class _FailContext(_FakeContext):
            async def new_cdp_session(self, page):
                self.cdp_targets.append(page)
                cdp = _FailCdp()
                self.cdps.append(cdp)
                return cdp

        page = _FakePage("http://example.test/")
        session = self._session(page, _FailContext([page]))
        session._cdp = None
        with self.assertRaises(RuntimeError):
            await session._start_screencast(page)
        self.assertIsNone(session._cdp)  # 死んだ CDP を残さない
        self.assertTrue(session._context.cdps[-1].detached)  # detach 済み

    async def test_cross_origin_popup_url_not_recorded(self):
        # 追従した cross-origin popup（SSO/決済等）の URL・forms は artifact に残さない
        # （same-origin のみ記録・Codex #153 P2）。screencast 追従（切替）自体は行う。
        old_page = _FakePage()
        evil = _FakePage("https://sso.evil.test/authorize?token=secret123",
                         forms=[{"index": 0, "inputs": [{"name": "pw"}]}])
        context = _FakeContext([old_page, evil])
        session = self._session(old_page, context)
        session._cdp = _FakeCdp()

        await session._activate_page(evil, "new_page")

        # 追従（アクティブ切替）は行う。
        self.assertIs(session._page, evil)
        self.assertIs(context.cdp_targets[-1], evil)
        # だが cross-origin の URL / forms / events は記録しない。
        self.assertNotIn("https://sso.evil.test/authorize?token=secret123", session.urls)
        self.assertNotIn("https://sso.evil.test/authorize?token=secret123", session.forms_by_url)
        self.assertFalse(any("evil.test" in json.dumps(e) for e in session.events))


class SameOriginTests(unittest.TestCase):
    def test_scheme_must_match(self):
        # http↔https を同一視しない（cross-origin popup を same-origin と誤判定しない・Codex #153）。
        self.assertFalse(_same_origin("http://app.test/x", "https://app.test/y"))

    def test_default_port_normalized(self):
        # 明示既定ポートと省略を同一 origin 扱いにする（記録取りこぼし防止）。
        self.assertTrue(_same_origin("https://app.test/x", "https://app.test:443/y"))
        self.assertTrue(_same_origin("http://app.test:80/x", "http://app.test/y"))

    def test_same_origin_true(self):
        self.assertTrue(_same_origin("https://app.test/a?b=1", "https://app.test/c"))

    def test_different_host(self):
        self.assertFalse(_same_origin("https://app.test/x", "https://evil.test/x"))

    def test_different_explicit_port(self):
        self.assertFalse(_same_origin("https://app.test:8443/x", "https://app.test/y"))

    def test_garbage_is_false(self):
        self.assertFalse(_same_origin("", "https://app.test"))
        self.assertFalse(_same_origin("not a url", "https://app.test"))


class CookieHostMatchTests(unittest.TestCase):
    def test_exact_and_subdomain(self):
        self.assertTrue(_cookie_host_matches("example.test", "example.test"))
        self.assertTrue(_cookie_host_matches(".example.test", "app.example.test"))

    def test_different_host(self):
        self.assertFalse(_cookie_host_matches("sso.evil.test", "example.test"))
        self.assertFalse(_cookie_host_matches("", "example.test"))


if __name__ == "__main__":
    unittest.main()
