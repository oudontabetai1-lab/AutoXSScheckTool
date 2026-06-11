import json
import tempfile
import unittest
from pathlib import Path

from wscan.manual_crawl import (
    build_seed_payload,
    coerce_input_event,
    load_manual_crawl_seed,
    parse_url_list,
    save_seed_payload,
    scale_point,
)


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


if __name__ == "__main__":
    unittest.main()
