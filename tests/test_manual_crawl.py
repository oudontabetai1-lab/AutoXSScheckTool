import json
import tempfile
import unittest
from pathlib import Path

from wscan.manual_crawl import (
    build_seed_payload,
    load_manual_crawl_seed,
    parse_url_list,
    save_seed_payload,
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

    def test_parse_url_list_accepts_list_input(self):
        self.assertEqual(
            parse_url_list(["http://x.test/1", "javascript:alert(1)", "https://x.test/2"]),
            ["http://x.test/1", "https://x.test/2"],
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


if __name__ == "__main__":
    unittest.main()
