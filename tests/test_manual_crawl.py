import json
import tempfile
import unittest
from pathlib import Path

from wscan.manual_crawl import load_manual_crawl_seed


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


if __name__ == "__main__":
    unittest.main()
