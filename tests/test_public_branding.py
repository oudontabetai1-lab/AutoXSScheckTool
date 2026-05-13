import unittest
from pathlib import Path


class PublicBrandingTests(unittest.TestCase):
    def test_public_ui_and_docs_do_not_name_reference_products(self):
        public_files = [
            Path("templates/dashboard.html"),
            Path("docs/advanced_features.md"),
        ]
        forbidden = tuple(
            "".join(chr(c) for c in codes)
            for codes in (
                (65, 101, 121, 101, 83, 99, 97, 110),
                (86, 69, 88),
                (86, 101, 120),
                (97, 101, 121, 101, 115, 99, 97, 110),
                (118, 101, 120),
            )
        )

        for path in public_files:
            text = path.read_text(encoding="utf-8")
            for name in forbidden:
                with self.subTest(path=str(path), name=name):
                    self.assertNotIn(name, text)

    def test_dashboard_exposes_role_model_controls(self):
        text = Path("templates/dashboard.html").read_text(encoding="utf-8")
        expected = (
            "cfgRoleModelsGrid",
            "cfgPlannerModel",
            "cfgPayloadModel",
            "cfgAdaptiveModel",
            "cfgTriageModel",
            "cfgReportModel",
            "collectRoleModels()",
            "restoreRoleModels",
            "role_models",
        )

        for marker in expected:
            with self.subTest(marker=marker):
                self.assertIn(marker, text)

    def test_dashboard_exposes_manual_crawl_controls(self):
        text = Path("templates/dashboard.html").read_text(encoding="utf-8")
        expected = (
            "cfgTab-manualcrawl",
            "cfgManualCrawlFile",
            "manualCrawlOutput",
            "startManualCrawl()",
            "stopManualCrawl()",
            "/api/v1/manual-crawl/start",
            "/api/v1/manual-crawl/stop",
            "manual_crawl_file",
        )

        for marker in expected:
            with self.subTest(marker=marker):
                self.assertIn(marker, text)

    def test_dashboard_exposes_scope_controls(self):
        text = Path("templates/dashboard.html").read_text(encoding="utf-8")
        expected = (
            "cfgTargetUrls",
            "cfgAccessUrls",
            "target_urls",
            "access_urls",
            "検査対象URLスコープ",
            "アクセスのみ許可URLスコープ",
        )

        for marker in expected:
            with self.subTest(marker=marker):
                self.assertIn(marker, text)

    def test_dashboard_loads_config_defaults(self):
        text = Path("templates/dashboard.html").read_text(encoding="utf-8")
        expected = (
            "/api/config/defaults",
            "loadDefaultConfigFromServer",
            "cfgProxy",
            "bootDashboard()",
        )

        for marker in expected:
            with self.subTest(marker=marker):
                self.assertIn(marker, text)

    def test_dashboard_exposes_post_scan_crawl_actions(self):
        text = Path("templates/dashboard.html").read_text(encoding="utf-8")
        expected = (
            "postScanActions",
            "rerunLastScan()",
            "openManualCrawlAfterScan()",
            "lastScanConfig",
            "再巡回",
            "手動巡回を追加",
        )

        for marker in expected:
            with self.subTest(marker=marker):
                self.assertIn(marker, text)


if __name__ == "__main__":
    unittest.main()
