import unittest

from wscan.engine import ScanEngine


class ScopeConfigTests(unittest.TestCase):
    def _engine(self, **kwargs):
        return ScanEngine(
            "http://app.test/root",
            checks=["xss"],
            llm_provider="none",
            open_report=False,
            enable_waf_detection=False,
            enable_ai_analysis=False,
            enable_payload_learning=False,
            enable_adaptive_payloads=False,
            **kwargs,
        )

    def test_primary_origin_is_attack_scope_by_default(self):
        engine = self._engine()

        self.assertTrue(engine._is_attack_target_url("http://app.test/admin"))
        self.assertTrue(engine._is_access_allowed_url("http://app.test/admin"))
        self.assertFalse(engine._is_access_allowed_url("http://auth.test/login"))

    def test_additional_target_scope_is_attacked(self):
        engine = self._engine(target_urls=["http://admin.test"])

        self.assertTrue(engine._is_attack_target_url("http://admin.test/panel"))
        self.assertTrue(engine._is_access_allowed_url("http://admin.test/panel"))

    def test_access_only_scope_is_not_attacked(self):
        engine = self._engine(access_urls=["http://auth.test"])

        self.assertTrue(engine._is_access_allowed_url("http://auth.test/login"))
        self.assertFalse(engine._is_attack_target_url("http://auth.test/login"))


if __name__ == "__main__":
    unittest.main()
