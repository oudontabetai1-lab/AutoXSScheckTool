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

    def test_same_origin_login_page_is_attacked(self):
        engine = self._engine(login_url="http://app.test/login")

        # The configured login page on the target origin must remain an attack
        # target so its form (username/password reflection, auth bypass) is tested.
        self.assertTrue(engine._is_attack_target_url("http://app.test/login"))

    def test_is_login_target_url_matches_only_login_page(self):
        engine = self._engine(login_url="http://app.test/login")

        # Deliberate visits to the login page must be recognised so they are not
        # mistaken for a session-expiry redirect.
        self.assertTrue(engine._is_login_target_url("http://app.test/login"))
        self.assertTrue(engine._is_login_target_url("http://app.test/login/"))
        self.assertTrue(engine._is_login_target_url("http://app.test/login?next=/x"))
        self.assertFalse(engine._is_login_target_url("http://app.test/dashboard"))
        self.assertFalse(engine._is_login_target_url(""))

    def test_is_login_target_url_requires_matching_host(self):
        # login_url points at an external IdP; the target app shares the /login
        # path. A redirect to the app's own /login must NOT be treated as a
        # deliberate login-page visit, otherwise re-auth would be wrongly skipped.
        engine = self._engine(login_url="http://auth.test/login")

        self.assertTrue(engine._is_login_target_url("http://auth.test/login"))
        self.assertFalse(engine._is_login_target_url("http://app.test/login"))

    def test_is_login_target_url_false_without_login_url(self):
        engine = self._engine()

        self.assertFalse(engine._is_login_target_url("http://app.test/login"))


if __name__ == "__main__":
    unittest.main()
