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

    def test_is_login_target_url_respects_query_route(self):
        # Some apps encode the route in the query string (e.g. OpenCart).
        # The login query must match — a protected route sharing the same path
        # must NOT be treated as the login page, otherwise re-auth is skipped.
        engine = self._engine(login_url="http://app.test/index.php?route=account/login")

        self.assertTrue(
            engine._is_login_target_url("http://app.test/index.php?route=account/login")
        )
        self.assertTrue(
            engine._is_login_target_url(
                "http://app.test/index.php?route=account/login&foo=bar"
            )
        )
        self.assertFalse(
            engine._is_login_target_url("http://app.test/index.php?route=checkout")
        )
        self.assertFalse(engine._is_login_target_url("http://app.test/index.php"))

    def test_is_login_target_url_false_without_login_url(self):
        engine = self._engine()

        self.assertFalse(engine._is_login_target_url("http://app.test/login"))

    def test_exclude_url_path_wildcard_matches_subtree(self):
        engine = self._engine(exclude_urls=["/dontScan/*"])

        self.assertTrue(engine._is_url_excluded("http://app.test/dontScan/a"))
        self.assertTrue(engine._is_url_excluded("http://app.test/dontScan/a/b/c"))
        # The base path itself (with or without trailing slash) is excluded too.
        self.assertTrue(engine._is_url_excluded("http://app.test/dontScan/"))
        self.assertTrue(engine._is_url_excluded("http://app.test/dontScan"))
        # Unrelated paths and prefixes that merely share a stem are not excluded.
        self.assertFalse(engine._is_url_excluded("http://app.test/other"))
        self.assertFalse(engine._is_url_excluded("http://app.test/dontScanX"))

    def test_exclude_url_full_width_asterisk(self):
        engine = self._engine(exclude_urls=["/dontScan/＊"])

        self.assertTrue(engine._is_url_excluded("http://app.test/dontScan/x"))

    def test_exclude_url_full_url_wildcard(self):
        engine = self._engine(exclude_urls=["http://app.test/admin/*"])

        self.assertTrue(engine._is_url_excluded("http://app.test/admin/users"))
        self.assertFalse(engine._is_url_excluded("http://app.test/public"))


if __name__ == "__main__":
    unittest.main()
