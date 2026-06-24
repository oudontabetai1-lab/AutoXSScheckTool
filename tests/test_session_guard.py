"""セッション失効検知（純粋関数）のテスト。"""
import unittest

from wscan.session_guard import looks_logged_out

LOGIN_FORM = (
    '<form method="post" action="/login">'
    '<input name="username" type="text">'
    '<input name="password" type="password">'
    '<button type="submit">Login</button></form>'
)
DASHBOARD = '<h1>Dashboard</h1><a href="/logout">Logout</a> Welcome admin'


class SessionGuardTests(unittest.TestCase):
    def test_401_is_logged_out(self):
        self.assertTrue(
            looks_logged_out(status=401, final_url="http://h/x", body="nope")
        )

    def test_403_alone_is_not(self):
        # 403 may be a legitimate authorization denial, not session expiry
        self.assertFalse(
            looks_logged_out(status=403, final_url="http://h/admin", body=DASHBOARD)
        )

    def test_redirect_to_login_form(self):
        self.assertTrue(
            looks_logged_out(
                status=200,
                final_url="http://h/login",
                body=LOGIN_FORM,
                login_url="http://h/login",
            )
        )

    def test_authenticated_page_not_logged_out(self):
        self.assertFalse(
            looks_logged_out(
                status=200,
                final_url="http://h/dashboard",
                body=DASHBOARD,
                login_url="http://h/login",
            )
        )

    def test_login_page_without_form_not_enough(self):
        # On login URL but no actual form rendered (e.g. SPA shell) → don't relogin
        self.assertFalse(
            looks_logged_out(
                status=200,
                final_url="http://h/login",
                body="<div id=app></div>",
                login_url="http://h/login",
            )
        )

    def test_marker_gone_with_form(self):
        self.assertTrue(
            looks_logged_out(
                status=200,
                final_url="http://h/account",
                body=LOGIN_FORM,
                logged_in_marker="Welcome admin",
            )
        )

    def test_marker_present_not_logged_out(self):
        self.assertFalse(
            looks_logged_out(
                status=200,
                final_url="http://h/account",
                body=DASHBOARD + LOGIN_FORM,
                logged_in_marker="Welcome admin",
            )
        )


if __name__ == "__main__":
    unittest.main()
