import unittest

from wscan import auth_detect as ad


_LOGIN_FORM = (
    '<form method="post" action="/login">'
    '<input type="text" name="username">'
    '<input type="password" name="password">'
    '<button type="submit">Sign in</button>'
    "</form>"
)
_DASHBOARD = '<h1>Welcome back</h1><a href="/logout">Logout</a><div>Your orders</div>'


class OnLoginPageTests(unittest.TestCase):
    def test_same_path_with_query_is_login_page(self):
        self.assertTrue(
            ad.on_login_page("http://x.test/login?error=1", "http://x.test/login")
        )

    def test_moved_away_is_not_login_page(self):
        self.assertFalse(
            ad.on_login_page("http://x.test/dashboard", "http://x.test/login")
        )

    def test_cross_host_same_path_redirect_is_not_login_page(self):
        # SSO/IdP: auth.example.com/ -> app.example.com/（同一パス別ホスト）は
        # ログイン成功とみなす（未認証スキャンに落とさない）。
        self.assertFalse(
            ad.on_login_page("https://app.example.com/", "https://auth.example.com/")
        )

    def test_same_host_same_path_is_login_page(self):
        # 同一ホストの同一パス（クエリ違い）は引き続きログインページ扱い。
        self.assertTrue(
            ad.on_login_page(
                "https://auth.example.com/signin?error=1",
                "https://auth.example.com/signin",
            )
        )

    def test_cross_host_same_login_path_is_not_login_page(self):
        # 別ホストの同一パス（/signin）でもログインページ扱いしない。
        self.assertFalse(
            ad.on_login_page(
                "https://app.example.com/signin", "https://auth.example.com/signin"
            )
        )

    def test_heuristic_when_login_url_empty(self):
        self.assertTrue(ad.on_login_page("http://x.test/signin", ""))
        self.assertFalse(ad.on_login_page("http://x.test/home", ""))


class FailureTextTests(unittest.TestCase):
    def test_case_insensitive_marker(self):
        self.assertTrue(ad.has_failure_text("Error: Invalid Credentials!"))

    def test_japanese_marker(self):
        self.assertTrue(ad.has_failure_text("ユーザー名またはパスワードが違います"))

    def test_clean_body(self):
        self.assertFalse(ad.has_failure_text(_DASHBOARD))


class LoginFormTests(unittest.TestCase):
    def test_detects_residual_login_form(self):
        self.assertTrue(ad.has_login_form(_LOGIN_FORM))

    def test_lone_password_input_without_username_is_not_login_form(self):
        # ダッシュボード上のパスワード変更欄のみ（ユーザ欄/submit/form 無し）。
        self.assertFalse(
            ad.has_login_form('<input type="password" id="newpw">')
        )

    def test_dashboard_has_no_login_form(self):
        self.assertFalse(ad.has_login_form(_DASHBOARD))

    def test_password_change_form_without_username_is_not_login_form(self):
        # ログイン後のパスワード変更フォーム（form+submit+password だが
        # ユーザ名/メール欄なし）を「ログインフォーム残存」と誤認しない。
        pw_change = (
            '<form method="post" action="/account/password">'
            '<input type="password" name="current_password">'
            '<input type="password" name="new_password">'
            '<input type="password" name="confirm_password">'
            '<button type="submit">Update password</button>'
            "</form>"
        )
        self.assertFalse(ad.has_login_form(pw_change))

    def test_email_only_login_form_is_detected(self):
        # name が user 等でなくても type=email があればログインフォーム扱い。
        email_form = (
            '<form><input type="email"><input type="password">'
            '<button type="submit">Go</button></form>'
        )
        self.assertTrue(ad.has_login_form(email_form))

    def test_try_again_text_is_not_a_failure_marker(self):
        # 「try again later」等の良性コピーを失敗と誤判定しない。
        self.assertFalse(ad.has_failure_text("Something went wrong, please try again later."))


class LoginSucceededTests(unittest.TestCase):
    def test_moved_but_still_login_form_is_failure(self):
        # 旧実装が誤って成功扱いにしていた /login?error= ケース。
        self.assertFalse(
            ad.login_succeeded(
                post_url="http://x.test/login?error=1",
                login_url="http://x.test/login",
                body="Invalid credentials" + _LOGIN_FORM,
            )
        )

    def test_clean_dashboard_is_success(self):
        self.assertTrue(
            ad.login_succeeded(
                post_url="http://x.test/dashboard",
                login_url="http://x.test/login",
                body=_DASHBOARD,
            )
        )

    def test_mfa_present_blocks_success(self):
        self.assertFalse(
            ad.login_succeeded(
                post_url="http://x.test/mfa",
                login_url="http://x.test/login",
                body=_DASHBOARD,
                mfa_present=True,
            )
        )

    def test_success_indicator_hit(self):
        self.assertTrue(
            ad.login_succeeded(
                post_url="http://x.test/app#/home",
                login_url="http://x.test/login",
                body="<div>nav</div>",
                success_indicator="/app",
            )
        )

    def test_success_indicator_with_failure_text_is_failure(self):
        self.assertFalse(
            ad.login_succeeded(
                post_url="http://x.test/app",
                login_url="http://x.test/login",
                body="login failed",
                success_indicator="/app",
            )
        )

    def test_missing_auth_cookie_denies_success(self):
        self.assertFalse(
            ad.login_succeeded(
                post_url="http://x.test/dashboard",
                login_url="http://x.test/login",
                body=_DASHBOARD,
                auth_cookie_present=False,
            )
        )


if __name__ == "__main__":
    unittest.main()
