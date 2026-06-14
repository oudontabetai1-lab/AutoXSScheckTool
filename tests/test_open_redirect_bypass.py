"""open_redirect スキャナのバイパス検出（純粋関数）の回帰テスト。

``/\\host`` や ``\\/host`` はブラウザが ``//host`` に正規化して外部遷移する。
urlparse は ``\\`` を path 文字として netloc を取りこぼすため、検出側で正規化して
ホストを判定できることを固定する（誤検知＝同一サイト相対は canary 扱いしない）。
"""
import unittest

from wscan.scanners.open_redirect import (
    _CANARY_HOST,
    _location_points_to_canary,
    _redirected_to_canary,
    _url_host,
)

BASE = "http://portal.example.test/sso/return"


class BackslashBypassDetectionTests(unittest.TestCase):
    def test_backslash_prefixed_host_resolves_to_canary(self):
        for loc in (f"/\\{_CANARY_HOST}", f"\\/{_CANARY_HOST}", f"//{_CANARY_HOST}"):
            with self.subTest(loc=loc):
                self.assertEqual(_url_host(loc, BASE), _CANARY_HOST.lower())

    def test_location_header_backslash_is_detected(self):
        pair = {"response": {"headers": {"location": f"/\\{_CANARY_HOST}"}}}
        self.assertTrue(_location_points_to_canary(pair, BASE))

    def test_browser_url_backslash_is_detected(self):
        self.assertTrue(_redirected_to_canary(f"/\\{_CANARY_HOST}", BASE))

    def test_same_site_relative_is_not_flagged(self):
        # 安全ツインが返す同一サイト相対パスは canary 扱いしない（誤検知ガード）。
        for safe in ("/portal/search", "/account/profile", "/"):
            with self.subTest(loc=safe):
                self.assertNotEqual(_url_host(safe, BASE), _CANARY_HOST.lower())
                self.assertFalse(_redirected_to_canary(safe, BASE))

    def test_echoed_param_not_flagged_without_redirect(self):
        # アドレスバーにパラメータが反射するだけ（実際の遷移先は同一サイト）→ 非検出。
        self.assertFalse(_redirected_to_canary(BASE + f"?dest=//{_CANARY_HOST}", BASE))


if __name__ == "__main__":
    unittest.main()
