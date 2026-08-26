"""FLOW-001: login_url 未設定時に /login の正規巡回を失効と誤判定しない回帰。

空 login_url では is_on_login_page が heuristic で /login を検知するが、_is_login_target_url が
False を返していたため、post-auth crawl で「意図的な /login 訪問」を「セッション失効」と誤判定し
未探索(unscannable)に落としていた。_is_login_target_url も heuristic を使うことで対称化する。
redirect（intended URL が login でない）のときは依然 expiry 判定される。
"""
from wscan.engine import ScanEngine


def _eng(login_url=""):
    eng = ScanEngine.__new__(ScanEngine)
    eng.login_url = login_url
    return eng


def test_empty_login_url_recognizes_deliberate_login_visit():
    eng = _eng("")
    # 意図的な /login 訪問は login target＝失効ではない（FLOW-001 の核）。
    assert eng._is_login_target_url("http://site/login") is True
    assert eng._is_login_target_url("http://site/account/login") is True


def test_empty_login_url_non_login_page_is_not_login_target():
    eng = _eng("")
    # 保護ページは login target でない → ここへ intend して /login へ redirect されたら失効判定される。
    assert eng._is_login_target_url("http://site/dashboard") is False
    # /login-history は /login で終わらないので誤検知しない。
    assert eng._is_login_target_url("http://site/admin/login-history") is False


def test_configured_login_url_behavior_preserved():
    eng = _eng("http://site/signin")
    assert eng._is_login_target_url("http://site/signin") is True
    assert eng._is_login_target_url("http://site/other") is False


def test_hash_routed_spa_login_recognized():
    # SPA の hash ルート login（/#/login）も意図的訪問と認識する（#108 Codex P2）。
    # is_on_login_page は全 URL を見て True、path だけ見る on_login_page では取りこぼす非対称を解消。
    eng = _eng("")
    assert eng._is_login_target_url("https://app.test/#/login") is True
    # 非 login の hash ルートは False（そこへの redirect は失効として扱える）。
    assert eng._is_login_target_url("https://app.test/#/dashboard") is False
    # クエリ値に /login を含む無関係ページは login target でない（真の失効検知を抑止しない）。
    assert eng._is_login_target_url("https://app.test/dashboard?next=/login") is False


def test_shared_heuristic_matches_browser_keywords():
    from wscan.auth_detect import url_looks_like_login
    for u in ("http://s/login", "http://s/signin", "http://s/sign-in",
              "http://s/auth/login", "http://s/account/login",
              "http://s/#/login", "http://s/#!/login", "http://s/login?next=/x", "http://s/login#top",
              "http://s/index.php?route=account/login"):  # 既知ルーティング param（#108）
        assert url_looks_like_login(u) is True, u
    # クエリ値に login パスを含む無関係 URL は login と誤判定しない（#108 Codex P2）。
    for u in ("http://s/dashboard", "http://s/login-history", "http://s/#/home",
              "http://s/dashboard?next=/login", "http://s/report?source=https://idp/login",
              "http://s/index.php?route=account/dashboard",  # ルーティング param でも非 login 値は False
              "http://s/docs#examples/login",   # 通常アンカーはルートでない（#108）
              "http://s/search?q=/login"):      # 検索 param はルータでない（#108）
        assert url_looks_like_login(u) is False, u
