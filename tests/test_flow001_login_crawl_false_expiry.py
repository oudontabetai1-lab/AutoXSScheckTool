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
