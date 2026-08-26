"""FLOW-002: post-auth crawl の seed/子 URL を **キーで dedup しつつ元 URL を navigation に保持**する回帰。

landing_url(rstrip 済) と target_url(生) の末尾 slash 差で root を二度 crawl する二重巡回を防ぐが、
navigation URL は書き換えない（/app/ と /app が別リソースの slash-sensitive サーバを壊さない）。
"""
from wscan.engine import ScanEngine


def test_seed_dedups_by_key_but_keeps_original_target_slash():
    f = ScanEngine._postauth_seed_urls
    # 同一ページ(landing=/site, target=/site/) はキーで dedup し、target の元 slash を保持
    assert f("http://site", "http://site/") == ["http://site/"]
    # target に slash が無ければそのまま
    assert f("http://site/app", "http://site/app") == ["http://site/app"]


def test_seed_keeps_distinct_pages_original():
    f = ScanEngine._postauth_seed_urls
    # 別ページ(redirect)は両方 queue（target 優先の順）
    assert f("http://site/dashboard", "http://site/login") == [
        "http://site/login", "http://site/dashboard"
    ]


def test_seed_handles_empty_landing():
    f = ScanEngine._postauth_seed_urls
    assert f("", "http://site/") == ["http://site/"]  # 元 slash 保持
    assert f("http://site/x", "") == ["http://site/x"]
