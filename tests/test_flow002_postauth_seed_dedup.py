"""FLOW-002: post-auth crawl seed の末尾 slash 正規化で root 二重 crawl を防ぐ回帰。

landing_url(rstrip 済) と target_url(生) を揃えないと http://s と http://s/ が別 seed になり
root を二度 crawl する。_postauth_seed_urls は rstrip("/") で dedup する（純粋）。
"""
from wscan.engine import ScanEngine


def test_seed_dedups_trailing_slash():
    f = ScanEngine._postauth_seed_urls
    assert f("http://site", "http://site/") == ["http://site"]
    assert f("http://site/app", "http://site/app") == ["http://site/app"]


def test_seed_keeps_distinct_pages():
    f = ScanEngine._postauth_seed_urls
    assert f("http://site/dashboard", "http://site/login") == [
        "http://site/dashboard", "http://site/login"
    ]


def test_seed_handles_empty_landing():
    f = ScanEngine._postauth_seed_urls
    assert f("", "http://site/") == ["http://site"]
    assert f("http://site/x", "") == ["http://site/x"]
