"""SPA クリック探索がログアウト等のセッション終了リンクを踏まないことの純粋判定（Codex #104 P1）。"""
from __future__ import annotations

import pytest

from wscan.browser import click_target_in_scope, is_session_ending_link


def _scope_fixture(url: str) -> bool:
    """fixture.test ホストのみ許可する簡易スコープ述語。"""
    from urllib.parse import urlparse

    return urlparse(url).netloc == "target.example"


@pytest.mark.parametrize(
    "href",
    [
        "/dashboard",          # 相対（同一ホストへ解決）
        "products?q=1",        # 相対
        "https://target.example/x",  # 同一ホスト絶対
        "",                    # href 無し（button 等）→ 同一ページ操作として許可
    ],
)
def test_click_target_in_scope_allows_in_scope(href):
    assert click_target_in_scope("https://target.example/", href, _scope_fixture) is True


@pytest.mark.parametrize(
    "href",
    [
        "//outside.example/action",              # プロトコル相対（外部）
        "https://target.example.evil/action",    # lookalike 絶対
        "https://outside.example/action",        # 明白な外部
    ],
)
def test_click_target_in_scope_blocks_out_of_scope(href):
    assert click_target_in_scope("https://target.example/", href, _scope_fixture) is False


def test_click_target_in_scope_fallback_netloc_exact_match():
    # is_in_scope 未指定時は netloc 完全一致。プロトコル相対の外部は弾く。
    assert click_target_in_scope("https://target.example/", "/a") is True
    assert click_target_in_scope("https://target.example/", "//outside.example/a") is False
    assert click_target_in_scope("https://target.example/", "https://target.example.evil/a") is False


@pytest.mark.parametrize(
    ("href", "text"),
    [
        ("/logout", ""),
        ("/auth/log-out", ""),
        ("/account/log_out", ""),
        ("?action=signout", ""),
        ("/sign-out", ""),
        ("/logoff", ""),
        ("", "Logout"),
        ("", "Log out"),
        ("", "Sign out"),
        ("", "ログアウト"),
        ("", "サインアウト"),
        ("#", "ログオフ"),
    ],
)
def test_session_ending_links_are_flagged(href, text):
    assert is_session_ending_link(href, text) is True


@pytest.mark.parametrize(
    ("href", "text"),
    [
        ("/dashboard", "ダッシュボード"),
        ("/products?q=1", "検索"),
        ("/about", "About"),
        ("/settings/profile", "プロフィール"),
        # トークン境界で誤検出しない（log/out・sign/out がセグメント跨ぎ・Codex #104 P2）。
        ("/catalog/output", ""),
        ("/blog/outdoors", ""),
        ("/prologoutfitters", ""),  # log/out を含むが単一の連続語（トークン境界なし）
        ("", "Catalog Output"),
        ("", "Blog Outdoors"),
        ("", "ログイン"),
        ("", "Sign in"),
        ("", ""),
    ],
)
def test_non_session_links_are_not_flagged(href, text):
    assert is_session_ending_link(href, text) is False
