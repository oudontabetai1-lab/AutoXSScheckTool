"""SPA クリック探索がログアウト等のセッション終了リンクを踏まないことの純粋判定（Codex #104 P1）。"""
from __future__ import annotations

import pytest

from wscan.browser import is_session_ending_link


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
        ("", "ログイン"),
        ("", "Sign in"),
        ("", ""),
    ],
)
def test_non_session_links_are_not_flagged(href, text):
    assert is_session_ending_link(href, text) is False
