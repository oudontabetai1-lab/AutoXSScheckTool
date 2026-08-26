"""LLM-007: web intelligence 検索に検査対象の host/URL を送らない（匿名化）回帰。

対象 host/URL を外部検索（DuckDuckGo）へ送ると検査対象の外部漏洩＋未信頼結果による
prompt contamination が起きる。planner は技術ヒントのみで検索し、host/URL を含めない。
"""
import re

from wscan.llm_web_tools import build_planner_web_query


def test_planner_query_has_no_host_or_url():
    q = build_planner_web_query("Laravel PHP admin login")
    assert "Laravel" in q  # 技術ヒントは活かす
    # host/URL/IP を含めない
    assert "//" not in q
    assert "http" not in q.lower()
    assert not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", q)  # IP なし


def test_planner_query_generic_when_no_hints():
    q = build_planner_web_query("")
    assert q == "web application vulnerability"


def test_planner_query_collapses_whitespace():
    q = build_planner_web_query("  Django   REST  ")
    assert q == "web application vulnerability Django REST"


def test_planner_query_strips_url_embedded_in_hints():
    # untrusted なページ title に URL が混ざるケース（Codex P2）
    q = build_planner_web_query("Admin https://internal.example/admin Panel")
    assert "internal.example" not in q
    assert "http" not in q.lower()
    assert "//" not in q
    assert "Admin" in q and "Panel" in q  # 非識別トークンは残す


def test_planner_query_strips_bare_host_and_ip():
    q = build_planner_web_query("Login internal.example 10.0.0.5 Django")
    assert "internal.example" not in q
    assert "10.0.0.5" not in q
    assert "Login" in q and "Django" in q
