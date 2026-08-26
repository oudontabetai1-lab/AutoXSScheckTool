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


def test_planner_query_strips_schemeless_host_with_path_or_port():
    # scheme 無しで path/port が付く host は fullmatch を素通りしていた（Codex P2 #2）
    for hint in (
        "Admin internal.example/admin Panel",
        "Admin internal.example:8443 Panel",
        "Admin 10.0.0.5/admin Panel",
        "Admin 10.0.0.5:8080 Panel",
    ):
        q = build_planner_web_query(hint)
        assert "internal.example" not in q, hint
        assert "10.0.0.5" not in q, hint
        assert "8443" not in q and "8080" not in q, hint
        assert "/admin" not in q, hint
        assert "Admin" in q and "Panel" in q, hint  # 非識別トークンは残す


def test_planner_query_redacts_known_single_label_host():
    # ヒューリスティックでは捕まらない単一ラベル内部 host も、対象既知なら落とす（Codex 示唆）
    q = build_planner_web_query("Admin intranet Dashboard", target_url="http://intranet/admin")
    assert "intranet" not in q.lower()
    assert "Admin" in q and "Dashboard" in q


def test_planner_query_redacts_known_host_with_port():
    q = build_planner_web_query("Portal myhost Login", target_url="http://myhost:8443/app")
    assert "myhost" not in q.lower()
    assert "Portal" in q and "Login" in q


def test_planner_query_target_url_optional():
    # target_url 無しでも従来通り動く（後方互換）
    q = build_planner_web_query("Django REST")
    assert q == "web application vulnerability Django REST"


def test_planner_query_strips_relative_path_token():
    # 相対 path も host も持たないが機微な path（Codex P2#3）
    q = build_planner_web_query("Admin /internal/tenant-42 Dashboard",
                                target_url="http://host/internal/tenant-42")
    assert "tenant-42" not in q
    assert "/internal" not in q and "internal/tenant" not in q
    assert "Admin" in q and "Dashboard" in q


def test_planner_query_allows_plain_tech_tokens():
    # アローリストは素の技術語（C#/C++ 含む）を通す
    q = build_planner_web_query("WordPress C# C++ nginx")
    assert "WordPress" in q and "nginx" in q
    assert "C#" in q and "C++" in q


def test_planner_query_allowlist_drops_any_url_structural_token():
    for bad in ("path?a=b", "a#frag/x", "user@host", "seg/ment", "a=b&c=d"):
        q = build_planner_web_query(f"Admin {bad} Page")
        assert bad not in q, bad
        assert "Admin" in q and "Page" in q
