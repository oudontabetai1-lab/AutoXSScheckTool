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
    q = build_planner_web_query("Admin intranet Dashboard", target_url="http://intranet/")
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


def test_planner_query_redacts_bare_path_segment():
    # 区切り無しで title に現れる target 固有の path segment（Codex P2#4）
    q = build_planner_web_query("Tenant tenant-42 Overview",
                                target_url="https://host/tenant-42")
    assert "tenant-42" not in q
    assert "Tenant" in q and "Overview" in q  # 一般語は残す


def test_planner_query_redacts_query_identifier():
    q = build_planner_web_query("Report acct-99 Summary",
                                target_url="https://host/r?account=acct-99")
    assert "acct-99" not in q
    assert "Report" in q and "Summary" in q


def test_planner_query_path_redaction_is_exact_token_only():
    # 完全一致のみ＝path segment を部分に含むだけの一般語は巻き込まない
    q = build_planner_web_query("administrator dashboard",
                                target_url="https://host/admin")
    assert "administrator" in q  # 'admin' を含むが完全一致でないので残る


def test_planner_query_redacts_spa_hash_route_identifier():
    # SPA hash-router のルート由来の対象固有識別子（proactive: fragment も既知対象として redact）
    q = build_planner_web_query("Tenant tenant-42 View",
                                target_url="https://host/app#/tenants/tenant-42")
    assert "tenant-42" not in q
    assert "Tenant" in q and "View" in q


def test_planner_query_rejects_compound_hash_route_token():
    # `#` を末尾のみ許可＝中間に `#` を持つ複合ハッシュルートを弾く（Codex P2#5）
    q = build_planner_web_query("View app#tenant-42 Page",
                                target_url="https://host/app#tenant-42")
    assert "app#tenant-42" not in q and "tenant-42" not in q
    assert "View" in q and "Page" in q
    # C#/C++/F# は末尾特殊文字なので通る
    q2 = build_planner_web_query("C# C++ F# WordPress")
    assert "C#" in q2 and "C++" in q2 and "F#" in q2 and "WordPress" in q2


def test_planner_query_redacts_multiword_query_value():
    # `?account=Acme+Corp` は parse_qsl で 'acme corp' になるが title は Acme/Corp に分割される
    # → 語単位でも redact（Codex P2#6）
    q = build_planner_web_query("Report Acme Corp Summary",
                                target_url="https://host/r?account=Acme+Corp")
    assert "Acme" not in q and "Corp" not in q
    assert "Report" in q and "Summary" in q


def test_planner_query_redacts_percent_encoded_path_identifier():
    # `/%74enant-42` は decode すると `tenant-42`。title は decode 済み表示なので一致させる（P2#7）
    q = build_planner_web_query("View tenant-42 Page",
                                target_url="https://host/%74enant-42")
    assert "tenant-42" not in q
    assert "View" in q and "Page" in q


def test_planner_query_redacts_percent_encoded_fragment_identifier():
    q = build_planner_web_query("Open tenant-42 Detail",
                                target_url="https://host/app#/%74enant-42")
    assert "tenant-42" not in q
    assert "Open" in q and "Detail" in q


def test_planner_query_purpose_hint_vocab_is_clean():
    # root では固定語彙 purpose_hint のみを送る。全語彙が識別子を含まず素通りすることを固定。
    for hint in (
        "authentication / login form",
        "administration panel",
        "search / query interface",
        "e-commerce / checkout form",
        "general web form",
    ):
        q = build_planner_web_query(hint, target_url="https://internal.example/tenant-42")
        assert q.startswith("web application vulnerability")
        assert "internal.example" not in q and "tenant-42" not in q
        # 語彙の単語は残る（`/` は構造文字として落ちるが単語は通る）
        assert "form" in q or "panel" in q or "interface" in q
