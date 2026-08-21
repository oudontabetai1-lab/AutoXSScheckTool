from types import SimpleNamespace

from wscan.attack_planner import (
    AttackPlanner,
    _sanitize_header_value,
    build_planner_fingerprint,
    canonical_origin,
    extract_tech_headers,
    summarize_api_schema,
)
from wscan.injection_point import InjectionPoint


def test_extract_tech_headers_filters_case_insensitively_and_sanitizes():
    headers = {
        "SeRvEr": "nginx`\r\n injected",
        "X-Powered-By": "Python/3.12",
        "Content-Type": "text/html",
    }

    assert extract_tech_headers(headers) == {
        "server": "nginx   injected",
        "x-powered-by": "Python/3.12",
    }


def test_extract_tech_headers_bounds_values_and_handles_empty_input():
    assert extract_tech_headers({"Server": "x" * 121}) == {"server": "x" * 120}
    assert extract_tech_headers({}) == {}
    assert extract_tech_headers(None) == {}
    assert extract_tech_headers([("Server", "nginx")]) == {}
    assert _sanitize_header_value("`a\r\nb`", max_len=4) == "a  b"


def test_summarize_api_schema_groups_json_pointers_and_limits_lines():
    points = [
        InjectionPoint.for_json_body("post", "https://example.test/api/users?draft=1", "/name"),
        InjectionPoint.for_json_body("POST", "https://example.test/api/users", "/profile/email"),
        InjectionPoint.for_json_body("POST", "https://example.test/api/users", "/name"),
        InjectionPoint.for_url_param("https://example.test/api/users?q=x", "q"),
        InjectionPoint.for_form("https://example.test/form", "message"),
        InjectionPoint.for_json_body("patch", "https://example.test/api/accounts/1", "/role"),
        InjectionPoint.for_json_body("put", "https://example.test/api/settings", "/theme"),
    ]

    assert summarize_api_schema(points, max_lines=2) == [
        "POST /api/users — JSON fields: /name, /profile/email",
        "PATCH /api/accounts/1 — JSON fields: /role",
    ]


def test_summarize_api_schema_handles_empty_and_broken_input():
    assert summarize_api_schema([]) == []
    assert summarize_api_schema(None) == []
    assert summarize_api_schema(42) == []
    malformed = SimpleNamespace(
        location="json_body", method=123, url=None, parameter_id=456
    )
    assert summarize_api_schema([malformed]) == [
        "123 / — JSON fields: 456"
    ]


def test_summarize_api_schema_includes_api_seed_requests():
    # --api-spec の API-first では json_injection_points が空でも、api_seed_requests
    # のテンプレート（method/path/json_body キー）を fingerprint に反映する。
    seeds = [
        SimpleNamespace(
            method="post",
            url="https://example.test/api/orders?draft=1",
            json_body={"item": "x", "qty": 1},
        ),
        SimpleNamespace(
            method="PUT",
            url="https://example.test/api/orders",
            json_body={"status": "paid"},
        ),
        SimpleNamespace(method="get", url="https://example.test/api/ping", json_body=None),
    ]
    assert summarize_api_schema([], seeds) == [
        "POST /api/orders — JSON fields: /item, /qty",
        "PUT /api/orders — JSON fields: /status",
        "GET /api/ping — JSON fields: (root)",
    ]


def test_summarize_api_schema_merges_points_and_seeds_by_endpoint():
    # 同一 (method, path) は json_points と api_seed_requests をまたいで pointer 集約。
    points = [
        InjectionPoint.for_json_body("POST", "https://example.test/api/orders", "/item"),
    ]
    seeds = [
        SimpleNamespace(method="post", url="https://example.test/api/orders",
                        json_body={"item": "x", "qty": 2}),
    ]
    assert summarize_api_schema(points, seeds) == [
        "POST /api/orders — JSON fields: /item, /qty",
    ]


def test_summarize_api_schema_enumerates_nested_and_array_leaves():
    # ネスト dict/配列は harvest 側の leaf pointer 表現（/profile/email, /tags/0）に揃える。
    seeds = [
        SimpleNamespace(
            method="POST",
            url="https://example.test/api/users",
            json_body={"profile": {"email": "x"}, "tags": ["a", "b"], "id": 1},
        ),
    ]
    assert summarize_api_schema([], seeds) == [
        "POST /api/users — JSON fields: /profile/email, /tags/0, /id",
    ]


def test_summarize_api_schema_filters_by_origin():
    # multi-origin スキャンで、指定 origin のエンドポイントだけ要約する。
    points = [
        InjectionPoint.for_json_body("POST", "https://a.test/api/x", "/f1"),
        InjectionPoint.for_json_body("POST", "https://b.test/api/y", "/f2"),
    ]
    seeds = [
        SimpleNamespace(method="PUT", url="https://a.test/api/z", json_body={"g": 1}),
        SimpleNamespace(method="PUT", url="https://b.test/api/w", json_body={"h": 1}),
    ]
    assert summarize_api_schema(points, seeds, origin="https://a.test") == [
        "POST /api/x — JSON fields: /f1",
        "PUT /api/z — JSON fields: /g",
    ]
    # origin 未指定なら全 origin を含む（後方互換）。
    assert len(summarize_api_schema(points, seeds)) == 4


def test_canonical_origin_normalizes_port_and_case():
    assert canonical_origin("https://EXAMPLE.test:443/x?y=1") == "https://example.test"
    assert canonical_origin("http://Example.test:80/") == "http://example.test"
    assert canonical_origin("https://example.test:8443/") == "https://example.test:8443"
    assert canonical_origin("not a url") == ""
    assert canonical_origin("") == ""


def test_canonical_origin_idna_matches_punycode():
    # Unicode ホストと Chromium が landed に使う punycode が同一 origin キーへ正規化される。
    puny = "ドメイン.example".encode("idna").decode("ascii")
    uni_origin = canonical_origin("https://ドメイン.example/path")
    puny_origin = canonical_origin(f"https://{puny}/path")
    assert uni_origin == puny_origin
    assert uni_origin.startswith("https://xn--")


def test_summarize_api_schema_origin_filter_uses_canonical_form():
    # capture(landed 正規化)と lookup(生 URL:ポート付) が canonical で一致する。
    points = [
        InjectionPoint.for_json_body("POST", "https://EXAMPLE.test:443/api/x", "/f1"),
    ]
    assert summarize_api_schema(points, origin="https://example.test") == [
        "POST /api/x — JSON fields: /f1",
    ]


def test_json_leaf_pointers_bounds_depth_and_count():
    from wscan.attack_planner import _json_leaf_pointers
    # 深さ上限を超える枝は leaf ではなくその時点のノードで打ち切る（bounded）。
    deep = {"a": {"b": {"c": {"d": {"e": 1}}}}}
    ptrs = _json_leaf_pointers(deep, max_depth=2)
    assert ptrs == ["/a/b"]
    # 件数上限。
    wide = {f"k{i}": i for i in range(20)}
    assert len(_json_leaf_pointers(wide, max_pointers=5)) == 5


def test_build_planner_fingerprint_includes_detected_context_and_sanitizes():
    cms = SimpleNamespace(
        name="Word`Press",
        version="6.6",
        confidence="high",
        is_known=True,
    )

    fingerprint = build_planner_fingerprint(
        waf="Cloud`flare",
        cms=cms,
        tech_headers={"server": "nginx`\nproxy"},
        api_schema=["POST /api/users — JSON fields: `/name`"],
    )

    assert "## Detected server fingerprint" in fingerprint
    assert "- WAF: Cloudflare" in fingerprint
    assert "- CMS: WordPress v6.6 (confidence: high)" in fingerprint
    assert "- Response header server: nginx proxy" in fingerprint
    assert "- API: POST /api/users — JSON fields: /name" in fingerprint
    assert "`" not in fingerprint


def test_build_planner_fingerprint_omits_empty_and_unknown_cms():
    unknown = SimpleNamespace(
        name="unknown", version="", confidence="low", is_known=False
    )

    assert build_planner_fingerprint() == ""
    assert build_planner_fingerprint(cms=unknown) == ""


def test_llm_prompt_accepts_and_inserts_fingerprint_placeholder():
    assert "{fingerprint}" in AttackPlanner._LLM_PROMPT

    prompt = AttackPlanner._LLM_PROMPT.format(
        site_map="map",
        url="https://example.test/",
        title="Example",
        purpose_hint="test page",
        inputs_desc="- q",
        fingerprint="FINGERPRINT-CONTEXT",
        all_checks="sqli, xss",
    )

    assert "FINGERPRINT-CONTEXT" in prompt
