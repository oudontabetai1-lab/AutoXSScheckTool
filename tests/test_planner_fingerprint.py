from types import SimpleNamespace

from wscan.attack_planner import (
    AttackPlanner,
    _sanitize_header_value,
    build_planner_fingerprint,
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
