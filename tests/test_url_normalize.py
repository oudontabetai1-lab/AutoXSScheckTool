"""checkpoint キー専用 URL 正規化の純粋・回帰テスト。"""
import pytest

from wscan.injection_point import InjectionPoint
from wscan.url_normalize import _looks_volatile_value, normalize_url_for_key


@pytest.mark.parametrize(
    "key",
    [
        "_",
        "cb",
        "_cb",
        "cachebuster",
        "cache_buster",
        "cache-buster",
        "cachebust",
        "_dc",
        "csrf",
        "_csrf",
        "csrf-token",
        "csrf_token",
        "csrftoken",
        "csrfmiddlewaretoken",
        "xsrf",
        "xsrf-token",
        "xsrf_token",
        "x-csrf-token",
        "x_csrf_token",
        "x-xsrf-token",
        "x_xsrf_token",
        "anti-csrf-token",
        "anti_csrf_token",
        "authenticity_token",
        "requestverificationtoken",
        "__requestverificationtoken",
    ],
)
def test_always_volatile_query_keys_are_removed_case_insensitively(key):
    url = f"HTTPS://Example.test/path?keep=yes&{key.upper()}=meaningful#section"
    assert normalize_url_for_key(url) == "HTTPS://Example.test/path?keep=yes"


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("time=commit", "time=commit"),
        ("time=preview", "time=preview"),
        ("t=preview", "t=preview"),
        ("t=5", "t=5"),
        ("v=2", "v=2"),
    ],
)
def test_conditional_keys_keep_meaningful_values(query, expected):
    assert normalize_url_for_key(f"https://h/p?{query}") == f"https://h/p?{expected}"


@pytest.mark.parametrize(
    "query",
    [
        "t=1699999999",
        "timestamp=1699999999000",
        "nonce=0123456789abcdef0123456789abcdef",
        "v=20231101",
        "v=AbCdEfGhIjKlMnOp_-012345",
    ],
)
def test_conditional_keys_remove_only_volatile_values(query):
    assert normalize_url_for_key(f"https://h/p?keep=yes&{query}") == "https://h/p?keep=yes"


def test_cachebuster_and_csrf_names_are_removed_regardless_of_value():
    url = (
        "https://h/p?_=1699999999&csrf=keep-me&authenticity_token=semantic"
        "&__RequestVerificationToken=anything&op=create"
    )
    assert normalize_url_for_key(url) == "https://h/p?op=create"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("16999999", True),
        ("1699999", False),
        ("1699999999", True),
        ("1699999999000", True),
        ("0123456789abcdef", True),
        ("AbCdEfGhIjKlMn_-", True),
        ("short-token", False),
        ("preview", False),
        ("１２３４５６７８", False),
        ("long token with spaces", False),
    ],
)
def test_looks_volatile_value(value, expected):
    assert _looks_volatile_value(value) is expected


def test_meaningful_and_unknown_query_keys_are_preserved_without_reencoding():
    url = "https://h/p?q=foo%20bar&op=create&id=5&build_nonce=keep%2Fme"
    assert normalize_url_for_key(url) == (
        "https://h/p?build_nonce=keep%2Fme&id=5&op=create&q=foo%20bar"
    )


def test_query_order_is_stable():
    assert normalize_url_for_key("https://h/p?a=1&b=2") == normalize_url_for_key(
        "https://h/p?b=2&a=1"
    )


def test_rotating_values_normalize_to_the_same_url():
    first = "https://h/p?op=create&t=1699999999&csrf=aaa"
    second = "https://h/p?csrf=bbb&t=1699999999000&op=create"
    assert normalize_url_for_key(first) == normalize_url_for_key(second)


def test_meaningful_operations_remain_distinct():
    create = normalize_url_for_key("https://h/p?time=preview")
    delete = normalize_url_for_key("https://h/p?time=commit")
    assert create != delete


@pytest.mark.parametrize("url", ["", "http://[::1"])
def test_empty_or_unparseable_url_is_exception_safe(url):
    assert normalize_url_for_key(url) == url


@pytest.mark.parametrize("location", ["form", "url_param", "json_body"])
def test_stable_key_parts_keeps_raw_url_for_unit_key_choke_point(location):
    def make(url):
        if location == "form":
            return InjectionPoint.for_form(url, "name")
        if location == "url_param":
            return InjectionPoint.for_url_param(url, "name")
        return InjectionPoint.for_json_body("POST", url, "/name")

    url = "https://h/action?op=create&t=1699999999"
    ip = make(url)

    assert ip.stable_key_parts()[0] == url
    assert ip.url == url
