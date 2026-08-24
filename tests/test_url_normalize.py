"""checkpoint キー専用 URL 正規化の純粋・回帰テスト。"""
import pytest

from wscan.injection_point import InjectionPoint
from wscan.url_normalize import (
    _looks_epoch_digits,
    _looks_random_token,
    normalize_url_for_key,
)


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
        ("timestamp=1700000000", "timestamp=1700000000"),
        ("time=1700000000", "time=1700000000"),
        ("t=1699999999", "t=1699999999"),
        ("v=20231101", "v=20231101"),
        ("time=commit", "time=commit"),
        ("t=preview", "t=preview"),
        ("v=2", "v=2"),
        ("v=release-candidate-1", "v=release-candidate-1"),
        ("timestamp=1700000000000000000", "timestamp=1700000000000000000"),
        (
            "t=0123456789abcdef0123456789abcdef",
            "t=0123456789abcdef0123456789abcdef",
        ),
    ],
)
def test_ambiguous_keys_are_always_kept(query, expected):
    assert normalize_url_for_key(f"https://h/p?{query}") == f"https://h/p?{expected}"


@pytest.mark.parametrize(
    "query",
    [
        "nonce=1700000000",
        "nonce=0123456789abcdef0123456789abcdef",
        "rand=12345678",
    ],
)
def test_transient_name_keys_remove_epoch_digits_and_random_tokens(query):
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
        ("0123456789abcdef", True),
        ("AbCdEfGhIjKlMn_-", True),
        ("1234567890123456", True),
        ("0123456789abcde", False),
        ("short-token", False),
        ("preview", False),
        ("１２３４５６７８", False),
        ("long token with spaces", False),
    ],
)
def test_looks_random_token(value, expected):
    assert _looks_random_token(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("16999999", True),
        ("1699999", False),
        ("1699999999", True),
        ("1699999999000", True),
        ("1234567a", False),
        ("１２３４５６７８", False),
    ],
)
def test_looks_epoch_digits(value, expected):
    assert _looks_epoch_digits(value) is expected


def test_meaningful_and_unknown_query_keys_are_preserved_without_reencoding():
    url = "https://h/p?q=foo%20bar&op=create&id=5&build_nonce=keep%2Fme"
    assert normalize_url_for_key(url) == (
        "https://h/p?build_nonce=keep%2Fme&id=5&op=create&q=foo%20bar"
    )


def test_query_order_is_stable():
    assert normalize_url_for_key("https://h/p?a=1&b=2") == normalize_url_for_key(
        "https://h/p?b=2&a=1"
    )


def test_trailing_slash_normalization_only_changes_path():
    assert normalize_url_for_key("http://h/p/") == "http://h/p"
    assert normalize_url_for_key("http://h/") == "http://h"
    assert normalize_url_for_key("http://h/p?z=/admin/&a=1") == (
        "http://h/p?a=1&z=/admin/"
    )
    assert normalize_url_for_key("http://h/p?z=/admin/&a=1") != (
        normalize_url_for_key("http://h/p?a=1&z=/admin")
    )


def test_rotating_values_normalize_to_the_same_url():
    first = "https://h/p?op=create&nonce=1699999999&csrf=aaa"
    second = "https://h/p?csrf=bbb&nonce=1699999999000&op=create"
    assert normalize_url_for_key(first) == normalize_url_for_key(second)


def test_meaningful_timestamp_values_remain_distinct():
    first = normalize_url_for_key("https://h/p?timestamp=1699999999")
    second = normalize_url_for_key("https://h/p?timestamp=1700000000")
    assert first != second


def test_meaningful_operations_remain_distinct():
    create = normalize_url_for_key("https://h/p?time=preview")
    delete = normalize_url_for_key("https://h/p?time=commit")
    assert create != delete


def test_spa_hash_routes_remain_distinct():
    admin = normalize_url_for_key("https://app.test/#/admin")
    users = normalize_url_for_key("https://app.test/#/users")

    assert admin == "https://app.test#/admin"
    assert users == "https://app.test#/users"
    assert admin != users


def test_in_page_anchor_is_removed():
    assert normalize_url_for_key(
        "https://app.test/page#section"
    ) == "https://app.test/page"


def test_hashbang_route_is_preserved():
    assert normalize_url_for_key(
        "https://app.test/#!/route"
    ) == "https://app.test#!/route"


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

    url = "https://h/action/?op=create&z=/admin/"
    ip = make(url)

    assert ip.stable_key_parts()[0] == url
    assert ip.url == url
