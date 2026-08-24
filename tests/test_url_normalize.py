"""checkpoint キー専用 URL 正規化の純粋・回帰テスト。"""
import pytest

from wscan.injection_point import InjectionPoint
from wscan.url_normalize import normalize_url_for_key


@pytest.mark.parametrize(
    "key",
    [
        "_",
        "t",
        "ts",
        "time",
        "timestamp",
        "nonce",
        "cb",
        "cachebuster",
        "cache_buster",
        "rand",
        "random",
        "_dc",
        "csrf",
        "csrf-token",
        "csrf_token",
        "csrftoken",
        "xsrf",
        "x-csrf-token",
        "x-xsrf-token",
        "authenticity_token",
        "__requestverificationtoken",
    ],
)
def test_known_volatile_query_keys_are_removed_case_insensitively(key):
    url = f"HTTPS://Example.test/path?keep=yes&{key.upper()}=rotating#section"
    assert normalize_url_for_key(url) == "HTTPS://Example.test/path?keep=yes"


def test_numeric_v_is_removed_but_non_numeric_v_is_preserved():
    assert normalize_url_for_key("https://h/p?v=123&id=5") == "https://h/p?id=5"
    assert normalize_url_for_key("https://h/p?v=release&id=5") == "https://h/p?id=5&v=release"


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
    first = "https://h/p?op=create&t=111&csrf=aaa"
    second = "https://h/p?csrf=bbb&t=222&op=create"
    assert normalize_url_for_key(first) == normalize_url_for_key(second)


def test_meaningful_operations_remain_distinct():
    create = normalize_url_for_key("https://h/p?t=1&op=create")
    delete = normalize_url_for_key("https://h/p?t=2&op=delete")
    assert create != delete


@pytest.mark.parametrize("url", ["", "http://[::1"])
def test_empty_or_unparseable_url_is_exception_safe(url):
    assert normalize_url_for_key(url) == url


@pytest.mark.parametrize("location", ["form", "url_param", "json_body"])
def test_stable_key_ignores_rotating_query_for_every_location(location):
    def make(url):
        if location == "form":
            return InjectionPoint.for_form(url, "name")
        if location == "url_param":
            return InjectionPoint.for_url_param(url, "name")
        return InjectionPoint.for_json_body("POST", url, "/name")

    first = make("https://h/action?op=create&t=111")
    second = make("https://h/action?t=222&op=create")

    assert first.stable_key_parts() == second.stable_key_parts()
    assert first.url == "https://h/action?op=create&t=111"
    assert second.url == "https://h/action?t=222&op=create"


@pytest.mark.parametrize("location", ["form", "url_param", "json_body"])
def test_stable_key_keeps_meaningful_operation_distinct(location):
    def make(operation):
        url = f"https://h/action?op={operation}&t=123"
        if location == "form":
            return InjectionPoint.for_form(url, "name")
        if location == "url_param":
            return InjectionPoint.for_url_param(url, "name")
        return InjectionPoint.for_json_body("POST", url, "/name")

    assert make("create").stable_key_parts() != make("delete").stable_key_parts()
