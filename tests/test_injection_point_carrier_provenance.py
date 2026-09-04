"""0035-B: InjectionPoint の carrier/value_kind/operation/template provenance 加算のテスト。

最重要の不変条件は **stable_key_parts()（checkpoint/resume キー）が加算フィールドの有無で
変わらない**こと。純粋ヘルパ（structure_digest / compute_operation_id）の決定論性・値非依存性も
検証する。
"""
import pytest

from wscan.injection_point import (
    InjectionPoint,
    compute_operation_id,
    structure_digest,
)
from wscan.scanner_contract import Carrier, ValueKind


# ── stable key 互換（最重要）─────────────────────────────────────────────

def test_stable_key_parts_unchanged_by_provenance_fields_form():
    base = InjectionPoint.for_form(
        "http://x/a", "q", form_index=2, method="POST", action="http://x/s"
    )
    enriched = InjectionPoint.for_form(
        "http://x/a", "q", form_index=2, method="POST", action="http://x/s",
        value_kind=ValueKind.STRING, operation_id="OP", template_source="crawl",
        template_digest="deadbeefdeadbeef",
    )
    assert base.stable_key_parts() == enriched.stable_key_parts()


def test_stable_key_parts_unchanged_by_provenance_fields_url_param():
    base = InjectionPoint.for_url_param("http://x/a?z=1", "z")
    enriched = InjectionPoint.for_url_param(
        "http://x/a?z=1", "z", value_kind=ValueKind.INTEGER, operation_id="OP",
        template_source="har", template_digest="cafebabe",
    )
    assert base.stable_key_parts() == enriched.stable_key_parts()


def test_stable_key_parts_unchanged_by_provenance_fields_json():
    base = InjectionPoint.for_json_body("POST", "http://x/api", "/a/b")
    enriched = InjectionPoint.for_json_body(
        "POST", "http://x/api", "/a/b", value_kind=ValueKind.OBJECT,
        operation_id="POST http://x/api login", template_source="spa",
        template_digest="0123456789abcdef",
    )
    assert base.stable_key_parts() == enriched.stable_key_parts()


# ── carrier property ─────────────────────────────────────────────────────

def test_carrier_maps_from_location():
    assert InjectionPoint.for_form("http://x", "q").carrier is Carrier.FORM
    assert InjectionPoint.for_url_param("http://x", "q").carrier is Carrier.QUERY
    assert InjectionPoint.for_json_body("POST", "http://x", "/a").carrier is Carrier.JSON


def test_carrier_unknown_location_raises():
    ip = InjectionPoint(location="mystery", url="http://x", parameter_id="q")
    with pytest.raises(ValueError):
        _ = ip.carrier


# ── 加算フィールドの既定値と pass-through ────────────────────────────────

def test_provenance_fields_default_empty():
    ip = InjectionPoint.for_form("http://x", "q")
    assert ip.value_kind is ValueKind.UNKNOWN
    assert ip.operation_id == ""
    assert ip.template_source == ""
    assert ip.template_digest == ""


def test_factories_pass_through_provenance():
    ip = InjectionPoint.for_json_body(
        "POST", "http://x", "/a", value_kind=ValueKind.ARRAY,
        operation_id="op-1", template_source="openapi", template_digest="abc123",
    )
    assert ip.value_kind is ValueKind.ARRAY
    assert ip.operation_id == "op-1"
    assert ip.template_source == "openapi"
    assert ip.template_digest == "abc123"


# ── structure_digest（値抜き構造ダイジェスト）────────────────────────────

def test_structure_digest_is_value_independent():
    # 同じ構造・異なる値 → 同一ダイジェスト（nonce/秘匿値に依存しない）。
    assert structure_digest({"a": 1, "b": "X"}) == structure_digest({"a": 999, "b": "Y"})


def test_structure_digest_distinguishes_structure_and_types():
    assert structure_digest({"a": 1}) != structure_digest({"a": "s"})   # 型差
    assert structure_digest({"a": 1}) != structure_digest({"b": 1})     # キー差
    assert structure_digest({"a": 1}) != structure_digest({"a": {"c": 1}})  # ネスト差


def test_structure_digest_is_list_length_independent():
    assert structure_digest([1, 1, 1]) == structure_digest([1])


def test_structure_digest_key_order_independent():
    assert structure_digest({"a": 1, "b": 2}) == structure_digest({"b": 2, "a": 1})


def test_structure_digest_omits_plaintext_values():
    secret = "super-secret-token-value"
    assert secret not in structure_digest({"token": secret})


# ── compute_operation_id（安定 operation identity）───────────────────────

def test_compute_operation_id_is_deterministic_and_normalized():
    assert compute_operation_id("post", "http://x/a", "Op") == compute_operation_id(
        "POST", "http://x/a", "Op"
    )


def test_compute_operation_id_distinguishes_operation_token():
    a = compute_operation_id("POST", "http://x/rpc", "login")
    b = compute_operation_id("POST", "http://x/rpc", "logout")
    assert a != b


def test_compute_operation_id_without_token_has_no_trailing_separator():
    assert compute_operation_id("GET", "http://x/a") == compute_operation_id(
        "GET", "http://x/a", ""
    )


def test_structure_digest_is_injective_across_delimiter_keys():
    # 区切り文字を含むキーで衝突しない（P2）: {"a":1,"b":2} と {"a:int,b":3} は別 digest。
    assert structure_digest({"a": 1, "b": 2}) != structure_digest({"a:int,b": 3})
    # 入れ子・array 型でも object/array/scalar の型差が保たれる
    assert structure_digest({"a": [1]}) != structure_digest({"a": {"0": 1}})
    assert structure_digest({"a": "x"}) != structure_digest({"a": ["x"]})
