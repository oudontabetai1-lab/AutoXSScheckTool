"""InjectionPoint と JSON Pointer 純粋ヘルパーのテスト。"""
import unittest
from dataclasses import FrozenInstanceError

from wscan.injection_point import (
    InjectionPoint,
    build_pointer,
    escape_token,
    parse_pointer,
    pointer_get,
    pointer_set_copy,
    unescape_token,
)


class JsonPointerTests(unittest.TestCase):
    def test_escape_and_unescape_order(self):
        self.assertEqual(escape_token("a~/b"), "a~0~1b")
        self.assertEqual(unescape_token("a~0~1b"), "a~/b")
        self.assertEqual(unescape_token("~01"), "~1")

    def test_parse_build_roundtrip(self):
        tokens = ["profile", "a/b", "tilde~key", ""]
        pointer = build_pointer(tokens)
        self.assertEqual(pointer, "/profile/a~1b/tilde~0key/")
        self.assertEqual(parse_pointer(pointer), tokens)
        self.assertEqual(parse_pointer(""), [])

    def test_pointer_get_dict_array_and_nested(self):
        doc = {"profile": {"email": "a@example.test"}, "items": [{"id": 7}]}
        self.assertEqual(pointer_get(doc, "/profile/email"), "a@example.test")
        self.assertEqual(pointer_get(doc, "/items/0/id"), 7)
        self.assertIs(pointer_get(doc, ""), doc)

    def test_pointer_set_copy_preserves_siblings_and_original(self):
        doc = {
            "profile": {"email": "old@example.test", "name": "Alice"},
            "password": "observed-secret",
        }
        changed = pointer_set_copy(doc, "/profile/email", "new@example.test")
        self.assertEqual(changed["profile"]["email"], "new@example.test")
        self.assertEqual(changed["profile"]["name"], "Alice")
        self.assertEqual(changed["password"], "observed-secret")
        self.assertEqual(doc["profile"]["email"], "old@example.test")

    def test_pointer_set_copy_handles_array_and_non_string_leaf(self):
        doc = {"filters": [{"email": "a"}, {"email": "b"}]}
        payload = {"$ne": ""}
        changed = pointer_set_copy(doc, "/filters/1/email", payload)
        self.assertEqual(changed["filters"][1]["email"], payload)
        self.assertEqual(doc["filters"][1]["email"], "b")
        payload["$ne"] = "mutated"
        self.assertEqual(changed["filters"][1]["email"], {"$ne": ""})

    def test_empty_pointer_replaces_document_with_deep_copy(self):
        value = {"$ne": [""]}
        changed = pointer_set_copy({"email": "old"}, "", value)
        self.assertEqual(changed, value)
        self.assertIsNot(changed, value)
        self.assertIsNot(changed["$ne"], value["$ne"])

    def test_missing_paths_raise(self):
        with self.assertRaises(KeyError):
            pointer_get({"profile": {}}, "/profile/email")
        with self.assertRaises(KeyError):
            pointer_set_copy({"profile": {}}, "/profile/email", "x")
        with self.assertRaises(KeyError):
            pointer_set_copy({}, "/profile/email", "x")
        with self.assertRaises(IndexError):
            pointer_set_copy({"items": []}, "/items/0", "x")


class InjectionPointTests(unittest.TestCase):
    def test_form_constructor_and_stable_key(self):
        ip = InjectionPoint.for_form("http://h/form/", "email", 2)
        self.assertEqual(ip.location, "form")
        self.assertEqual(ip.parameter_id, "email")
        self.assertEqual(ip.display_name, "email")
        self.assertEqual(ip.method, "")
        self.assertEqual(ip.source, "crawl")
        self.assertEqual(
            ip.stable_key_parts(),
            ("http://h/form", "email", "2", "f", ""),
        )

    def test_url_param_constructor_and_stable_key(self):
        ip = InjectionPoint.for_url_param("http://h/search/", "q")
        self.assertEqual(ip.location, "url_param")
        self.assertEqual(ip.form_index, 0)
        self.assertEqual(
            ip.stable_key_parts(),
            ("http://h/search", "q", "0", "u", ""),
        )

    def test_json_constructor_derives_display_name_and_stable_key(self):
        ip = InjectionPoint.for_json_body(
            "post",
            "http://h/login/",
            "/profile/email",
            template_id="login-1",
        )
        self.assertEqual(ip.location, "json_body")
        self.assertEqual(ip.display_name, "email")
        self.assertEqual(ip.method, "POST")
        self.assertEqual(ip.template_id, "login-1")
        self.assertEqual(ip.source, "spa")
        self.assertEqual(
            ip.stable_key_parts(),
            ("http://h/login", "email", "0", "j:POST", "/profile/email"),
        )

    def test_json_constructor_honours_display_name(self):
        ip = InjectionPoint.for_json_body(
            "patch", "http://h/user", "/profile/email", display_name="mail"
        )
        self.assertEqual(ip.display_name, "mail")
        self.assertEqual(ip.method, "PATCH")

    def test_descriptor_is_frozen(self):
        ip = InjectionPoint.for_form("http://h/form", "email")
        with self.assertRaises(FrozenInstanceError):
            ip.url = "http://other"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
