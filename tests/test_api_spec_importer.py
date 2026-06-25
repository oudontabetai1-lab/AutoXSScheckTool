"""API スペック取り込み（OpenAPI/Swagger/Postman, 純粋関数）のテスト。"""
import json
import tempfile
import unittest
from pathlib import Path

from wscan.api_spec_importer import (
    ApiSpecImporter,
    parse_openapi,
    parse_postman,
    _sample_for_name,
    _fill_path,
)

OPENAPI3 = {
    "openapi": "3.0.0",
    "servers": [{"url": "https://api.example.com/v1"}],
    "paths": {
        "/users": {
            "get": {
                "parameters": [
                    {"name": "page", "in": "query", "schema": {"type": "integer"}},
                    {"name": "q", "in": "query", "schema": {"type": "string"}},
                ]
            },
            "post": {
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "age": {"type": "integer"},
                                },
                            }
                        }
                    }
                }
            },
        },
        "/users/{id}": {
            "get": {
                "parameters": [
                    {"name": "id", "in": "path", "schema": {"type": "integer"}}
                ]
            }
        },
    },
}

SWAGGER2 = {
    "swagger": "2.0",
    "host": "api.example.com",
    "basePath": "/v2",
    "schemes": ["https"],
    "paths": {
        "/login": {
            "post": {
                "parameters": [
                    {
                        "in": "body",
                        "name": "creds",
                        "schema": {
                            "type": "object",
                            "properties": {"user": {"type": "string"}},
                        },
                    }
                ]
            }
        }
    },
}

POSTMAN = {
    "info": {"schema": "https://schema.getpostman.com/json/collection/v2.1.0/"},
    "item": [
        {
            "name": "folder",
            "item": [
                {
                    "name": "get users",
                    "request": {
                        "method": "GET",
                        "header": [{"key": "Authorization", "value": "Bearer x"}],
                        "url": "https://api.example.com/users?page=1",
                    },
                },
                {
                    "name": "create",
                    "request": {
                        "method": "POST",
                        "url": {
                            "raw": "https://api.example.com/users",
                            "host": ["api", "example", "com"],
                            "path": ["users"],
                        },
                        "body": {"mode": "raw", "raw": '{"name": "x"}'},
                    },
                },
            ],
        }
    ],
}


class HelperTests(unittest.TestCase):
    def test_sample_for_name_id(self):
        self.assertEqual(_sample_for_name("user_id"), 1)
        self.assertEqual(_sample_for_name("q", {"type": "string"}), "test")

    def test_fill_path(self):
        # {id} と {pid} は ID 名なので 1、{slug} は文字列なので test に具体化される
        self.assertEqual(
            _fill_path("/users/{id}/posts/{slug}", {"id": {"type": "integer"}}),
            "/users/1/posts/test",
        )


class OpenApiTests(unittest.TestCase):
    def test_urls_and_base(self):
        seed = parse_openapi(OPENAPI3)
        joined = "\n".join(seed.urls)
        self.assertIn("https://api.example.com/v1/users?", joined)
        self.assertIn("page=1", joined)
        self.assertIn("https://api.example.com/v1/users/1", joined)

    def test_request_body_template(self):
        seed = parse_openapi(OPENAPI3)
        posts = [r for r in seed.requests if r.method == "POST"]
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0].url, "https://api.example.com/v1/users")
        self.assertEqual(posts[0].json_body, {"name": "test", "age": 1})

    def test_request_body_ref_resolved(self):
        spec = {
            "openapi": "3.0.0",
            "servers": [{"url": "https://api.example.com"}],
            "components": {"schemas": {
                "User": {"type": "object", "properties": {
                    "name": {"type": "string"}, "age": {"type": "integer"}}},
            }},
            "paths": {"/users": {"post": {"requestBody": {"content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/User"}}}}}}},
        }
        seed = parse_openapi(spec)
        posts = [r for r in seed.requests if r.method == "POST"]
        self.assertEqual(len(posts), 1)
        # $ref が解決され、通常フィールドを含む本文になる（空 {} ではない）
        self.assertEqual(posts[0].json_body, {"name": "test", "age": 1})

    def test_swagger2_definitions_ref_resolved(self):
        spec = {
            "swagger": "2.0", "host": "api.example.com", "schemes": ["https"],
            "definitions": {"Creds": {"type": "object",
                                      "properties": {"user": {"type": "string"}}}},
            "paths": {"/login": {"post": {"parameters": [
                {"in": "body", "name": "b", "schema": {"$ref": "#/definitions/Creds"}}]}}},
        }
        seed = parse_openapi(spec)
        posts = [r for r in seed.requests if r.method == "POST"]
        self.assertEqual(posts[0].json_body, {"user": "test"})

    def test_swagger2_base(self):
        seed = parse_openapi(SWAGGER2)
        # body operation → request template, base from host+basePath
        self.assertTrue(any(r.url == "https://api.example.com/v2/login" for r in seed.requests))

    def test_relative_server_resolved_with_fallback(self):
        spec = {"openapi": "3.0.0", "servers": [{"url": "/api"}],
                "paths": {"/ping": {"get": {}}}}
        seed = parse_openapi(spec, fallback_base="https://h.example.com/app")
        self.assertIn("https://h.example.com/api/ping", seed.urls)

    def test_all_servers_expanded(self):
        # 先頭サーバがスコープ外でも後続を落とさないよう全ベースに展開する
        spec = {
            "openapi": "3.0.0",
            "servers": [
                {"url": "https://staging.example.com/v1"},
                {"url": "https://prod.example.com/v1"},
            ],
            "paths": {
                "/users": {"get": {}, "post": {"requestBody": {"content": {
                    "application/json": {"schema": {"type": "object",
                                                    "properties": {"n": {"type": "string"}}}}}}}},
            },
        }
        seed = parse_openapi(spec)
        self.assertIn("https://staging.example.com/v1/users", seed.urls)
        self.assertIn("https://prod.example.com/v1/users", seed.urls)
        post_urls = {r.url for r in seed.requests if r.method == "POST"}
        self.assertIn("https://staging.example.com/v1/users", post_urls)
        self.assertIn("https://prod.example.com/v1/users", post_urls)


class PostmanTests(unittest.TestCase):
    def test_walk_folders(self):
        seed = parse_postman(POSTMAN)
        self.assertIn("https://api.example.com/users?page=1", seed.urls)
        self.assertIn("https://api.example.com/users", seed.urls)
        self.assertEqual(seed.headers.get("Authorization"), "Bearer x")
        self.assertTrue(any(r.json_body == {"name": "x"} for r in seed.requests))


class LoadTests(unittest.TestCase):
    def test_load_json_openapi(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "spec.json"
            p.write_text(json.dumps(OPENAPI3), encoding="utf-8")
            seed = ApiSpecImporter().load(str(p))
            self.assertTrue(seed.urls)

    def test_load_detects_postman(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "collection.json"
            p.write_text(json.dumps(POSTMAN), encoding="utf-8")
            seed = ApiSpecImporter().load(str(p))
            self.assertTrue(seed.urls)

    def test_missing_raises(self):
        with self.assertRaises(FileNotFoundError):
            ApiSpecImporter().load("/no/such/file.json")


if __name__ == "__main__":
    unittest.main()
