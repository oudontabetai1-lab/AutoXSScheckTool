"""F07: /api/v1/scan の入力型検証。

配列 body / 配列 config / 非文字列 url を開始前に 4xx で拒否し、500 や受理後の
非同期例外にしない。正しい型は受理する。
"""
import unittest

from fastapi.testclient import TestClient

from wscan.monitor import MonitorServer


class ApiScanInputValidationTests(unittest.TestCase):
    def setUp(self):
        # auth_token="" は無認証（既存 security テストと同様）。allow-list 無し＝スコープ制限なし。
        self.client = TestClient(MonitorServer(port=0, auth_token="").app)

    def test_array_body_rejected(self):
        r = self.client.post("/api/v1/scan", json=[])
        self.assertEqual(r.status_code, 400)

    def test_array_config_rejected(self):
        r = self.client.post("/api/v1/scan", json={"config": []})
        self.assertEqual(r.status_code, 400)

    def test_numeric_url_rejected(self):
        r = self.client.post("/api/v1/scan", json={"url": 123})
        self.assertEqual(r.status_code, 400)

    def test_missing_url_rejected(self):
        r = self.client.post("/api/v1/scan", json={})
        self.assertEqual(r.status_code, 400)

    def test_valid_url_accepted(self):
        r = self.client.post("/api/v1/scan", json={"url": "http://example.test/"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json().get("status"), "accepted")
