import unittest

from fastapi.testclient import TestClient

from wscan.monitor import MonitorServer


class ProxyConfigTests(unittest.TestCase):
    def test_dashboard_defaults_endpoint_exposes_config_proxy(self):
        monitor = MonitorServer(port=8765)
        monitor.default_scan_cfg = {
            "proxy": "http://127.0.0.1:8080",
            "depth": 2,
            "checks": ["xss"],
        }

        with TestClient(monitor.app) as client:
            resp = client.get("/api/config/defaults")

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["proxy"], "http://127.0.0.1:8080")


if __name__ == "__main__":
    unittest.main()
