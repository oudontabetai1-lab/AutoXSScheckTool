"""Tests for the manual attack-scenario builder wiring.

Covers the WebSocket crawl-review message capturing operator-defined scenarios
and the ScanFlow round-trip those scenarios rely on.
"""
import unittest

from wscan.monitor import MonitorServer
from wscan.flow_runner import ScanFlow


class CrawlReviewScenarioTests(unittest.TestCase):
    def test_crawl_review_message_captures_flows(self):
        monitor = MonitorServer()
        monitor._handle_client_message(
            '{"action":"crawl_review","command":"continue",'
            '"flows":[{"name":"login","steps":['
            '{"action":"navigate","url":"http://app.test/login"},'
            '{"action":"fill","field":"user","value":"admin"},'
            '{"action":"submit"},'
            '{"action":"navigate","url":"http://app.test/admin"}]}]}'
        )
        action = monitor.crawl_review_action
        self.assertEqual(action["command"], "continue")
        self.assertTrue(monitor.crawl_review_event.is_set())
        self.assertEqual(len(action["flows"]), 1)
        self.assertEqual(action["flows"][0]["name"], "login")
        self.assertEqual(len(action["flows"][0]["steps"]), 4)

    def test_crawl_review_defaults_flows_to_empty_list(self):
        monitor = MonitorServer()
        monitor._handle_client_message(
            '{"action":"crawl_review","command":"continue"}'
        )
        self.assertEqual(monitor.crawl_review_action["flows"], [])

    def test_scenario_dict_round_trips_into_scanflow(self):
        raw = {
            "name": "login",
            "steps": [
                {"action": "navigate", "url": "http://app.test/login"},
                {"action": "fill", "field": "user", "value": "admin"},
                {"action": "submit"},
                {"action": "navigate", "url": "http://app.test/admin"},
            ],
        }
        flow = ScanFlow.from_dict(raw)
        self.assertIsInstance(flow, ScanFlow)
        self.assertEqual(flow.name, "login")
        self.assertEqual(len(flow.steps), 4)
        # Last navigate target defines the page the scenario attacks.
        last_nav = next(
            s for s in reversed(flow.steps) if s.action == "navigate"
        )
        self.assertEqual(last_nav.url, "http://app.test/admin")


if __name__ == "__main__":
    unittest.main()
