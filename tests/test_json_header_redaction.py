import unittest

from wscan.reproduction import _finding_to_repro_item
from wscan.scanners.base import Finding


def _finding_with_sensitive_headers() -> Finding:
    return Finding(
        check_type="xss",
        severity="high",
        url="https://example.test/",
        field_name="q",
        payload="<script>alert(1)</script>",
        evidence="dialog fired",
        request={
            "method": "GET",
            "url": "https://example.test/",
            "headers": {
                "Authorization": "Bearer X",
                "Accept": "*/*",
            },
        },
        response={
            "status": 200,
            "headers": {
                "Set-Cookie": "session=secret",
                "Content-Type": "text/html",
            },
            "body": "<html></html>",
        },
    )


class JsonHeaderRedactionTests(unittest.TestCase):
    def test_finding_to_dict_redacts_headers_without_mutating_finding(self):
        finding = _finding_with_sensitive_headers()

        data = finding.to_dict()

        self.assertEqual(data["request"]["headers"]["Authorization"], "<redacted>")
        self.assertEqual(data["request"]["headers"]["Accept"], "*/*")
        self.assertEqual(data["response"]["headers"]["Set-Cookie"], "<redacted>")
        self.assertEqual(data["response"]["headers"]["Content-Type"], "text/html")
        self.assertNotIn("body", data["response"])
        self.assertEqual(finding.request["headers"]["Authorization"], "Bearer X")
        self.assertEqual(finding.response["headers"]["Set-Cookie"], "session=secret")

    def test_reproduction_item_redacts_request_and_response_headers(self):
        finding = _finding_with_sensitive_headers()

        item = _finding_to_repro_item(finding, 1)

        self.assertEqual(item["request"]["headers"]["Authorization"], "<redacted>")
        self.assertEqual(item["request"]["headers"]["Accept"], "*/*")
        self.assertEqual(item["response"]["headers"]["Set-Cookie"], "<redacted>")
        self.assertEqual(item["response"]["headers"]["Content-Type"], "text/html")
        self.assertNotIn("body", item["response"])
        self.assertEqual(finding.request["headers"]["Authorization"], "Bearer X")
        self.assertEqual(finding.response["headers"]["Set-Cookie"], "session=secret")


if __name__ == "__main__":
    unittest.main()
