import json
import tempfile
import unittest
from pathlib import Path

from wscan.reproduction import write_reproduction_package
from wscan.scanners.base import Finding


class ReproductionPackageTests(unittest.TestCase):
    def test_write_reproduction_package_with_curl_command(self):
        finding = Finding(
            check_type="xss",
            severity="critical",
            url="http://fixture.test/search",
            field_name="q",
            payload="<script>alert(1)</script>",
            evidence="dialog fired",
            confidence="confirmed",
            evidence_type="xss_dialog",
            evidence_details={"execution_signal": "browser_dialog"},
            reproduction_steps=["Open page", "Submit payload"],
            request={
                "method": "GET",
                "url": "http://fixture.test/search?q=%3Cscript%3Ealert%281%29%3C/script%3E",
                "headers": {"accept": "text/html", "host": "fixture.test"},
            },
            response={"status": 200, "headers": {"content-type": "text/html"}},
        )

        with tempfile.TemporaryDirectory() as tmp:
            result = write_reproduction_package([finding], Path(tmp))
            repro = json.loads(Path(result["json"]).read_text(encoding="utf-8"))
            shell = Path(result["shell"]).read_text(encoding="utf-8")

        self.assertEqual(result["count"], 1)
        self.assertEqual(repro["findings"][0]["evidence_type"], "xss_dialog")
        self.assertIn("curl -i -sS -X GET", shell)
        self.assertIn("http://fixture.test/search", shell)


if __name__ == "__main__":
    unittest.main()
