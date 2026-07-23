"""Dashboard scan config promotion/rejection state transitions."""
import shutil
import subprocess
import unittest
from pathlib import Path


class DashboardScanConfigStateTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node.js is required for dashboard JS test")
    def test_pending_config_is_discarded_on_rejection_and_promoted_on_acceptance(self):
        html = Path("templates/dashboard.html").read_text(encoding="utf-8")
        start = html.index("function _markOwnScan(config)")
        end = html.index("// finding の安定キー", start)
        functions = html[start:end]

        script = f"""
global.self = {{crypto: {{randomUUID: () => 'test-nonce-1'}}}};
global.crypto = self.crypto;
const state = {{
  lastScanConfig: {{url: 'https://accepted.example', auth_pass: 'original-value'}},
  pendingScanConfig: null,
  myScanNonce: null,
}};
{functions}

const previous = JSON.stringify(state.lastScanConfig);
const rejected = {{url: 'https://rejected.example', auth_pass: 'rejected-value'}};
_markOwnScan(rejected);
_discardRejectedPendingScan({{_client_nonce: state.myScanNonce}});
if (state.pendingScanConfig !== null) process.exit(10);
if (JSON.stringify(state.lastScanConfig) !== previous) process.exit(11);

self.crypto.randomUUID = () => 'test-nonce-2';
const accepted = {{url: 'https://new.example', auth_pass: 'full-value'}};
_markOwnScan(accepted);
_promotePendingScan({{
  _client_nonce: state.myScanNonce,
  url: accepted.url,
  auth_pass: '***REDACTED***',
}});
if (state.pendingScanConfig !== null) process.exit(20);
if (state.lastScanConfig.url !== accepted.url) process.exit(21);
if (state.lastScanConfig.auth_pass !== 'full-value') process.exit(22);

_promotePendingScan({{url: 'https://observed.example', auth_pass: '***REDACTED***'}});
if (state.lastScanConfig.url !== 'https://observed.example') process.exit(30);
if (state.lastScanConfig.auth_pass !== '***REDACTED***') process.exit(31);
"""
        result = subprocess.run(
            [shutil.which("node"), "-e", script],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
