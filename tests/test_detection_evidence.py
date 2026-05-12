import unittest
from unittest.mock import AsyncMock, patch

from wscan.browser import NetworkCapture
from wscan.ctf_flag_finder import FlagFinder
from wscan.engine import ScanEngine
from wscan.payload_gen import PayloadGenerator, _format_prompt_template
from wscan.scanners.base import BaseScanner, Finding, finding_dedup_key_for
from wscan.scanners.header_injection import HeaderInjectionScanner
from wscan.scanners.nosql_injection import NoSQLInjectionScanner
from wscan.scanners.open_redirect import OpenRedirectScanner
from wscan.scanners.os_injection import OSInjectionScanner
from wscan.scanners.path_traversal import PathTraversalScanner
from wscan.scanners.security_headers import SecurityHeadersScanner
from wscan.scanners.sqli import SQLiScanner
from wscan.scanners.ssrf import SSRFScanner
from wscan.scanners.ssti import SSTIScanner
from wscan.scanners.xss import XSSScanner


class _DummyBrowser:
    async def screenshot_b64(self, label=""):
        return ""


class _DummyEngine:
    def __init__(self):
        self.browser = _DummyBrowser()
        self.monitor = None
        self.payload_gen = None
        self._finding_dedup = set()
        self.all_findings = []


class _DummyScanner(BaseScanner):
    CHECK_TYPE = "xss"

    async def scan_field(self, url, form_index, field, is_url_param=False):
        return []


class _VerifierBrowser:
    def __init__(self, baseline_html=""):
        self.dialog_fired = False
        self.page = type(
            "Page",
            (),
            {"content": AsyncMock(return_value=baseline_html)},
        )()
        self.navigate = AsyncMock(return_value=True)

    def reset_dialog(self):
        self.dialog_fired = False


class DetectionEvidenceTests(unittest.TestCase):
    def test_finding_serializes_structured_evidence(self):
        finding = Finding(
            check_type="xss",
            severity="high",
            url="http://example.test/search?q=x",
            field_name="q",
            payload="<svg onload=alert(1)>",
            evidence="reflected in script context",
            confidence="likely",
            evidence_type="xss_reflection",
            evidence_details={"context": "script", "raw_payload_present": True},
            reproduction_steps=["Open page", "Submit payload"],
        )

        data = finding.to_dict()

        self.assertEqual(data["evidence_type"], "xss_reflection")
        self.assertEqual(data["evidence_details"]["context"], "script")
        self.assertEqual(data["reproduction_steps"], ["Open page", "Submit payload"])

    def test_dedup_key_preserves_distinct_evidence_types_on_same_input(self):
        finding = Finding(
            check_type="sqli",
            severity="critical",
            url="http://fixture.test/login",
            field_name="username",
            payload="'",
            evidence="SQL error",
            evidence_type="sqli_error",
        )
        auth_finding = Finding(
            check_type="sqli",
            severity="critical",
            url="http://fixture.test/login",
            field_name="username",
            payload="' OR '1'='1",
            evidence="Auth bypass",
            evidence_type="sqli_auth_bypass",
        )

        self.assertNotEqual(
            finding_dedup_key_for(finding),
            finding_dedup_key_for(auth_finding),
        )

    def test_record_finding_dedups_exact_evidence_only(self):
        async def run():
            engine = _DummyEngine()
            scanner = _DummyScanner(engine)
            pair = {"request": {}, "response": {"body": "payload"}}

            first = await scanner.record_finding(
                "http://fixture.test/search",
                "q",
                "<script>alert(1)</script>",
                "Dialog fired",
                pair,
                evidence_type="xss_dialog",
            )
            duplicate = await scanner.record_finding(
                "http://fixture.test/search",
                "q",
                "<script>alert(1)</script>",
                "Dialog fired again",
                pair,
                evidence_type="xss_dialog",
            )
            reflected = await scanner.record_finding(
                "http://fixture.test/search",
                "q",
                "<b>wscan</b>",
                "Reflected text",
                pair,
                evidence_type="xss_reflection",
            )

            self.assertIsNotNone(first)
            self.assertIsNone(duplicate)
            self.assertIsNotNone(reflected)
            self.assertEqual(len(engine.all_findings), 2)

        self.run_async(run())

    def test_xss_reflection_context_marks_script_as_likely(self):
        scanner = object.__new__(XSSScanner)
        payload = '";alert(1);//'
        source = f"<html><script>const q = \"{payload}\";</script></html>"

        reflection = scanner._analyze_reflection(source, payload)

        self.assertEqual(reflection["context"], "script")
        self.assertEqual(reflection["confidence"], "likely")
        self.assertTrue(reflection["raw_payload_present"])

    def test_xss_reflection_context_marks_text_as_tentative(self):
        scanner = object.__new__(XSSScanner)
        payload = "<b>wscan</b>"
        source = f"<html><body>Search: {payload}</body></html>"

        reflection = scanner._analyze_reflection(source, payload)

        self.assertEqual(reflection["context"], "html_text")
        self.assertEqual(reflection["confidence"], "tentative")

    def test_xss_verifier_resets_stale_dialog_state(self):
        async def run():
            scanner = XSSScanner(_DummyEngine())
            scanner.browser = _VerifierBrowser("<html>baseline</html>")
            scanner.browser.dialog_fired = True
            scanner._apply_payload = AsyncMock(return_value=("<html>no payload</html>", {}))
            finding = Finding(
                check_type="xss",
                severity="critical",
                url="http://fixture.test/search?q=x",
                field_name="q",
                payload="<script>alert(1)</script>",
                evidence="dialog fired",
                evidence_type="xss_dialog",
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_xss_verifier_uses_baseline_for_reflection(self):
        async def run():
            payload = "<svg onload=alert(1)>"
            html = f"<html><body>{payload}</body></html>"
            scanner = XSSScanner(_DummyEngine())
            scanner.browser = _VerifierBrowser(html)
            scanner._apply_payload = AsyncMock(return_value=(html, {}))
            finding = Finding(
                check_type="xss",
                severity="high",
                url="http://fixture.test/search?q=x",
                field_name="q",
                payload=payload,
                evidence="reflected",
                evidence_type="xss_reflection",
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_nosql_boolean_verifier_requires_baseline_delta(self):
        async def run():
            scanner = NoSQLInjectionScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(side_effect=[
                ("A" * 1000, {}),
                ("A" * 1000, {}),
                ("A" * 1200, {}),
            ])
            finding = Finding(
                check_type="nosql",
                severity="high",
                url="http://fixture.test/nosql-login",
                field_name="username",
                payload='{"$ne": ""}',
                evidence="NoSQL boolean",
                evidence_type="nosql_boolean",
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_nosql_boolean_verifier_confirms_large_replay_delta(self):
        async def run():
            scanner = NoSQLInjectionScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(side_effect=[
                ("A" * 1000, {}),
                ("A" * 1005, {}),
                ("B" * 1800, {}),
            ])
            finding = Finding(
                check_type="nosql",
                severity="high",
                url="http://fixture.test/nosql-login",
                field_name="username",
                payload='{"$ne": ""}',
                evidence="NoSQL boolean",
                evidence_type="nosql_boolean",
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)

        self.run_async(run())

    def test_nosql_error_verifier_rejects_preexisting_error(self):
        async def run():
            scanner = NoSQLInjectionScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(side_effect=[
                ("MongoServerError: preexisting", {}),
                ("MongoServerError: preexisting", {}),
                ("MongoServerError: preexisting", {}),
            ])
            finding = Finding(
                check_type="nosql",
                severity="high",
                url="http://fixture.test/nosql-login",
                field_name="username",
                payload='{"$ne": ""}',
                evidence="NoSQL error",
                evidence_type="nosql_error",
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_ssrf_verifier_rejects_preexisting_marker(self):
        async def run():
            scanner = SSRFScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(side_effect=[
                ("instance-id already present", {}),
                ("instance-id already present", {}),
            ])
            finding = Finding(
                check_type="ssrf",
                severity="critical",
                url="http://fixture.test/fetch?url=http://example.test/",
                field_name="url",
                payload="http://169.254.169.254/latest/meta-data/",
                evidence="SSRF marker",
                evidence_type="ssrf_internal_marker",
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_ssrf_verifier_confirms_probe_only_marker(self):
        async def run():
            scanner = SSRFScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(side_effect=[
                ("Fetched public resource", {}),
                ("instance-id\ni-1234567890abcdef0", {}),
            ])
            finding = Finding(
                check_type="ssrf",
                severity="critical",
                url="http://fixture.test/fetch?url=http://example.test/",
                field_name="url",
                payload="http://169.254.169.254/latest/meta-data/",
                evidence="SSRF marker",
                evidence_type="ssrf_internal_marker",
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)

        self.run_async(run())

    def test_sqli_similarity_ignores_dynamic_noise(self):
        scanner = object.__new__(SQLiScanner)
        baseline = "<html><script>var ts=1778469492;</script><body>Welcome user 1234567890</body></html>"
        equivalent = "<html><script>var ts=1778469500;</script><body>Welcome user 9999999999</body></html>"
        different = "<html><body>Invalid credentials</body></html>"

        self.assertGreater(scanner._body_similarity(baseline, equivalent), 0.90)
        self.assertLess(scanner._body_similarity(baseline, different), 0.80)

    def test_sqli_prioritizes_auth_bypass_payloads_for_login_fields_under_cap(self):
        scanner = object.__new__(SQLiScanner)
        scanner.engine = type("Engine", (), {"max_payloads": 3})()
        payloads = ["'", "''", '"', "1 AND 1=1"]

        prioritized = scanner._prioritize_login_payloads("username", payloads)

        self.assertEqual(prioritized[0], "' OR '1'='1")
        self.assertEqual(len(prioritized), 3)
        self.assertNotIn("'", prioritized)

    def test_sqli_keeps_generic_payload_order_for_non_login_fields(self):
        scanner = object.__new__(SQLiScanner)
        scanner.engine = type("Engine", (), {"max_payloads": 3})()
        payloads = ["'", "''", '"', "1 AND 1=1"]

        prioritized = scanner._prioritize_login_payloads("search", payloads)

        self.assertEqual(prioritized, payloads)

    def test_sqli_boolean_verifier_requires_true_response_to_stay_near_baseline(self):
        async def run():
            scanner = SQLiScanner(_DummyEngine())
            baseline = "Y" * 1000
            true_src = "Y" * 1500
            false_src = "Z" * 1500
            scanner._get_baseline = AsyncMock(return_value=(baseline, {}))
            scanner._apply_payload = AsyncMock(side_effect=[
                (true_src, {}),
                (true_src, {}),
                (false_src, {}),
            ])
            finding = Finding(
                check_type="sqli",
                severity="high",
                url="http://fixture.test/item?id=1",
                field_name="id",
                payload="1 AND 1=1",
                evidence="boolean sqli",
                evidence_type="sqli_boolean",
                evidence_details={
                    "true_payload": "1 AND 1=1",
                    "false_payload": "1 AND 1=2",
                    "baseline_variance": 0,
                },
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_sqli_boolean_verifier_accepts_detection_thresholds(self):
        async def run():
            scanner = SQLiScanner(_DummyEngine())
            baseline = "Y" * 1000
            true_src = "Y" * 990
            false_src = "Z" * 1500
            scanner._get_baseline = AsyncMock(return_value=(baseline, {}))
            scanner._apply_payload = AsyncMock(side_effect=[
                (true_src, {}),
                (true_src, {}),
                (false_src, {}),
            ])
            finding = Finding(
                check_type="sqli",
                severity="high",
                url="http://fixture.test/item?id=1",
                field_name="id",
                payload="1 AND 1=1",
                evidence="boolean sqli",
                evidence_type="sqli_boolean",
                evidence_details={
                    "true_payload": "1 AND 1=1",
                    "false_payload": "1 AND 1=2",
                    "baseline_variance": 0,
                },
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)

        self.run_async(run())

    def test_prompt_template_formatting_preserves_payload_braces(self):
        template = (
            'Generate for "{field_name}" at "{url}". '
            "Keep ;${IFS}id and ;{cat,/etc/passwd} examples."
        )

        rendered = _format_prompt_template(
            template,
            field_name="host",
            url="http://fixture.test/tools",
        )

        self.assertIn('"host"', rendered)
        self.assertIn('"http://fixture.test/tools"', rendered)
        self.assertIn(";${IFS}id", rendered)
        self.assertIn(";{cat,/etc/passwd}", rendered)

    def test_ctf_flag_finder_ignores_lowercase_js_function_blocks(self):
        finder = FlagFinder()
        text = "try{alert('x')} FLAG{real_flag} CTF{also_real} ACSC{UPPER_PREFIX}"

        found = finder.find(text)

        self.assertNotIn("try{alert('x')}", found)
        self.assertIn("FLAG{real_flag}", found)
        self.assertIn("CTF{also_real}", found)
        self.assertIn("ACSC{UPPER_PREFIX}", found)

    def test_page_fingerprint_preserves_distinct_form_actions(self):
        base = "<html><body><h1>Panel</h1><form method='post' action='/admin/users/role'><input name='role'></form></body></html>"
        same_layout_other_action = "<html><body><h1>Panel</h1><form method='post' action='/support'><input name='role'></form></body></html>"

        self.assertNotEqual(
            ScanEngine._page_fingerprint(base),
            ScanEngine._page_fingerprint(same_layout_other_action),
        )

    def test_page_fingerprint_preserves_distinct_url_inputs(self):
        html = "<html><body><h1>Lookup</h1><p>missing token</p></body></html>"

        self.assertNotEqual(
            ScanEngine._page_fingerprint(html, "http://fixture.test/ctf/js-hidden?token=from-script"),
            ScanEngine._page_fingerprint(html, "http://fixture.test/ctf/bundle-hidden?token=from-bundle"),
        )

    def test_merge_url_params_preserves_redirect_source_query_inputs(self):
        params = ScanEngine._merge_url_params([], "http://fixture.test/go?next=/catalog")

        self.assertEqual(params, ["next"])

    def test_merge_url_params_keeps_current_and_queued_query_inputs(self):
        params = ScanEngine._merge_url_params(
            ["page"],
            "http://fixture.test/go?next=/catalog&page=1",
        )

        self.assertEqual(params, ["page", "next"])

    def test_ssti_verifier_uses_detected_probe_expected_value(self):
        async def run():
            scanner = SSTIScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(side_effect=[
                ("<html>baseline</html>", {}),
                ("<html>7045744422742119121</html>", {}),
            ])
            finding = Finding(
                check_type="ssti",
                severity="critical",
                url="http://fixture.test/template?name=guest",
                field_name="name",
                payload="{{2654435761*2654435761}}",
                evidence="SSTI detected",
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)
            scanner._apply_payload.assert_any_await(
                finding.url,
                0,
                "name",
                "{{2654435761*2654435761}}",
                True,
            )

        import asyncio
        asyncio.run(run())

    def test_header_injection_verifier_replays_payload_and_checks_header(self):
        async def run():
            scanner = HeaderInjectionScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(return_value=(
                "ok",
                {"response": {"headers": {"x-wscanhdrinject": "1"}}},
            ))
            finding = Finding(
                check_type="header_injection",
                severity="high",
                url="http://fixture.test/header-echo?ref=safe",
                field_name="ref",
                payload="\r\nX-WscanHdrInject: 1",
                evidence="header injected",
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)
            scanner._apply_payload.assert_awaited_with(
                finding.url,
                0,
                "ref",
                "\r\nX-WscanHdrInject: 1",
                True,
            )

        self.run_async(run())

    def test_open_redirect_verifier_replays_payload_and_checks_location(self):
        async def run():
            scanner = OpenRedirectScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(return_value=(
                "",
                {
                    "response": {
                        "headers": {"Location": "https://evil.wscan-test.example.com"}
                    }
                },
            ))
            finding = Finding(
                check_type="open_redirect",
                severity="medium",
                url="http://fixture.test/go?next=/catalog",
                field_name="next",
                payload="https://evil.wscan-test.example.com",
                evidence="redirected",
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)
            scanner._apply_payload.assert_awaited_with(
                finding.url,
                0,
                "next",
                "https://evil.wscan-test.example.com",
                True,
            )

        self.run_async(run())

    def test_path_traversal_verifier_replays_baseline_and_payload(self):
        async def run():
            scanner = PathTraversalScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(side_effect=[
                ("Documentation for baseline_test_value", {}),
                ("root:x:0:0:root:/root:/bin/bash", {}),
            ])
            finding = Finding(
                check_type="path_traversal",
                severity="high",
                url="http://fixture.test/download?file=readme.txt",
                field_name="file",
                payload="../../../../etc/passwd",
                evidence="passwd leaked",
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)
            scanner._apply_payload.assert_any_await(
                finding.url,
                0,
                "file",
                "baseline_test_value",
                True,
            )
            scanner._apply_payload.assert_any_await(
                finding.url,
                0,
                "file",
                "../../../../etc/passwd",
                True,
            )

        self.run_async(run())

    def test_path_traversal_verifier_rejects_baseline_pattern(self):
        async def run():
            scanner = PathTraversalScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(side_effect=[
                ("root:x:0:0:root:/root:/bin/bash", {}),
                ("root:x:0:0:root:/root:/bin/bash", {}),
            ])
            finding = Finding(
                check_type="path_traversal",
                severity="high",
                url="http://fixture.test/download?file=readme.txt",
                field_name="file",
                payload="../../../../etc/passwd",
                evidence="passwd leaked",
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_os_verifier_replays_baseline_and_payload_body(self):
        async def run():
            scanner = OSInjectionScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(side_effect=[
                ("PING baseline_os_test", {"response": {"body": "PING baseline_os_test"}}),
                ("", {"response": {"body": "uid=1000(wscan) gid=1000(wscan)"}}),
            ])
            finding = Finding(
                check_type="os",
                severity="critical",
                url="http://fixture.test/ping?host=127.0.0.1",
                field_name="host",
                payload="; id",
                evidence="command output",
            )

            result = await scanner.verify_finding(finding)

            self.assertTrue(result)
            scanner._apply_payload.assert_any_await(
                finding.url,
                0,
                "host",
                "baseline_os_test",
                True,
            )
            scanner._apply_payload.assert_any_await(
                finding.url,
                0,
                "host",
                "; id",
                True,
            )

        self.run_async(run())

    def test_os_verifier_rejects_preexisting_command_output(self):
        async def run():
            scanner = OSInjectionScanner(_DummyEngine())
            scanner._apply_payload = AsyncMock(side_effect=[
                ("uid=1000(wscan)", {"response": {"body": "uid=1000(wscan)"}}),
                ("uid=1000(wscan)", {"response": {"body": "uid=1000(wscan)"}}),
            ])
            finding = Finding(
                check_type="os",
                severity="critical",
                url="http://fixture.test/ping?host=127.0.0.1",
                field_name="host",
                payload="; id",
                evidence="command output",
            )

            result = await scanner.verify_finding(finding)

            self.assertFalse(result)

        self.run_async(run())

    def test_network_capture_prefers_target_url_over_later_assets(self):
        capture = NetworkCapture()
        capture.pairs = [
            {
                "request": {"url": "http://fixture.test/template?name=%7B%7B2654435761%2A2654435761%7D%7D"},
                "response": {"url": "http://fixture.test/template?name=%7B%7B2654435761%2A2654435761%7D%7D"},
            },
            {
                "request": {"url": "http://fixture.test/static/app.js"},
                "response": {"url": "http://fixture.test/static/app.js"},
            },
        ]

        pair = capture.latest_for_url(
            "http://fixture.test/template?name=%7B%7B2654435761%2A2654435761%7D%7D"
        )

        self.assertEqual(
            pair["request"]["url"],
            "http://fixture.test/template?name=%7B%7B2654435761%2A2654435761%7D%7D",
        )

    def test_network_capture_can_match_form_action_without_query(self):
        capture = NetworkCapture()
        capture.pairs = [
            {
                "request": {"url": "http://fixture.test/search?q=%3Cscript%3E"},
                "response": {"url": "http://fixture.test/search?q=%3Cscript%3E"},
            },
            {
                "request": {"url": "http://fixture.test/static/app.js"},
                "response": {"url": "http://fixture.test/static/app.js"},
            },
        ]

        pair = capture.latest_for_url("http://fixture.test/search", match_query=False)

        self.assertEqual(pair["request"]["url"], "http://fixture.test/search?q=%3Cscript%3E")

    def test_network_capture_matches_empty_root_path_to_slash(self):
        capture = NetworkCapture()
        capture.pairs = [
            {
                "request": {"url": "http://fixture.test/"},
                "response": {"url": "http://fixture.test/"},
            },
            {
                "request": {"url": "http://fixture.test/static/app.js"},
                "response": {"url": "http://fixture.test/static/app.js"},
            },
        ]

        pair = capture.latest_for_url("http://fixture.test", match_query=False)

        self.assertEqual(pair["request"]["url"], "http://fixture.test/")

    def test_page_level_scanner_uses_document_pair_over_later_asset(self):
        async def run():
            engine = _DummyEngine()
            engine.browser.network = NetworkCapture()
            engine.browser.network.pairs = [
                {
                    "request": {"url": "http://fixture.test/"},
                    "response": {
                        "url": "http://fixture.test/",
                        "headers": {
                            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                            "Content-Security-Policy": "default-src 'self'",
                            "X-Content-Type-Options": "nosniff",
                            "Referrer-Policy": "strict-origin-when-cross-origin",
                            "Permissions-Policy": "geolocation=()",
                            "Cross-Origin-Opener-Policy": "same-origin",
                        },
                    },
                },
                {
                    "request": {"url": "http://fixture.test/static/app.js"},
                    "response": {
                        "url": "http://fixture.test/static/app.js",
                        "headers": {},
                    },
                },
            ]
            scanner = SecurityHeadersScanner(engine)

            findings = await scanner.scan_page("http://fixture.test/")

            self.assertEqual(findings, [])

        self.run_async(run())

    def test_payload_generator_returns_role_specific_models(self):
        gen = PayloadGenerator(
            provider="ollama",
            ollama_model="qwen2.5-coder:latest",
            role_models={"planner": "qwen3:8b", "report": "llama3.1:8b"},
        )

        self.assertEqual(gen.get_model("planner"), "qwen3:8b")
        self.assertEqual(gen.get_model("payload"), "qwen2.5-coder:latest")
        self.assertEqual(gen.get_model("report"), "llama3.1:8b")

    def test_payload_generator_role_context_restores_default_model(self):
        gen = PayloadGenerator(
            provider="ollama",
            ollama_model="qwen2.5-coder:latest",
            role_models={"adaptive": "qwen3:8b"},
        )

        with gen.use_role("adaptive"):
            self.assertEqual(gen.ollama_model, "qwen3:8b")

        self.assertEqual(gen.ollama_model, "qwen2.5-coder:latest")

    def test_sqli_auth_bypass_fresh_verifier_restores_original_browser(self):
        async def run():
            scanner = object.__new__(SQLiScanner)
            original_browser = type(
                "Browser",
                (),
                {
                    "timeout": 10000,
                    "headless": True,
                    "auth_user": "",
                    "auth_pass": "",
                    "proxy": "",
                    "sleep_factor": 1.0,
                },
            )()
            fresh_browser = type(
                "FreshBrowser",
                (),
                {"init": AsyncMock(), "close": AsyncMock()},
            )()
            scanner.browser = original_browser
            scanner._apply_payload = AsyncMock(return_value=("<html>admin</html>", {}))
            scanner._detect_auth_bypass = lambda url, source: (scanner.browser is fresh_browser, "http://fixture/admin")
            finding = Finding(
                check_type="sqli",
                severity="critical",
                url="http://fixture/login",
                field_name="username",
                payload="' OR '1'='1",
                evidence="auth bypass",
                evidence_type="sqli_auth_bypass",
            )

            with patch("wscan.browser.BrowserManager", return_value=fresh_browser):
                result = await scanner._verify_auth_bypass_fresh_context(finding)

            self.assertTrue(result)
            self.assertIs(scanner.browser, original_browser)
            fresh_browser.close.assert_awaited()

        self.run_async(run())

    def run_async(self, coro):
        import asyncio
        return asyncio.run(coro)


if __name__ == "__main__":
    unittest.main()
