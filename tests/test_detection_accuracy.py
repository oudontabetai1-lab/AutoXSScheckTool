"""
Regression tests for detection-accuracy bugs in scanner predicates.

Each test exercises a pure predicate (no browser / no network) and asserts
the FP / FN we want to guard against.
"""
import re
import unittest

from wscan.scanners.xss import XSSScanner
from wscan.scanners.mail_header import _field_name_suggests_mail
from wscan.scanners.open_redirect import (
    _CANARY_HOST,
    _is_external_redirect,
    _location_points_to_canary,
    _redirected_to_canary,
)
from wscan.scanners.sqli import LOGIN_FAILED_PATTERNS


class OpenRedirectHostCheckTests(unittest.TestCase):
    """The canary host must only match an actual redirect destination,
    not its appearance as a query-parameter value on the original page."""

    def test_canary_as_query_value_is_not_a_redirect(self):
        # Non-vulnerable app: param echoed back into the address bar but no
        # redirect occurred.  Old substring check incorrectly flagged this.
        current_url = f"https://victim.test/page?next=https://{_CANARY_HOST}"
        self.assertFalse(_redirected_to_canary(current_url, "https://victim.test/page"))

    def test_canary_as_path_segment_is_not_a_redirect(self):
        current_url = f"https://victim.test/redirect?back=//{_CANARY_HOST}/foo"
        self.assertFalse(_redirected_to_canary(current_url, "https://victim.test/redirect"))

    def test_actual_redirect_to_canary_host(self):
        current_url = f"https://{_CANARY_HOST}/landing"
        self.assertTrue(_redirected_to_canary(current_url, "https://victim.test/page"))

    def test_location_header_points_to_canary(self):
        pair = {"response": {"headers": {"location": f"https://{_CANARY_HOST}/foo"}}}
        self.assertTrue(_location_points_to_canary(pair, "https://victim.test/login"))

    def test_location_header_to_safe_host(self):
        pair = {"response": {"headers": {"location": "https://victim.test/home"}}}
        self.assertFalse(_location_points_to_canary(pair, "https://victim.test/login"))

    def test_relative_location_does_not_match_canary(self):
        # Common safe pattern: server issues a relative Location.
        pair = {"response": {"headers": {"location": f"/internal?u=https://{_CANARY_HOST}"}}}
        self.assertFalse(_location_points_to_canary(pair, "https://victim.test/login"))

    def test_is_external_redirect_combines_both_signals(self):
        pair_safe = {"response": {"headers": {"location": "/home"}}}
        self.assertFalse(
            _is_external_redirect(
                pair_safe,
                f"https://victim.test/?next=https://{_CANARY_HOST}",
                "https://victim.test/",
            )
        )
        pair_bad = {"response": {"headers": {"location": f"https://{_CANARY_HOST}/"}}}
        self.assertTrue(
            _is_external_redirect(pair_bad, "https://victim.test/login", "https://victim.test/login")
        )


class MailHeaderFieldHintTests(unittest.TestCase):
    """Short hints like ``to`` / ``cc`` / ``bcc`` / ``from`` must NOT match
    arbitrary fields whose names happen to contain those letters."""

    def test_mail_related_fields_match(self):
        for name in [
            "email", "Email", "user_email", "contact_email",
            "to", "To", "from", "cc", "bcc",
            "reply_to", "reply-to", "subject", "sender", "recipient",
            "mailto", "contact.to", "mail_cc1",
        ]:
            with self.subTest(name=name):
                self.assertTrue(_field_name_suggests_mail(name))

    def test_unrelated_fields_do_not_match(self):
        # These were previously matched because of substring search on the
        # tokens "to" / "cc" / "from" / "bcc".
        for name in [
            "token", "csrf_token", "totp", "photo", "stockton",
            "account", "accept", "captcha", "address",  # contained "cc"
            "fromage", "fromtimer",                       # contained "from"
            "bccount",                                    # contained "bcc"
            "username", "password", "title", "body",
            "search", "query", "id",
        ]:
            with self.subTest(name=name):
                self.assertFalse(_field_name_suggests_mail(name))


class SqliLoginFailedPatternTests(unittest.TestCase):
    """The login-failed regex set is used to *exclude* false-positive auth
    bypasses.  Overly broad patterns hide real bypasses (false negatives)."""

    @staticmethod
    def _matches(text: str) -> bool:
        for pat in LOGIN_FAILED_PATTERNS:
            if re.search(pat, text, re.IGNORECASE | re.DOTALL):
                return True
        return False

    def test_real_login_failure_messages_still_match(self):
        for msg in [
            "Invalid username or password",
            "Login failed. Please try again.",
            "Authentication failed",
            "Incorrect password",
            "User not found",
            "Access denied",
            "Bad credentials",
            "Username is incorrect",
            "Please re-enter your password",
        ]:
            with self.subTest(msg=msg):
                self.assertTrue(self._matches(msg), msg)

    def test_authenticated_dashboard_does_not_falsely_match(self):
        # Realistic admin/dashboard copy that previously tripped the loose
        # `(please |try again|retry|re-enter)` and `error.*log(in|on)` rules.
        for msg in [
            "Welcome, admin. Please select a project from the sidebar.",
            "Dashboard — recent error logs are below.",
            "Please contact support if anything looks off.",
            "Server error log retention is 30 days.",
            "Try our new analytics dashboard!",
            "<h1>Admin panel</h1><p>Logged in as root</p>",
        ]:
            with self.subTest(msg=msg):
                self.assertFalse(self._matches(msg), msg)


class XSSReflectionEscapingTests(unittest.TestCase):
    """Bare XSS markers (``alert(`` / ``onload=`` / ``onerror=``) carry no
    HTML-structural character, so they survive ``html.escape()`` verbatim.

    A correctly-escaped page that echoes user input must NOT be reported: the
    angle brackets / quotes the payload relied on were neutralised, so the
    marker is inert text. Failing to account for this produced false positives
    on every escaped reflection (search, greeting, profile name, …).
    """

    def setUp(self):
        self.scanner = object.__new__(XSSScanner)

    def test_escaped_script_payload_in_text_is_not_flagged(self):
        payload = "<script>alert(1)</script>"
        baseline = "<html><body><p>Hello, guest! Welcome back.</p></body></html>"
        # Server HTML-escaped the payload: '<' and '>' became entities, but the
        # literal substring 'alert(' survives.
        escaped = "<html><body><p>Hello, &lt;script&gt;alert(1)&lt;/script&gt;! Welcome back.</p></body></html>"

        self.assertEqual(self.scanner._analyze_reflection(escaped, payload, baseline), {})

    def test_escaped_event_handler_payload_in_attribute_is_not_flagged(self):
        payload = '" onmouseover=alert(1)'
        baseline = '<html><body><input name="q" value=""></body></html>'
        # The breaking quote was encoded to &quot; — 'onmouseover=' survives but
        # cannot escape the attribute, so it is not exploitable.
        escaped = '<html><body><input name="q" value="&quot; onmouseover=alert(1)"></body></html>'

        self.assertEqual(self.scanner._analyze_reflection(escaped, payload, baseline), {})

    def test_raw_unescaped_payload_is_still_flagged(self):
        payload = "<svg onload=alert(1)>"
        baseline = "<html><body><p>Search</p></body></html>"
        # Reflected verbatim — a real reflected XSS that must NOT be suppressed.
        raw = "<html><body><p>Search result: <svg onload=alert(1)></p></body></html>"

        reflection = self.scanner._analyze_reflection(raw, payload, baseline)

        self.assertTrue(reflection)
        self.assertTrue(reflection.get("raw_payload_present"))

    def test_marker_surviving_with_real_breakout_is_flagged(self):
        # Payload partially mutated so the verbatim string is absent, but the
        # raw '<' it introduced survives — a genuine breakout that must fire.
        payload = "<img src=x onerror=alert(1)>"
        baseline = "<html><body><p>Comments</p></body></html>"
        mutated = "<html><body><p>Comment: <img src=x onerror=alert(1) data-z></p></body></html>"

        reflection = self.scanner._analyze_reflection(mutated, payload, baseline)

        self.assertTrue(reflection)


class StoredXSSMarkerClassificationTests(unittest.TestCase):
    """Stored-XSS の実行可能/無害化の判定。マーカーは英数字のみのため、
    旧実装は ``html.escape(marker) == marker`` で in_raw == in_encoded となり、
    エンコード(無害)格納まで常に critical/executable と誤分類していた。"""

    def setUp(self):
        from wscan.scanners.stored_xss import classify_stored_marker
        self.classify = classify_stored_marker
        self.marker = "wsxss1a2b3c4d"
        self.payload = f'<script id="{self.marker}">/*{self.marker}*/</script>'

    def test_raw_script_tag_is_executable(self):
        # サーバが生のまま反映 → DOM 直列化で <script id="..."> が残る = 実行可能。
        src = f'<html><body><script id="{self.marker}">/*{self.marker}*/</script></body></html>'
        v = self.classify(self.marker, self.payload, src)
        self.assertTrue(v["found"])
        self.assertTrue(v["in_raw"])
        self.assertTrue(v["executable"])

    def test_html_encoded_storage_is_not_executable(self):
        # サーバがHTMLエンコードしてテキスト化 → マーカーは在るが生タグは無い = 無害。
        import html as _html
        src = f"<html><body><p>{_html.escape(self.payload)}</p></body></html>"
        v = self.classify(self.marker, self.payload, src)
        self.assertTrue(v["found"])
        self.assertFalse(v["in_raw"])
        self.assertTrue(v["in_encoded"])
        self.assertFalse(v["executable"])  # ← 旧実装はここが True だった

    def test_marker_absent(self):
        v = self.classify(self.marker, self.payload, "<html>nothing here</html>")
        self.assertFalse(v["found"])
        self.assertFalse(v["executable"])


if __name__ == "__main__":
    unittest.main()
