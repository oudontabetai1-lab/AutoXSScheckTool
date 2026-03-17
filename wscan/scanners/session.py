"""
Session Management Scanner
Checks cookie security attributes for session tokens (IPA: 1.4 セッション管理の不備).

Per-page check that inspects cookies set by the application and flags ones that:
  - Lack the Secure flag (transmitted over plain HTTP)
  - Lack the HttpOnly flag (accessible by JavaScript → XSS escalation)
  - Have a permissive or missing SameSite attribute (→ CSRF risk)
"""
from typing import TYPE_CHECKING

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# Substrings that suggest a cookie is a session/auth token worth auditing
SESSION_COOKIE_HINTS = {
    "session", "sess", "sessionid", "sessid",
    "sid", "auth", "token", "jwt",
    "access_token", "id_token", "refresh_token",
    "remember", "remember_me",
    "user_id", "userid", "user",
    "phpsessid", "jsessionid",
    "asp.net_sessionid", "asp_net_sessionid",
    "connect.sid",
    "login",
}


class SessionScanner(BaseScanner):
    """Session management / insecure cookie scanner (IPA 1.4)."""

    CHECK_TYPE = "session"
    SEVERITY = "medium"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._reported_cookies: set[str] = set()

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        # Session checks are page-level; no per-field work needed.
        return []

    async def scan_page(self, url: str) -> list[Finding]:
        """Inspect browser cookies after loading the page."""
        findings = []

        if self.monitor:
            await self.monitor.emit_status(f"Session management check on {url}")

        try:
            cookies = await self.browser._context.cookies()
        except Exception:
            return []

        for cookie in cookies:
            name: str = cookie.get("name", "")
            name_key = name.lower()

            # Only audit cookies that look like session / auth tokens
            if not any(hint in name_key for hint in SESSION_COOKIE_HINTS):
                continue

            # Avoid duplicate findings for the same cookie across pages
            if name_key in self._reported_cookies:
                continue

            issues: list[str] = []

            if not cookie.get("secure"):
                issues.append(
                    "Secure flag missing — cookie transmitted over unencrypted HTTP"
                )
            if not cookie.get("httpOnly"):
                issues.append(
                    "HttpOnly flag missing — accessible via JavaScript (amplifies XSS risk)"
                )

            samesite = (cookie.get("sameSite") or "").upper()
            if samesite not in ("STRICT", "LAX"):
                label = samesite if samesite else "unset"
                issues.append(
                    f"SameSite={label} — cookie sent on cross-site requests (CSRF risk)"
                )

            if issues:
                self._reported_cookies.add(name_key)
                pair = self.browser.network.latest() or {}
                finding = await self.record_finding(
                    url=url,
                    field_name=f"Cookie: {name}",
                    payload="(no payload — cookie attribute analysis)",
                    evidence=(
                        f"Insecure session cookie '{name}': "
                        + "; ".join(issues)
                    ),
                    pair=pair,
                    severity="medium",
                )
                findings.append(finding)

        return findings
