"""
Session Management Scanner
Checks cookie security attributes for session tokens (IPA: 1.4 セッション管理の不備).

Per-page check that inspects cookies set by the application and flags ones that:
  - Lack the Secure flag (transmitted over plain HTTP)
  - Lack the HttpOnly flag (accessible by JavaScript → XSS escalation)
  - Have a permissive or missing SameSite attribute (→ CSRF risk)
"""
from typing import TYPE_CHECKING

from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    PayloadShape, Prerequisite, ScannerContract, StateChangeClass, TransportKind,
    ValueKind,
)

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

    HAS_PAGE_LEVEL = True
    CHECK_TYPE = "session"
    CONTRACT = ScannerContract(
        execution_kinds=frozenset({ExecutionKind.PAGE_ANALYSIS}),
        capabilities=(
            CarrierCapability(
                carrier=Carrier.QUERY, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.FORM, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.JSON, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.XML, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.MULTIPART, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.HEADER, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.COOKIE, state=CapabilityState.UNSUPPORTED,
                reason="cookie を解析するが注入しない",
            ),
            CarrierCapability(
                carrier=Carrier.PATH, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.GRAPHQL, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.WEBSOCKET, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
        ),
        state_change=StateChangeClass.READ_ONLY,
        # scan_page が cookie を browser._context.cookies() からのみ取得するため browser 必須。
        prerequisites=frozenset({Prerequisite.BROWSER}),
        cost=CostClass.LOW,
    )

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
        except Exception as exc:
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] session: failed to read cookies on {url}: {exc}"
                )
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

            issues = self._cookie_issues(cookie)

            if issues:
                self._reported_cookies.add(name_key)
                pair = self.current_page_pair(url)
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
                    confidence="likely",
                    evidence_type="session_cookie_attributes",
                    evidence_details={
                        "cookie_name": name,
                        "issues": issues,
                        "secure": bool(cookie.get("secure")),
                        "httpOnly": bool(cookie.get("httpOnly")),
                        "sameSite": cookie.get("sameSite") or "",
                        "domain": cookie.get("domain", ""),
                        "path": cookie.get("path", ""),
                    },
                )
                findings.append(finding)

        return findings

    async def verify_finding(self, finding: Finding) -> bool | None:
        if finding.evidence_type != "session_cookie_attributes":
            return None

        details = getattr(finding, "evidence_details", {}) or {}
        cookie_name = details.get("cookie_name") or finding.field_name.replace("Cookie:", "").strip()
        expected_issues = set(details.get("issues") or [])
        if not cookie_name:
            return None

        try:
            cookies = await self.browser._context.cookies()
        except Exception:
            return None

        for cookie in cookies:
            if (cookie.get("name", "") or "").lower() != cookie_name.lower():
                continue
            current_issues = set(self._cookie_issues(cookie))
            return bool(current_issues) and (not expected_issues or expected_issues.issubset(current_issues))

        return False

    def _cookie_issues(self, cookie: dict) -> list[str]:
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
        # SameSite=None is acceptable ONLY when paired with the Secure flag
        # (required by modern browsers for cross-site APIs). Flag it only
        # when Secure is absent.
        if samesite in ("STRICT", "LAX"):
            pass
        elif samesite == "NONE":
            if not cookie.get("secure"):
                issues.append(
                    "SameSite=None without Secure — modern browsers reject "
                    "this and it still permits CSRF over HTTP"
                )
        else:
            label = samesite if samesite else "unset"
            issues.append(
                f"SameSite={label} — cookie sent on cross-site requests (CSRF risk)"
            )

        return issues
