"""
Privilege Escalation / Unauthorized Access Scanner
====================================================
Simulates real-world attacker behavior by testing whether authenticated
resources can be accessed:
  1. Without any session (unauthenticated access)
  2. With a low-privilege session (vertical privilege escalation)

Check types emitted
-------------------
  privesc_unauth   — resource accessible without any credentials
  privesc_vertical — low-privilege session can reach a high-privilege resource

Trigger conditions
------------------
  • --cookie / --cookie-file provides a high-privilege (authenticated) session.
  • --low-priv-cookies / --low-priv-cookie-file provides a second, lower-
    privilege session used for the vertical escalation test.
  • At minimum the scanner will flag privileged-looking paths (admin, dashboard,
    manage, …) that return HTTP 200 without any authentication.
"""
import re
from typing import TYPE_CHECKING, Optional
from urllib.parse import urlparse, urlunparse

import httpx

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# ---------------------------------------------------------------------------
# Heuristics
# ---------------------------------------------------------------------------

# URL path segments that suggest a protected / privileged resource
PROTECTED_PATH_RE = re.compile(
    r"/(admin|manage|dashboard|settings|profile|account|config|setup"
    r"|users?|members?|orders?|payment|billing|api/v\d|private|secure"
    r"|internal|panel|control|portal|staff|operator|moderator|superuser"
    r"|root|backup|logs?|audit|reports?|analytics|export|import)",
    re.IGNORECASE,
)

# Keywords that indicate the server responded with a login / auth-required page
# (i.e. soft-redirect: returns 200 but shows a login form or "access denied" message)
LOGIN_GATE_RE = re.compile(
    r"(log\s*in|sign\s*in|please.*authenticate|authentication.*required"
    r"|you.*must.*log\s*in|unauthorized|access.*denied|forbidden"
    r"|session.*expired|セッション.*切れ|ログイン.*してください|認証.*必要"
    r"|ログインが必要|権限がありません|アクセス.*禁止)",
    re.IGNORECASE,
)

# Common HTTP headers used by the scanner
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class PrivEscScanner(BaseScanner):
    """
    Tests each crawled URL for unauthorized / under-authorized access.

    This is a *page-level* scanner — scan_field() is a no-op.
    All logic lives in scan_page().
    """

    CHECK_TYPE = "privesc"
    SEVERITY = "high"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._tested_urls: set[str] = set()

    # ------------------------------------------------------------------
    # BaseScanner interface
    # ------------------------------------------------------------------

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        return []  # privilege escalation is URL-level, not field-level

    async def scan_page(self, url: str) -> list[Finding]:
        """
        Perform unauthenticated and (optionally) low-privilege access tests.
        """
        if url in self._tested_urls:
            return []
        self._tested_urls.add(url)

        has_auth = bool(getattr(self.engine, "cookies", "") or
                        getattr(self.engine, "cookie_list", []))
        is_privileged = bool(PROTECTED_PATH_RE.search(urlparse(url).path))

        # Skip if neither condition triggers the test
        if not has_auth and not is_privileged:
            return []

        findings: list[Finding] = []
        timeout = float(getattr(self.engine, "timeout", 30))

        # ── Test 1: Unauthenticated access ────────────────────────────
        unauth_finding = await self._test_unauth(url, has_auth, is_privileged, timeout)
        if unauth_finding:
            findings.append(unauth_finding)
            await self._emit(unauth_finding)

        # ── Test 2: Low-privilege vertical escalation ─────────────────
        low_priv_cookies: str = getattr(self.engine, "low_priv_cookies", "")
        if low_priv_cookies and is_privileged:
            lp_finding = await self._test_lowpriv(url, low_priv_cookies, timeout)
            if lp_finding:
                findings.append(lp_finding)
                await self._emit(lp_finding)

        # ── Test 3: Horizontal privilege escalation (IDOR) ────────────
        if has_auth:
            cookies_str = (
                getattr(self.engine, "cookies", "")
                or "; ".join(
                    f"{c['name']}={c['value']}"
                    for c in getattr(self.engine, "cookie_list", [])
                    if c.get("name") and c.get("value") is not None
                )
            )
            if cookies_str:
                horiz_findings = await self._test_horizontal_privesc(url, cookies_str, timeout)
                for hf in horiz_findings:
                    findings.append(hf)
                    await self._emit(hf)

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _test_unauth(
        self,
        url: str,
        has_auth: bool,
        is_privileged: bool,
        timeout: float,
    ) -> Optional[Finding]:
        """Send a bare (no-cookie) GET request and analyse the response."""
        try:
            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=timeout,
                verify=False,
                headers=_HEADERS,
            ) as client:
                resp = await client.get(url)
                status = resp.status_code
                body = resp.text[:8000]
        except Exception:
            return None

        # Redirect to login or explicit auth error → properly protected
        if status in (301, 302, 303, 307, 308, 401, 403):
            return None

        # Non-2xx → no useful signal
        if not (200 <= status < 300):
            return None

        # 200 but page itself shows a login gate → protected via soft-redirect
        if LOGIN_GATE_RE.search(body):
            return None

        path = urlparse(url).path

        if has_auth and is_privileged:
            # We are authenticated (high-priv) but this URL is also reachable
            # without any session cookies → access control missing
            return Finding(
                check_type="privesc_unauth",
                severity="high",
                url=url,
                field_name="(URL-level access control)",
                payload="unauthenticated GET",
                evidence=(
                    f"Unauthenticated access: '{path}' returned HTTP {status} "
                    f"without any session cookies. "
                    f"This appears to be a privileged resource that should require authentication."
                ),
                request={"url": url, "method": "GET", "headers": {}},
                response={"status": status, "url": url},
            )

        if not has_auth and is_privileged:
            # No auth cookies at all, but path looks privileged
            return Finding(
                check_type="privesc_unauth",
                severity="medium",
                url=url,
                field_name="(URL-level access control)",
                payload="unauthenticated GET",
                evidence=(
                    f"Potentially exposed privileged path: '{path}' returned HTTP {status} "
                    f"without authentication. Verify this resource is intentionally public."
                ),
                request={"url": url, "method": "GET", "headers": {}},
                response={"status": status, "url": url},
            )

        return None

    async def _test_lowpriv(
        self,
        url: str,
        low_priv_cookies: str,
        timeout: float,
    ) -> Optional[Finding]:
        """Send a request with low-privilege cookies and analyse the response."""
        try:
            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=timeout,
                verify=False,
                headers={**_HEADERS, "Cookie": low_priv_cookies},
            ) as client:
                resp = await client.get(url)
                status = resp.status_code
                body = resp.text[:8000]
        except Exception:
            return None

        if status in (301, 302, 303, 307, 308, 401, 403):
            return None
        if not (200 <= status < 300):
            return None
        if LOGIN_GATE_RE.search(body):
            return None

        path = urlparse(url).path
        return Finding(
            check_type="privesc_vertical",
            severity="critical",
            url=url,
            field_name="(URL-level privilege escalation)",
            payload="low-privilege session cookie",
            evidence=(
                f"Vertical privilege escalation: low-privilege session can access "
                f"'{path}' (HTTP {status}). "
                f"This resource appears to require higher privileges but is accessible "
                f"with the provided low-privilege credentials."
            ),
            request={"url": url, "method": "GET", "headers": {"Cookie": "<low-priv-token>"}},
            response={"status": status, "url": url},
        )

    # ------------------------------------------------------------------
    # S-6: Horizontal privilege escalation (IDOR)
    # ------------------------------------------------------------------

    async def _test_horizontal_privesc(
        self,
        url: str,
        cookies: str,
        timeout: float,
    ) -> list[Finding]:
        """
        Detect Insecure Direct Object Reference (IDOR) by enumerating
        numeric IDs in the URL path and checking if adjacent IDs are
        accessible with the same session.

        Example: /user/123/profile → try /user/122/profile, /user/124/profile
        """
        parsed = urlparse(url)
        path = parsed.path

        # Find all numeric path segments
        segments = path.split("/")
        findings: list[Finding] = []

        for seg_idx, seg in enumerate(segments):
            if not seg.isdigit():
                continue
            original_id = int(seg)
            # Try adjacent IDs (±1, ±5)
            candidate_ids = {original_id - 1, original_id + 1,
                             original_id - 5, original_id + 5}
            candidate_ids.discard(original_id)
            candidate_ids = {i for i in candidate_ids if i > 0}

            # Get our own response to use as baseline
            try:
                async with httpx.AsyncClient(
                    follow_redirects=True,
                    timeout=timeout,
                    verify=False,
                    headers={**_HEADERS, "Cookie": cookies},
                ) as client:
                    own_resp = await client.get(url)
                    own_status = own_resp.status_code
                    own_body = own_resp.text[:8000]
            except Exception:
                continue

            if own_status not in range(200, 300):
                continue

            for candidate_id in candidate_ids:
                new_segments = list(segments)
                new_segments[seg_idx] = str(candidate_id)
                new_path = "/".join(new_segments)
                candidate_url = urlunparse(parsed._replace(path=new_path))

                try:
                    async with httpx.AsyncClient(
                        follow_redirects=True,
                        timeout=timeout,
                        verify=False,
                        headers={**_HEADERS, "Cookie": cookies},
                    ) as client:
                        resp = await client.get(candidate_url)
                        status = resp.status_code
                        body = resp.text[:8000]
                except Exception:
                    continue

                if status not in range(200, 300):
                    continue
                if LOGIN_GATE_RE.search(body):
                    continue

                # Heuristic: significant overlap with own response could mean same page,
                # but different content means we actually got another resource
                if len(body) < 100:
                    continue

                finding = Finding(
                    check_type="privesc_horizontal",
                    severity="high",
                    url=url,
                    field_name=f"(URL path segment: {seg})",
                    payload=candidate_url,
                    evidence=(
                        f"Horizontal privilege escalation (IDOR): "
                        f"Changed ID {original_id}→{candidate_id} in '{path}' "
                        f"returned HTTP {status}. Possible access to another user's resource."
                    ),
                    request={"url": candidate_url, "method": "GET",
                             "headers": {"Cookie": "<session-token>"}},
                    response={"status": status, "url": candidate_url},
                )
                findings.append(finding)
                break  # One confirmation per segment is enough

        return findings

    async def _emit(self, finding: Finding) -> None:
        """Push finding to the engine and monitor."""
        self.findings.append(finding)
        self.engine.all_findings.append(finding)
        if self.monitor:
            await self.monitor.emit_finding(finding.to_dict())
