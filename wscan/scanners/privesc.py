"""
Privilege Escalation / Unauthorized Access Scanner
====================================================
Simulates real-world attacker behavior by testing whether authenticated
resources can be accessed:
  1. Without any session (unauthenticated access)
  2. With a low-privilege session (vertical privilege escalation)
  3. By enumerating numeric/UUID IDs in URLs (IDOR – horizontal escalation)
  4. By probing query/body parameters that carry user/object identifiers (③)
  5. With a second user-account session (cross-account IDOR / vertical test)

Check types emitted
-------------------
  privesc_unauth      — resource accessible without any credentials
  privesc_vertical    — low-privilege session can reach a high-privilege resource
  privesc_horizontal  — IDOR via URL path ID manipulation
  privesc_param_idor  — IDOR via query/body parameter manipulation (NEW ③)
  privesc_cross_acct  — cross-account access confirmed with a second session (NEW A)

Trigger conditions
------------------
  • --cookie / --cookie-file provides a high-privilege (authenticated) session.
  • --low-priv-cookies / --low-priv-cookie-file provides a second, lower-
    privilege session used for the vertical escalation test.
  • --accounts "user1:pass1,user2:pass2" provides multiple named accounts; the
    engine resolves each account to a cookie string and passes them via
    engine.account_sessions (list[dict] with keys: username, cookies).
  • At minimum the scanner will flag privileged-looking paths (admin, dashboard,
    manage, …) that return HTTP 200 without any authentication.
"""
from __future__ import annotations

import re
import uuid
from difflib import SequenceMatcher
from typing import TYPE_CHECKING, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

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
LOGIN_GATE_RE = re.compile(
    r"(log\s*in|sign\s*in|please.*authenticate|authentication.*required"
    r"|you.*must.*log\s*in|unauthorized|access.*denied|forbidden"
    r"|session.*expired|セッション.*切れ|ログイン.*してください|認証.*必要"
    r"|ログインが必要|権限がありません|アクセス.*禁止)",
    re.IGNORECASE,
)

# Query-parameter names that commonly carry user/object identifiers
_IDOR_PARAM_RE = re.compile(
    r"^(user_?id|userid|owner_?id|ownerid|account_?id|accountid|member_?id|memberid"
    r"|order_?id|orderid|file_?id|fileid|doc_?id|docid|record_?id|recordid"
    r"|profile_?id|profileid|customer_?id|customerid|id|uid|oid|pid|fid)$",
    re.IGNORECASE,
)

# UUID pattern (any version)
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


# ---------------------------------------------------------------------------
# Helper — mutate one hex character of a UUID
# ---------------------------------------------------------------------------

def _mutate_uuid(u: str) -> str:
    """Return a UUID with the last character of the node section changed."""
    # Replace last hex digit with a different one
    parts = list(u)
    idx = len(u) - 1
    original = u[idx]
    replacement = "a" if original != "a" else "b"
    parts[idx] = replacement
    return "".join(parts)


def _normalize_response_body(body: str) -> str:
    """Remove common dynamic noise before comparing authorization responses."""
    text = body.lower()
    text = re.sub(r"\b[0-9a-f]{8,}\b", "<hex>", text)
    text = re.sub(r"\b\d{5,}\b", "<num>", text)
    text = re.sub(r"(csrf|nonce|token|timestamp|ts)[\"'=:\s-]+[^\"'<>\s]+", r"\1=<dyn>", text)
    text = re.sub(r"\s+", " ", text)
    return text[:6000]


def _body_similarity(left: str, right: str) -> float:
    if not left or not right:
        return 0.0
    return SequenceMatcher(None, _normalize_response_body(left), _normalize_response_body(right)).ratio()


def _identity_markers(username: str) -> set[str]:
    """Return stable owner markers that should not be visible to another account."""
    raw = (username or "").strip().lower()
    if not raw:
        return set()
    markers = {raw}
    if "@" in raw:
        markers.add(raw.split("@", 1)[0])
    # Avoid overly generic markers that appear in navigation or labels.
    return {m for m in markers if len(m) >= 4 and m not in {"user", "admin", "test", "demo"}}


def _role_rank(role: str) -> int:
    role_l = (role or "").strip().lower()
    if role_l in {"root", "superuser", "owner"}:
        return 4
    if role_l in {"admin", "administrator"}:
        return 3
    if role_l in {"staff", "operator", "moderator", "manager"}:
        return 2
    if role_l in {"registered", "member", "user"}:
        return 1
    return 0


def _url_has_object_identifier(url: str) -> bool:
    parsed = urlparse(url)
    if any(seg.isdigit() or _UUID_RE.match(seg) for seg in parsed.path.split("/") if seg):
        return True
    qs = parse_qs(parsed.query, keep_blank_values=True)
    return any(_IDOR_PARAM_RE.match(param) for param in qs)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class PrivEscScanner(BaseScanner):
    """
    Tests each crawled URL for unauthorized / under-authorized access.

    This is primarily a *page-level* scanner — scan_field() is a no-op.
    All logic lives in scan_page().
    """

    CHECK_TYPE = "privesc"
    SEVERITY = "high"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._tested_urls: set[str] = set()
        self._tested_params: set[tuple] = set()  # (url_without_qs, param_name)

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
        Perform unauthenticated, low-privilege, IDOR, and cross-account tests.
        """
        if url in self._tested_urls:
            return []
        self._tested_urls.add(url)

        has_auth = bool(getattr(self.engine, "cookies", "") or
                        getattr(self.engine, "cookie_list", []))
        is_privileged = bool(PROTECTED_PATH_RE.search(urlparse(url).path))

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

        # Build the primary session cookie string
        cookies_str = self._get_primary_cookies()

        if has_auth and cookies_str:
            # ── Test 3: Horizontal privilege escalation (path IDOR) ───
            horiz_findings = await self._test_horizontal_privesc(url, cookies_str, timeout)
            for hf in horiz_findings:
                findings.append(hf)
                await self._emit(hf)

            # ── Test 4: Query-parameter IDOR (③) ──────────────────────
            param_findings = await self._test_param_idor(url, cookies_str, timeout)
            for pf in param_findings:
                findings.append(pf)
                await self._emit(pf)

        # ── Test 5: Cross-account IDOR / vertical (A) ─────────────────
        account_sessions: list[dict] = getattr(self.engine, "account_sessions", [])
        if len(account_sessions) >= 2 and is_privileged:
            cross_findings = await self._test_cross_account(
                url, account_sessions, timeout
            )
            for cf in cross_findings:
                findings.append(cf)
                await self._emit(cf)

        return findings

    # ------------------------------------------------------------------
    # Cookie helpers
    # ------------------------------------------------------------------

    def _get_primary_cookies(self) -> str:
        cookies_str = getattr(self.engine, "cookies", "") or ""
        if not cookies_str:
            cookie_list = getattr(self.engine, "cookie_list", []) or []
            cookies_str = "; ".join(
                f"{c['name']}={c['value']}"
                for c in cookie_list
                if c.get("name") and c.get("value") is not None
            )
        return cookies_str

    def _client_proxy_kwargs(self) -> dict:
        proxy = getattr(self.engine, "proxy", "") or None
        return {"proxy": proxy} if proxy else {}

    # ------------------------------------------------------------------
    # Test 1: Unauthenticated access
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
                **self._client_proxy_kwargs(),
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

        if has_auth and is_privileged:
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

    # ------------------------------------------------------------------
    # Test 2: Low-privilege vertical escalation
    # ------------------------------------------------------------------

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
                **self._client_proxy_kwargs(),
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
    # Test 3: S-6 — Horizontal privilege escalation via path ID
    # ------------------------------------------------------------------

    async def _test_horizontal_privesc(
        self,
        url: str,
        cookies: str,
        timeout: float,
    ) -> list[Finding]:
        """
        Detect IDOR by enumerating numeric and UUID IDs in the URL path.
        """
        parsed = urlparse(url)
        path = parsed.path
        segments = path.split("/")
        findings: list[Finding] = []

        for seg_idx, seg in enumerate(segments):
            if not seg:
                continue

            # ── Numeric ID ──────────────────────────────────────────────
            if seg.isdigit():
                original_id = int(seg)
                candidate_ids = {
                    original_id - 1, original_id + 1,
                    original_id - 5, original_id + 5,
                }
                candidate_ids.discard(original_id)
                candidate_ids = {i for i in candidate_ids if i > 0}

                own_status, own_body = await self._get(url, cookies, timeout)
                if own_status not in range(200, 300):
                    continue

                for cid in candidate_ids:
                    new_segs = list(segments)
                    new_segs[seg_idx] = str(cid)
                    candidate_url = urlunparse(parsed._replace(path="/".join(new_segs)))
                    status, body = await self._get(candidate_url, cookies, timeout)

                    if status not in range(200, 300):
                        continue
                    if LOGIN_GATE_RE.search(body):
                        continue
                    if len(body) < 100:
                        continue

                    findings.append(Finding(
                        check_type="privesc_horizontal",
                        severity="high",
                        url=url,
                        field_name=f"(URL path segment: {seg})",
                        payload=candidate_url,
                        evidence=(
                            f"Horizontal privilege escalation (IDOR): "
                            f"Changed numeric ID {original_id}→{cid} in '{path}' "
                            f"returned HTTP {status} ({len(body)} bytes). "
                            f"Possible access to another user's resource."
                        ),
                        request={"url": candidate_url, "method": "GET",
                                 "headers": {"Cookie": "<session-token>"}},
                        response={"status": status, "url": candidate_url},
                    ))
                    break  # one confirmation per segment

            # ── UUID in path ────────────────────────────────────────────
            elif _UUID_RE.match(seg):
                mutated = _mutate_uuid(seg)
                new_segs = list(segments)
                new_segs[seg_idx] = mutated
                candidate_url = urlunparse(parsed._replace(path="/".join(new_segs)))
                status, body = await self._get(candidate_url, cookies, timeout)

                if status not in range(200, 300):
                    continue
                if LOGIN_GATE_RE.search(body):
                    continue
                if len(body) < 100:
                    continue

                findings.append(Finding(
                    check_type="privesc_horizontal",
                    severity="high",
                    url=url,
                    field_name=f"(URL path UUID: {seg[:8]}...)",
                    payload=candidate_url,
                    evidence=(
                        f"Horizontal privilege escalation (UUID IDOR): "
                        f"Mutated UUID '{seg[:8]}...' → '{mutated[:8]}...' in path "
                        f"returned HTTP {status}. "
                        f"Possible access to another user's resource via UUID guessing."
                    ),
                    request={"url": candidate_url, "method": "GET",
                             "headers": {"Cookie": "<session-token>"}},
                    response={"status": status, "url": candidate_url},
                ))

        return findings

    # ------------------------------------------------------------------
    # Test 4: Query-parameter IDOR (③)
    # ------------------------------------------------------------------

    async def _test_param_idor(
        self,
        url: str,
        cookies: str,
        timeout: float,
    ) -> list[Finding]:
        """
        Detect IDOR via numeric and UUID query parameters.
        e.g. /orders?order_id=123 → try order_id=122, order_id=124
        """
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        findings: list[Finding] = []

        for param, values in qs.items():
            if not _IDOR_PARAM_RE.match(param):
                continue
            for val in values:
                dedup_key = (parsed._replace(query="").geturl(), param)
                if dedup_key in self._tested_params:
                    continue
                self._tested_params.add(dedup_key)

                # ── Numeric parameter value ─────────────────────────────
                if val.isdigit():
                    original_id = int(val)
                    candidates = [
                        original_id - 1, original_id + 1,
                        original_id - 5, original_id + 5,
                    ]

                    own_status, own_body = await self._get(url, cookies, timeout)
                    if own_status not in range(200, 300):
                        continue

                    for cid in candidates:
                        if cid <= 0 or cid == original_id:
                            continue
                        new_qs = dict(qs)
                        new_qs[param] = [str(cid)]
                        candidate_url = urlunparse(
                            parsed._replace(query=urlencode(new_qs, doseq=True))
                        )
                        status, body = await self._get(candidate_url, cookies, timeout)

                        if status not in range(200, 300):
                            continue
                        if LOGIN_GATE_RE.search(body):
                            continue
                        if len(body) < 50:
                            continue

                        findings.append(Finding(
                            check_type="privesc_param_idor",
                            severity="high",
                            url=url,
                            field_name=f"(query param: {param}={val})",
                            payload=f"?{param}={cid}",
                            evidence=(
                                f"Parameter IDOR: Changed query parameter "
                                f"'{param}' from {original_id} to {cid} — "
                                f"server returned HTTP {status} ({len(body)} bytes). "
                                f"Possible access to another user's data via parameter manipulation."
                            ),
                            request={"url": candidate_url, "method": "GET",
                                     "headers": {"Cookie": "<session-token>"}},
                            response={"status": status, "url": candidate_url},
                        ))
                        break

                # ── UUID parameter value ────────────────────────────────
                elif _UUID_RE.match(val):
                    mutated = _mutate_uuid(val)
                    new_qs = dict(qs)
                    new_qs[param] = [mutated]
                    candidate_url = urlunparse(
                        parsed._replace(query=urlencode(new_qs, doseq=True))
                    )
                    status, body = await self._get(candidate_url, cookies, timeout)

                    if status not in range(200, 300):
                        continue
                    if LOGIN_GATE_RE.search(body):
                        continue
                    if len(body) < 50:
                        continue

                    findings.append(Finding(
                        check_type="privesc_param_idor",
                        severity="high",
                        url=url,
                        field_name=f"(query param UUID: {param})",
                        payload=f"?{param}={mutated}",
                        evidence=(
                            f"Parameter UUID-IDOR: Changed query parameter "
                            f"'{param}' UUID from '{val[:8]}...' to '{mutated[:8]}...' — "
                            f"server returned HTTP {status} ({len(body)} bytes). "
                            f"Possible access to another object via UUID guessing."
                        ),
                        request={"url": candidate_url, "method": "GET",
                                 "headers": {"Cookie": "<session-token>"}},
                        response={"status": status, "url": candidate_url},
                    ))

        return findings

    # ------------------------------------------------------------------
    # Test 5: Cross-account IDOR / vertical escalation (A)
    # ------------------------------------------------------------------

    async def _test_cross_account(
        self,
        url: str,
        account_sessions: list[dict],
        timeout: float,
    ) -> list[Finding]:
        """
        Using the set of authenticated account sessions, test whether account B
        can access resources owned by account A (horizontal escalation) and
        whether lower-indexed accounts can reach privileged paths (vertical).

        account_sessions is a list of dicts:
            {"username": str, "cookies": str, "role": str (optional)}
        """
        findings: list[Finding] = []
        path = urlparse(url).path
        is_privileged = bool(PROTECTED_PATH_RE.search(path))

        for i, account_a in enumerate(account_sessions):
            cookies_a = account_a.get("cookies", "")
            user_a = account_a.get("username", f"account[{i}]")
            role_a = account_a.get("role", "")

            if not cookies_a:
                continue

            # Fetch the resource as account A
            status_a, body_a = await self._get(url, cookies_a, timeout)
            if status_a not in range(200, 300) or LOGIN_GATE_RE.search(body_a):
                continue

            for j, account_b in enumerate(account_sessions):
                if i == j:
                    continue
                cookies_b = account_b.get("cookies", "")
                user_b = account_b.get("username", f"account[{j}]")
                role_b = account_b.get("role", "")
                if not cookies_b:
                    continue

                status_b, body_b = await self._get(url, cookies_b, timeout)

                if status_b not in range(200, 300) or LOGIN_GATE_RE.search(body_b):
                    continue
                if len(body_b) < 50:
                    continue

                # Vertical: lower-ranked account reached a resource that was
                # also accessible to a higher-ranked account. Do not infer role
                # solely from list order; same-role accounts are horizontal only.
                if _role_rank(role_a) > _role_rank(role_b) and is_privileged:
                    findings.append(Finding(
                        check_type="privesc_cross_acct",
                        severity="critical",
                        url=url,
                        field_name=f"(cross-account vertical: {user_b} → {path})",
                        payload=f"{user_b} session cookie",
                        evidence=(
                            f"Vertical privilege escalation (cross-account): "
                            f"Account '{user_b}' (lower-privilege) can access "
                            f"privileged path '{path}' (HTTP {status_b}). "
                            f"This resource should only be accessible to '{user_a}'."
                        ),
                        request={"url": url, "method": "GET",
                                 "headers": {"Cookie": f"<{user_b}-token>"}},
                        response={"status": status_b, "url": url},
                    ))
                else:
                    # Horizontal: two different user accounts accessing same resource
                    # Flag when account B appears to receive account A's resource.
                    # A per-user dashboard often returns HTTP 200 with different
                    # content for each user; that is expected and should not be
                    # treated as IDOR. Stronger evidence is either account A's
                    # identity marker in B's response or near-identical content.
                    owner_markers = _identity_markers(user_a)
                    body_b_lower = body_b.lower()
                    owner_marker_seen = any(marker in body_b_lower for marker in owner_markers)
                    similarity = _body_similarity(body_a, body_b)
                    same_resource_seen = similarity >= 0.92 and _url_has_object_identifier(url)
                    if owner_marker_seen or same_resource_seen:
                        evidence_reason = (
                            f"owner marker from '{user_a}' is present in '{user_b}' response"
                            if owner_marker_seen
                            else f"response is highly similar to '{user_a}' resource"
                        )
                        findings.append(Finding(
                            check_type="privesc_cross_acct",
                            severity="high",
                            url=url,
                            field_name=f"(cross-account horizontal: {user_b} → {path})",
                            payload=f"{user_b} session cookie",
                            evidence=(
                                f"Horizontal privilege escalation (cross-account): "
                                f"Account '{user_b}' can access '{path}' for "
                                f"account '{user_a}' (HTTP {status_b}); "
                                f"{evidence_reason}. "
                                f"This indicates access to another user's private data."
                            ),
                            request={"url": url, "method": "GET",
                                     "headers": {"Cookie": f"<{user_b}-token>"}},
                            response={
                                "status": status_b,
                                "url": url,
                                "similarity": round(similarity, 3),
                                "owner_marker_seen": owner_marker_seen,
                            },
                        ))
                        break  # One finding per (url, account_a) pair is enough

        return findings

    # ------------------------------------------------------------------
    # HTTP helper
    # ------------------------------------------------------------------

    async def _get(self, url: str, cookies: str, timeout: float) -> tuple[int, str]:
        """Issue a GET request and return (status_code, body_excerpt)."""
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=timeout,
                verify=False,
                headers={**_HEADERS, "Cookie": cookies} if cookies else _HEADERS,
                **self._client_proxy_kwargs(),
            ) as client:
                resp = await client.get(url)
                return resp.status_code, resp.text[:8000]
        except Exception:
            return 0, ""

    async def _emit(self, finding: Finding) -> None:
        """Push finding to the engine and monitor."""
        self.findings.append(finding)
        self.engine.all_findings.append(finding)
        if self.monitor:
            await self.monitor.emit_finding(finding.to_dict())
