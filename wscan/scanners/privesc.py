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
  6. By bypassing a 401/403 access control with path-normalisation,
     trusted-IP spoofing headers, URL-rewrite headers or HTTP verb tampering

Check types emitted
-------------------
  privesc_unauth      — resource accessible without any credentials
  privesc_vertical    — low-privilege session can reach a high-privilege resource
  privesc_horizontal  — IDOR via URL path ID manipulation
  privesc_param_idor  — IDOR via query/body parameter manipulation (NEW ③)
  privesc_cross_acct  — cross-account access confirmed with a second session (NEW A)
  privesc_bypass      — an enforced 401/403 access control was bypassed

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
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import httpx

from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    PayloadShape, Prerequisite, ScannerContract, StateChangeClass, TransportKind,
    ValueKind,
)

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


def _engine_custom_headers(engine, url: str = "") -> dict:
    """Return custom --header / refreshed-token headers, *without* the Cookie
    (privesc deliberately swaps the Cookie under test)."""
    if not hasattr(engine, "auth_headers"):
        return {}
    if url and hasattr(engine, "headers_for_url"):
        hdrs = engine.auth_headers(
            include_cookie=False,
            url=url,
        )
    else:
        hdrs = engine.auth_headers(include_cookie=False)
    return {k: v for k, v in hdrs.items() if k.lower() != "cookie"}


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

ACTION_PATH_RE = re.compile(
    r"/(admin|manage|settings|users?|members?|orders?|payment|billing|private"
    r"|secure|internal|staff|moderator|approve|delete|remove|update|edit"
    r"|create|export|import|role|permission)",
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

NON_RESOURCE_RE = re.compile(
    r"(not\s*found|no\s+such|does\s+not\s+exist|missing|unknown\s+(resource|record|object)"
    r"|404|見つかりません|存在しません)",
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
# 401/403 access-control bypass payloads
# ---------------------------------------------------------------------------

# Headers commonly abused to spoof a trusted origin / internal IP and slip past
# gateway- or middleware-level access control.
_BYPASS_HEADERS: tuple[dict, ...] = (
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Host": "127.0.0.1"},
)

# Headers some reverse proxies honour to *rewrite* the requested path: the
# request is sent to a benign URL while the header points at the protected one.
_REWRITE_HEADERS: tuple[str, ...] = ("X-Original-URL", "X-Rewrite-URL")

# Verbs to try when a GET is blocked (verb / method tampering).
# OPTIONS is deliberately NOT probed: a successful OPTIONS only returns
# preflight/metadata and never proves that protected data or an operation
# became accessible. POST/PUT/PATCH *can* change state or perform an action,
# so they only run when the operator explicitly opts in.
_TAMPER_METHODS_SAFE: tuple[str, ...] = ()
_TAMPER_METHODS_MUTATING: tuple[str, ...] = ("POST", "PUT", "PATCH")

# Header names that carry credentials. The 401/403 *bypass* probes claim to be
# unauthenticated, so any of these coming from --header / a refreshed token must
# be stripped — otherwise a valid token (not the bypass) is what served the
# resource, invalidating the finding.
_CREDENTIAL_HEADER_NAMES = frozenset({
    "authorization", "proxy-authorization", "cookie", "authentication",
    "x-api-key", "x-apikey", "api-key", "apikey", "x-auth-token", "x-auth",
    "x-access-token", "x-session-token", "x-csrf-token", "x-xsrf-token",
    "x-amz-security-token", "bearer",
})
_CREDENTIAL_HEADER_SUBSTRINGS = (
    "auth", "token", "api-key", "apikey", "session", "cookie", "credential", "secret",
)


def _strip_credential_headers(headers: dict) -> dict:
    """Drop credential-bearing headers so an 'unauthenticated' probe really is."""
    out: dict = {}
    for key, value in (headers or {}).items():
        kl = key.lower()
        if kl in _CREDENTIAL_HEADER_NAMES:
            continue
        if any(token in kl for token in _CREDENTIAL_HEADER_SUBSTRINGS):
            continue
        out[key] = value
    return out


def _path_bypass_variants(path: str) -> list[str]:
    """Return path-normalisation tricks that frequently bypass naive ACL prefix
    matching (e.g. a rule that only blocks the exact string '/admin')."""
    base = (path or "/").rstrip("/")
    if not base:
        return []
    segs = base.split("/")
    last = segs[-1]
    prefix = "/".join(segs[:-1])
    # NOTE: do not add file-extension suffixes (e.g. ".json"/".html"). Those are
    # plausibly distinct application routes rather than normalisation aliases of
    # the protected path, so a 2xx there is not evidence of an ACL bypass.
    variants = {
        base + "/",
        base + "//",
        base + "/.",
        base + "/./",
        base + "/..;/",
        base + ";/",
        base + "%20",
        base + "%09",
        f"{prefix}//{last}",
        f"{prefix}/./{last}",
        f"{prefix}/{last};",
    }
    if last and last.lower() != last.upper():
        variants.add(f"{prefix}/{last.upper()}")
    return [v for v in variants if v and v != base]


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


def _has_sensitive_idor_param(url: str) -> bool:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    for param in qs:
        if not _IDOR_PARAM_RE.match(param):
            continue
        if param.lower() != "id" or PROTECTED_PATH_RE.search(parsed.path):
            return True
    return False


def _body_contains_identifier(body: str, identifier: str) -> bool:
    if not body or not identifier:
        return False
    if identifier.isdigit():
        return bool(re.search(rf"(?<!\d){re.escape(identifier)}(?!\d)", body))
    return identifier.lower() in body.lower()


def _is_auth_gate(body: str) -> bool:
    """Detect real auth gates without treating a normal Login nav link as a gate."""
    body_l = (body or "").lower()
    if re.search(
        r"(please.*log\s*in|must.*log\s*in|authentication.*required"
        r"|unauthorized|access.*denied|forbidden|session.*expired"
        r"|ログイン.*してください|認証.*必要|ログインが必要"
        r"|権限がありません|アクセス.*禁止)",
        body_l,
        re.IGNORECASE,
    ):
        return True
    return bool(
        re.search(r"<form[^>]+action=[\"'][^\"']*(?:login|signin|auth)", body_l, re.IGNORECASE)
        and re.search(r"type=[\"']password[\"']", body_l, re.IGNORECASE)
    )


def _idor_response_confidence(
    original_body: str,
    candidate_body: str,
    original_identifier: str,
    candidate_identifier: str,
) -> tuple[bool, str, float]:
    """Return whether a mutated object-id response looks like real object access."""
    if len(candidate_body) < 50:
        return False, "short candidate response", 0.0
    if _is_auth_gate(candidate_body):
        return False, "authentication gate", 0.0
    if NON_RESOURCE_RE.search(candidate_body):
        return False, "not-found response", 0.0

    norm_original = _normalize_response_body(original_body)
    norm_candidate = _normalize_response_body(candidate_body)
    if norm_original == norm_candidate:
        return False, "generic identical response", 1.0

    similarity = _body_similarity(original_body, candidate_body)
    candidate_id_seen = _body_contains_identifier(candidate_body, candidate_identifier)
    original_id_seen = _body_contains_identifier(original_body, original_identifier)

    if candidate_id_seen:
        return True, "candidate object identifier is present in response", similarity
    if original_id_seen and 0.45 <= similarity <= 0.985:
        return True, "response shape matches original object but content changed", similarity
    if 0.70 <= similarity <= 0.985 and abs(len(candidate_body) - len(original_body)) >= 20:
        return True, "similar object template returned different content", similarity

    return False, "insufficient object-specific evidence", similarity


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class PrivEscScanner(BaseScanner):
    """
    Tests each crawled URL for unauthorized / under-authorized access.

    This is primarily a *page-level* scanner — scan_field() is a no-op.
    All logic lives in scan_page().
    """

    HAS_PAGE_LEVEL = True
    CHECK_TYPE = "privesc"
    CONTRACT = ScannerContract(
        execution_kinds=frozenset({ExecutionKind.PAGE_ANALYSIS}),
        capabilities=(
            CarrierCapability(
                # scan_page が _test_param_idor()/_mutate_uuid() で ID 系クエリ値を
                # 差し替え HTTPX 送信し IDOR を検査するため supported。
                carrier=Carrier.QUERY, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.HTTPX}),
                payload_shapes=frozenset({PayloadShape.SCALAR}),
            ),
            CarrierCapability(
                # _test_state_changing_forms() が特権フォームを _request_form() で送信し
                # privesc_action を検査するため supported。
                carrier=Carrier.FORM, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.HTTPX}),
                payload_shapes=frozenset({PayloadShape.SCALAR}),
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
                # _BYPASS_HEADERS（X-Forwarded-For/Host, X-Real-IP 等）と _REWRITE_HEADERS
                # （X-Original-URL/X-Rewrite-URL）を _raw_request で注入し 401/403 access-control
                # bypass を検査するため supported。
                carrier=Carrier.HEADER, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.HTTPX}),
                payload_shapes=frozenset({PayloadShape.SCALAR}),
            ),
            CarrierCapability(
                # identity 切替のため multi-account の認証 cookie を持ち回るだけで、
                # cookie 値へ攻撃 payload を注入するわけではない。
                carrier=Carrier.COOKIE, state=CapabilityState.UNSUPPORTED,
                reason="identity 切替の認証 cookie を持ち回るが cookie 値へ payload 注入はしない",
            ),
            CarrierCapability(
                # _test_horizontal_privesc() が path の数値/UUID セグメントを差し替え、
                # _test_forbidden_bypass() が path 正規化変種を送って path-based IDOR/bypass を検査。
                carrier=Carrier.PATH, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.HTTPX}),
                payload_shapes=frozenset({PayloadShape.SCALAR}),
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
        state_change=StateChangeClass.CONDITIONAL,
        cost=CostClass.HIGH,
    )

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

        # ── Test 1b: 401/403 access-control bypass ────────────────────
        if is_privileged:
            for bf in await self._test_forbidden_bypass(url, is_privileged, timeout):
                findings.append(bf)
                await self._emit(bf)

        # ── Test 2: Low-privilege vertical escalation ─────────────────
        low_priv_cookies: str = getattr(self.engine, "low_priv_cookies", "")
        if low_priv_cookies and is_privileged:
            lp_finding = await self._test_lowpriv(url, low_priv_cookies, timeout)
            if lp_finding:
                findings.append(lp_finding)
                await self._emit(lp_finding)

        # Build the primary session cookie string
        cookies_str = self._get_primary_cookies()

        should_probe_path_idor = has_auth and cookies_str and is_privileged
        should_probe_param_idor = has_auth and cookies_str and (
            is_privileged or _has_sensitive_idor_param(url)
        )

        if should_probe_path_idor:
            # ── Test 3: Horizontal privilege escalation (path IDOR) ───
            horiz_findings = await self._test_horizontal_privesc(url, cookies_str, timeout)
            for hf in horiz_findings:
                findings.append(hf)
                await self._emit(hf)

        if should_probe_param_idor:
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

    async def scan_page_context(self, page) -> list[Finding]:
        """Run URL checks plus form/action authorization checks with page context."""
        findings = await self.scan_page(page.url)
        action_findings = await self._test_state_changing_forms(page)
        for af in action_findings:
            findings.append(af)
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

    def _client_transport_kwargs(self) -> dict:
        if hasattr(self.engine, "httpx_client_kwargs"):
            return self.engine.httpx_client_kwargs()
        return {"verify": False, **self._client_proxy_kwargs()}

    def _form_payload(self, form: dict) -> dict:
        data: dict[str, str] = {}
        for inp in form.get("inputs", []):
            name = inp.get("name") or inp.get("id")
            if not name:
                continue
            value = inp.get("value")
            if value in (None, ""):
                hint = f"{name} {inp.get('type', '')}".lower()
                if "mail" in hint or "email" in hint:
                    value = "wscan-action@example.test"
                elif "user" in hint or "name" in hint:
                    value = "wscan-action"
                elif "amount" in hint or "price" in hint or "count" in hint:
                    value = "1"
                else:
                    value = "wscan-action-probe"
            data[name] = str(value)
        data.setdefault("_wscan_probe", "1")
        return data

    def _action_url(self, page_url: str, form: dict) -> str:
        action = form.get("action") or page_url
        return urljoin(page_url, action)

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
                headers=_HEADERS,
                **self._client_transport_kwargs(),
            ) as client:
                resp = await client.get(url)
                self._record_probe_status(resp)
                status = resp.status_code
                body = resp.text[:8000]
        except Exception:
            return None

        if status in (301, 302, 303, 307, 308, 401, 403):
            return None
        if not (200 <= status < 300):
            return None
        if _is_auth_gate(body):
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
                headers={
                    **_HEADERS,
                    **_engine_custom_headers(self.engine, url),
                    "Cookie": low_priv_cookies,
                },
                **self._client_transport_kwargs(),
            ) as client:
                resp = await client.get(url)
                self._record_probe_status(resp)
                status = resp.status_code
                body = resp.text[:8000]
        except Exception:
            return None

        if status in (301, 302, 303, 307, 308, 401, 403):
            return None
        if not (200 <= status < 300):
            return None
        if _is_auth_gate(body):
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
    # Test 1b: 401/403 access-control bypass
    # ------------------------------------------------------------------

    async def _test_forbidden_bypass(
        self,
        url: str,
        is_privileged: bool,
        timeout: float,
    ) -> list[Finding]:
        """When a privileged path enforces access control (401/403 for a bare
        request), probe common bypass techniques: path normalisation,
        trusted-IP spoofing headers, URL-rewrite headers and verb tampering.
        Returns at most one finding (the first confirmed bypass)."""
        if not is_privileged:
            return []

        parsed = urlparse(url)
        path = parsed.path or "/"

        # Baseline must actually be blocked — otherwise the unauth/vertical
        # tests already cover open access and there is nothing to "bypass".
        base_status, _ = await self._raw_request("GET", url, timeout)
        if base_status not in (401, 403):
            return []

        def _make(technique: str, candidate_url: str, status: int,
                  body: str, request: dict) -> Finding:
            return Finding(
                check_type="privesc_bypass",
                severity="high",
                url=url,
                field_name=f"(access-control bypass: {technique})",
                payload=candidate_url,
                evidence=(
                    f"Access-control bypass: the canonical request to '{path}' "
                    f"was blocked (HTTP {base_status}), but {technique} reached "
                    f"the resource (HTTP {status}, {len(body)} bytes) without "
                    f"valid authorization. The access control appears to be "
                    f"enforced only on the exact/canonical request shape."
                ),
                request=request,
                response={
                    "status": status,
                    "url": candidate_url,
                    "baseline_status": base_status,
                },
            )

        # Control paths that should not exist. We probe one OUTSIDE the
        # protected prefix (so an upstream ACL on /admin/* can't reject it
        # before the backend's generic fallback shows) and one INSIDE the same
        # routing context (so an SPA mounted under /app/* is still detected when
        # root-level unknown paths 404). A candidate is suppressed if either
        # control yields an equivalent "successful" response.
        control_urls = self._nonexistent_control_urls(parsed)

        # Public-root / parent control: some normalisation variants (e.g.
        # '/admin/..;/') are collapsed by the server/proxy to a parent landing
        # page rather than the protected resource — the site root '/' for a
        # top-level path, or e.g. '/app/' for a mounted '/app/admin'. We fetch
        # the site root (index 0, reused by the rewrite branch) plus the parent
        # directory when it differs, and suppress a variant matching either.
        collapse_urls = self._collapse_control_urls(parsed)
        collapse_controls: list[tuple[int, str]] = [
            await self._raw_request("GET", c_url, timeout) for c_url in collapse_urls
        ]
        root_url = collapse_urls[0]
        root_status, root_body = collapse_controls[0]

        # 1) Path-normalisation bypass
        for variant_path in _path_bypass_variants(path):
            candidate_url = urlunparse(parsed._replace(path=variant_path))
            status, body = await self._raw_request("GET", candidate_url, timeout)
            if not self._bypass_succeeded(status, body):
                continue
            # If a plain request to a nonexistent path returns an equivalent
            # 2xx, the server serves a generic page for unknown paths (SPA
            # fallback / custom error) — the variant didn't reach the resource.
            if await self._any_control_equivalent("GET", control_urls, timeout, None, status, body):
                continue
            # If the variant collapsed to a parent landing page (site root or the
            # path's parent directory), it didn't reach the protected resource.
            if any(
                c_body and self._responses_equivalent(c_status, c_body, status, body)
                for c_status, c_body in collapse_controls
            ):
                continue
            return [_make(
                f"path normalisation '{variant_path}'", candidate_url,
                status, body,
                {"url": candidate_url, "method": "GET", "headers": {}},
            )]

        # 2) Trusted-origin / internal-IP spoofing headers
        for hdr in _BYPASS_HEADERS:
            status, body = await self._raw_request("GET", url, timeout, headers=hdr)
            if not self._bypass_succeeded(status, body):
                continue
            # Control: same header on a nonexistent path. If it yields an
            # equivalent 2xx, the header only routes to generic/default content
            # (e.g. X-Forwarded-Host selecting another vhost), not the resource.
            if await self._any_control_equivalent("GET", control_urls, timeout, hdr, status, body):
                continue
            return [_make(
                f"spoofed header {', '.join(hdr)}", url, status, body,
                {"url": url, "method": "GET", "headers": dict(hdr)},
            )]

        # 3) URL-rewrite headers (request the root, point the header at the path)
        rewrite_target = path + (f"?{parsed.query}" if parsed.query else "")
        nonexistent_target = "/wscan-nonexistent-probe-zzq"
        # Reuse the public-root control fetched above: if the proxy ignores the
        # header, the root just serves its public homepage. We must observe a
        # different response with the header to claim the protected resource was
        # actually reached — otherwise this is a false positive.
        control_status, control_body = root_status, root_body
        for hname in _REWRITE_HEADERS:
            status, body = await self._raw_request(
                "GET", root_url, timeout, headers={hname: rewrite_target}
            )
            if not self._bypass_succeeded(status, body):
                continue
            # Need a usable control to establish a difference; a failed control
            # (network error / empty) gives no evidence, so skip conservatively.
            if not control_body:
                continue
            if self._responses_equivalent(control_status, control_body, status, body):
                continue  # header ignored — only proves '/' is public
            # The proxy may honour the header but route *any* target (incl.
            # nonexistent ones) to a generic custom page. Control with the same
            # header pointing at a nonexistent target and suppress if equivalent.
            if await self._control_is_equivalent(
                "GET", root_url, timeout, {hname: nonexistent_target}, status, body
            ):
                continue
            return [_make(
                f"rewrite header {hname}", root_url, status, body,
                {"url": root_url, "method": "GET",
                 "headers": {hname: rewrite_target}},
            )]

        # 4) HTTP verb / method tampering. Nothing runs by default (OPTIONS is
        # not evidence of a bypass); the state-changing verbs run only when the
        # operator opts in, since blindly POST/PUT/PATCH-ing a privileged URL
        # could mutate server state.
        methods = list(_TAMPER_METHODS_SAFE)
        if getattr(self.engine, "allow_state_changing_probes", False):
            methods += list(_TAMPER_METHODS_MUTATING)
        for method in methods:
            status, body = await self._raw_request(method, url, timeout)
            if not self._bypass_succeeded(status, body):
                continue
            # Control: same verb on a nonexistent path. A generic CORS /
            # framework handler (common for OPTIONS) answers 2xx for any path,
            # so an equivalent response means no protected resource was served.
            if await self._any_control_equivalent(method, control_urls, timeout, None, status, body):
                continue
            return [_make(
                f"{method} method tampering", url, status, body,
                {"url": url, "method": method, "headers": {}},
            )]

        return []

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
                    confident, confidence_reason, similarity = _idor_response_confidence(
                        own_body, body, str(original_id), str(cid)
                    )
                    if not confident:
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
                            f"{confidence_reason}; response similarity={similarity:.3f}. "
                            f"Possible access to another user's resource."
                        ),
                        request={"url": candidate_url, "method": "GET",
                                 "headers": {"Cookie": "<session-token>"}},
                        response={
                            "status": status,
                            "url": candidate_url,
                            "similarity": round(similarity, 3),
                            "confidence_reason": confidence_reason,
                        },
                    ))
                    break  # one confirmation per segment

            # ── UUID in path ────────────────────────────────────────────
            elif _UUID_RE.match(seg):
                own_status, own_body = await self._get(url, cookies, timeout)
                if own_status not in range(200, 300):
                    continue

                mutated = _mutate_uuid(seg)
                new_segs = list(segments)
                new_segs[seg_idx] = mutated
                candidate_url = urlunparse(parsed._replace(path="/".join(new_segs)))
                status, body = await self._get(candidate_url, cookies, timeout)

                if status not in range(200, 300):
                    continue
                confident, confidence_reason, similarity = _idor_response_confidence(
                    own_body, body, seg, mutated
                )
                if not confident:
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
                        f"{confidence_reason}; response similarity={similarity:.3f}. "
                        f"Possible access to another user's resource via UUID guessing."
                    ),
                    request={"url": candidate_url, "method": "GET",
                             "headers": {"Cookie": "<session-token>"}},
                    response={
                        "status": status,
                        "url": candidate_url,
                        "similarity": round(similarity, 3),
                        "confidence_reason": confidence_reason,
                    },
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
                        confident, confidence_reason, similarity = _idor_response_confidence(
                            own_body, body, str(original_id), str(cid)
                        )
                        if not confident:
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
                                f"{confidence_reason}; response similarity={similarity:.3f}. "
                                f"Possible access to another user's data via parameter manipulation."
                            ),
                            request={"url": candidate_url, "method": "GET",
                                     "headers": {"Cookie": "<session-token>"}},
                            response={
                                "status": status,
                                "url": candidate_url,
                                "similarity": round(similarity, 3),
                                "confidence_reason": confidence_reason,
                            },
                        ))
                        break

                # ── UUID parameter value ────────────────────────────────
                elif _UUID_RE.match(val):
                    own_status, own_body = await self._get(url, cookies, timeout)
                    if own_status not in range(200, 300):
                        continue

                    mutated = _mutate_uuid(val)
                    new_qs = dict(qs)
                    new_qs[param] = [mutated]
                    candidate_url = urlunparse(
                        parsed._replace(query=urlencode(new_qs, doseq=True))
                    )
                    status, body = await self._get(candidate_url, cookies, timeout)

                    if status not in range(200, 300):
                        continue
                    confident, confidence_reason, similarity = _idor_response_confidence(
                        own_body, body, val, mutated
                    )
                    if not confident:
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
                            f"{confidence_reason}; response similarity={similarity:.3f}. "
                            f"Possible access to another object via UUID guessing."
                        ),
                        request={"url": candidate_url, "method": "GET",
                                 "headers": {"Cookie": "<session-token>"}},
                        response={
                            "status": status,
                            "url": candidate_url,
                            "similarity": round(similarity, 3),
                            "confidence_reason": confidence_reason,
                        },
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
            if status_a not in range(200, 300) or _is_auth_gate(body_a):
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

                if status_b not in range(200, 300) or _is_auth_gate(body_b):
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
    # Test 6: State-changing form/action authorization
    # ------------------------------------------------------------------

    async def _test_state_changing_forms(self, page) -> list[Finding]:
        """Submit privileged-looking non-GET forms with lower-privilege sessions."""
        findings: list[Finding] = []
        forms = getattr(page, "forms", []) or []
        if not forms:
            return findings

        timeout = float(getattr(self.engine, "timeout", 30))
        low_priv_cookies: str = getattr(self.engine, "low_priv_cookies", "")
        account_sessions: list[dict] = getattr(self.engine, "account_sessions", [])

        probes: list[tuple[str, str, str]] = []
        if low_priv_cookies:
            probes.append(("low-privilege", low_priv_cookies, "user"))
        for account in account_sessions:
            cookies = account.get("cookies", "")
            if not cookies:
                continue
            role = account.get("role", "")
            if _role_rank(role) <= 1:
                probes.append((account.get("username", "account"), cookies, role or "user"))

        if not probes:
            return findings

        from wscan.state_profile import may_submit as _may_submit
        _profile = getattr(self.engine, "state_profile", "unrestricted")
        for form in forms:
            method = (form.get("method") or "GET").upper()
            if method == "GET":
                continue
            action_url = self._action_url(page.url, form)
            # state profile: 低権限セッションでの状態変更フォーム送信も profile に従う。
            if not _may_submit(_profile, method=method, action=action_url,
                               labels=form.get("labels") or ""):
                self._record_scan_note(f"state_change_skipped:{self.CHECK_TYPE}")
                continue
            action_path = urlparse(action_url).path
            if not ACTION_PATH_RE.search(action_path):
                continue
            data = self._form_payload(form)
            for actor, cookies, role in probes:
                status, body = await self._request_form(method, action_url, data, cookies, timeout)
                if status in (0, 401, 403):
                    continue
                if status in (301, 302, 303, 307, 308):
                    # A redirect away from login/error after a state-changing request often
                    # means the action was accepted.
                    accepted = True
                else:
                    # Do not use the broad LOGIN_GATE_RE here: many normal pages
                    # include a "Login" nav link even after a successful action.
                    rejected = re.search(
                        r"(unauthorized|forbidden|access\s*denied|invalid\s*login"
                        r"|authentication\s*required|権限がありません|アクセス.*禁止)",
                        body,
                        re.IGNORECASE,
                    )
                    accepted = 200 <= status < 300 and not rejected
                if not accepted:
                    continue

                findings.append(Finding(
                    check_type="privesc_action",
                    severity="high",
                    url=page.url,
                    field_name=f"(state-changing action: {method} {action_path})",
                    payload=f"{actor} session submitted form",
                    evidence=(
                        f"State-changing authorization issue: low-privilege actor "
                        f"'{actor}' ({role}) could submit {method} {action_path} "
                        f"and received HTTP {status}. This action path appears "
                        f"privileged and should enforce server-side authorization."
                    ),
                    request={
                        "url": action_url,
                        "method": method,
                        "headers": {"Cookie": f"<{actor}-token>"},
                        "body": data,
                    },
                    response={"status": status, "url": action_url},
                ))
                break

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
                headers=(
                    {
                        **_HEADERS,
                        **_engine_custom_headers(self.engine, url),
                        "Cookie": cookies,
                    }
                    if cookies
                    else {**_HEADERS, **_engine_custom_headers(self.engine, url)}
                ),
                **self._client_transport_kwargs(),
            ) as client:
                resp = await client.get(url)
                self._record_probe_status(resp)
                return resp.status_code, resp.text[:8000]
        except Exception:
            return 0, ""

    async def _raw_request(
        self,
        method: str,
        url: str,
        timeout: float,
        *,
        headers: Optional[dict] = None,
        cookies: str = "",
    ) -> tuple[int, str]:
        """Issue an arbitrary-method request (no redirect following) with
        optional extra headers. Used by the 401/403 bypass probes, which are
        unauthenticated — so credential headers from --header / a refreshed
        token are stripped. Explicit probe ``headers`` are applied afterwards
        and never stripped (they carry the bypass payload itself)."""
        hdrs = {
            **_HEADERS,
            **_strip_credential_headers(
                _engine_custom_headers(self.engine, url)
            ),
        }
        if headers:
            hdrs.update(headers)
        if cookies:
            hdrs["Cookie"] = cookies
        try:
            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=timeout,
                headers=hdrs,
                **self._client_transport_kwargs(),
            ) as client:
                resp = await client.request(method, url)
                self._record_probe_status(resp)
                return resp.status_code, resp.text[:8000]
        except Exception:
            return 0, ""

    def _responses_equivalent(
        self, status_a: int, body_a: str, status_b: int, body_b: str
    ) -> bool:
        """True when two responses are effectively the same page (same status
        and near-identical body). Used to prove a URL-rewrite header actually
        changed what was served, rather than just returning the public root."""
        if status_a != status_b:
            return False
        if _normalize_response_body(body_a) == _normalize_response_body(body_b):
            return True
        return _body_similarity(body_a, body_b) >= 0.98

    def _nonexistent_control_urls(self, parsed) -> list[str]:
        """Build nonexistent control URLs for the protected resource: one
        outside any prefix (origin root) for the upstream-ACL case, and one in
        the same routing context (parent dir) for the SPA-mounted-under-prefix
        case."""
        token = "/wscan-nonexistent-probe-zzq"
        paths = [token]
        parent = (parsed.path or "/").rsplit("/", 1)[0]
        if parent and parent != "":
            inside = f"{parent}{token}"
            if inside not in paths:
                paths.append(inside)
        return [
            urlunparse(parsed._replace(path=p, query="", fragment=""))
            for p in paths
        ]

    def _collapse_control_urls(self, parsed) -> list[str]:
        """Parent landing pages a '..;/'-style normalisation variant may collapse
        to: the site root '/' (index 0, reused by the rewrite branch) and the
        protected path's immediate parent directory when it differs."""
        urls = [urlunparse(parsed._replace(path="/", query="", fragment=""))]
        parent_path = (parsed.path or "/").rsplit("/", 1)[0] or "/"
        if not parent_path.endswith("/"):
            parent_path += "/"
        if parent_path != "/":
            urls.append(
                urlunparse(parsed._replace(path=parent_path, query="", fragment=""))
            )
        return urls

    async def _any_control_equivalent(
        self,
        method: str,
        control_urls: list[str],
        timeout: float,
        headers: Optional[dict],
        status: int,
        body: str,
    ) -> bool:
        """True if the technique applied to ANY nonexistent control path yields
        an equivalent 'successful' response (generic content, not the resource)."""
        for control_url in control_urls:
            if await self._control_is_equivalent(
                method, control_url, timeout, headers, status, body
            ):
                return True
        return False

    async def _control_is_equivalent(
        self,
        method: str,
        control_url: str,
        timeout: float,
        headers: Optional[dict],
        status: int,
        body: str,
    ) -> bool:
        """Apply the SAME technique (method + headers) to a nonexistent control
        path and report whether it produced an equivalent 'successful' response.

        True ⇒ the technique merely yields generic content (catch-all page,
        default vhost, blanket CORS/OPTIONS handler) rather than the protected
        resource, so the candidate finding should be suppressed.
        """
        ctrl_status, ctrl_body = await self._raw_request(
            method, control_url, timeout, headers=headers
        )
        return (
            bool(ctrl_body)
            and self._bypass_succeeded(ctrl_status, ctrl_body)
            and self._responses_equivalent(ctrl_status, ctrl_body, status, body)
        )

    def _bypass_succeeded(self, status: int, body: str) -> bool:
        """A bypass attempt counts only if the resource was actually served:
        a 2xx with substantial content that is neither an auth gate nor a
        not-found page."""
        return (
            200 <= status < 300
            and len(body or "") >= 50
            and not _is_auth_gate(body or "")
            and not NON_RESOURCE_RE.search(body or "")
        )

    async def _request_form(
        self,
        method: str,
        url: str,
        data: dict,
        cookies: str,
        timeout: float,
    ) -> tuple[int, str]:
        """Submit a form-like request and return (status_code, body_excerpt)."""
        try:
            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=timeout,
                headers=(
                    {
                        **_HEADERS,
                        **_engine_custom_headers(self.engine, url),
                        "Cookie": cookies,
                    }
                    if cookies
                    else {**_HEADERS, **_engine_custom_headers(self.engine, url)}
                ),
                **self._client_transport_kwargs(),
            ) as client:
                resp = await client.request(method, url, data=data)
                self._record_probe_status(resp)
                return resp.status_code, resp.text[:8000]
        except Exception:
            return 0, ""

    async def verify_finding(self, finding: Finding) -> bool | None:
        timeout = float(getattr(self.engine, "timeout", 30))

        if finding.check_type == "privesc_unauth":
            url = finding.request.get("url") or finding.url
            status, body = await self._get(url, "", timeout)
            return self._accessible_response(status, body)

        if finding.check_type == "privesc_bypass":
            req = finding.request or {}
            candidate_url = req.get("url") or finding.url
            method = req.get("method", "GET")
            headers = {
                k: v for k, v in (req.get("headers") or {}).items()
                if k.lower() != "cookie"
            }
            # 1) The canonical resource must still be blocked — otherwise it
            # became public between phases and there is no bypass to confirm.
            base_status, _ = await self._raw_request("GET", finding.url, timeout)
            if base_status not in (401, 403):
                return False
            # 2) The candidate must still serve substantial content.
            status, body = await self._raw_request(
                method, candidate_url, timeout, headers=headers
            )
            if not self._bypass_succeeded(status, body):
                return False
            # 3) Repeat the technique-specific control comparison so a generic
            # page (catch-all / default vhost / blanket handler) isn't confirmed.
            parsed_orig = urlparse(finding.url)
            rewrite_hdr = next((h for h in headers if h in _REWRITE_HEADERS), None)
            if rewrite_hdr:
                ctrl_headers = dict(headers)
                ctrl_headers[rewrite_hdr] = "/wscan-nonexistent-probe-zzq"
                if await self._control_is_equivalent(
                    method, candidate_url, timeout, ctrl_headers, status, body
                ):
                    return False
            else:
                control_urls = self._nonexistent_control_urls(parsed_orig)
                if await self._any_control_equivalent(
                    method, control_urls, timeout, headers or None, status, body
                ):
                    return False
                # Path-normalisation findings (plain GET) can collapse to a
                # parent landing page; repeat the scan-time root/parent check so
                # a variant that only reached '/' (or '/app/') isn't confirmed.
                if method == "GET" and not headers:
                    for c_url in self._collapse_control_urls(parsed_orig):
                        c_status, c_body = await self._raw_request("GET", c_url, timeout)
                        if c_body and self._responses_equivalent(c_status, c_body, status, body):
                            return False
            return True

        if finding.check_type == "privesc_vertical":
            cookies = getattr(self.engine, "low_priv_cookies", "")
            if not cookies:
                return None
            status, body = await self._get(finding.url, cookies, timeout)
            return self._accessible_response(status, body)

        if finding.check_type in {"privesc_horizontal", "privesc_param_idor"}:
            cookies = self._get_primary_cookies()
            candidate_url = finding.request.get("url") or finding.response.get("url")
            if not cookies or not candidate_url:
                return None
            own_status, own_body = await self._get(finding.url, cookies, timeout)
            cand_status, cand_body = await self._get(candidate_url, cookies, timeout)
            return self._verifies_idor_response(
                own_status,
                own_body,
                cand_status,
                cand_body,
            )

        if finding.check_type == "privesc_cross_acct":
            account = self._account_for_finding(finding)
            if not account:
                return None
            status, body = await self._get(finding.url, account.get("cookies", ""), timeout)
            if not self._accessible_response(status, body):
                return False
            owner_user = self._owner_from_evidence(finding)
            if owner_user:
                owner_markers = _identity_markers(owner_user)
                if owner_markers:
                    return any(marker in body.lower() for marker in owner_markers)
            return True

        if finding.check_type == "privesc_action":
            req = finding.request or {}
            action_url = req.get("url")
            method = req.get("method", "POST")
            body = req.get("body") or {}
            cookies = self._cookies_for_action_finding(finding)
            if not action_url or not cookies:
                return None
            status, response_body = await self._request_form(
                method,
                action_url,
                body,
                cookies,
                timeout,
            )
            return self._accepted_action_response(status, response_body)

        return None

    def _accessible_response(self, status: int, body: str) -> bool:
        return (
            status in range(200, 300)
            and not _is_auth_gate(body or "")
            and not NON_RESOURCE_RE.search(body or "")
        )

    def _verifies_idor_response(
        self,
        own_status: int,
        own_body: str,
        cand_status: int,
        cand_body: str,
    ) -> bool:
        if not self._accessible_response(own_status, own_body):
            return False
        if not self._accessible_response(cand_status, cand_body):
            return False
        if len(cand_body or "") < 50:
            return False
        similarity = _body_similarity(own_body, cand_body)
        return _normalize_response_body(own_body) != _normalize_response_body(cand_body) and similarity < 0.995

    def _account_for_finding(self, finding: Finding) -> Optional[dict]:
        actor = self._actor_from_payload(finding.payload)
        if not actor:
            return None
        for account in getattr(self.engine, "account_sessions", []) or []:
            if account.get("username") == actor:
                return account
        return None

    def _cookies_for_action_finding(self, finding: Finding) -> str:
        actor = self._actor_from_payload(finding.payload)
        if not actor or actor == "low-privilege":
            return getattr(self.engine, "low_priv_cookies", "")
        for account in getattr(self.engine, "account_sessions", []) or []:
            if account.get("username") == actor:
                return account.get("cookies", "")
        return ""

    def _actor_from_payload(self, payload: str) -> str:
        return (payload or "").split(" session", 1)[0].strip()

    def _owner_from_evidence(self, finding: Finding) -> str:
        match = re.search(r"account '([^']+)'", finding.evidence or "")
        return match.group(1) if match else ""

    def _accepted_action_response(self, status: int, body: str) -> bool:
        if status in (0, 401, 403):
            return False
        if status in (301, 302, 303, 307, 308):
            return True
        rejected = re.search(
            r"(unauthorized|forbidden|access\s*denied|invalid\s*login"
            r"|authentication\s*required|権限がありません|アクセス.*禁止)",
            body or "",
            re.IGNORECASE,
        )
        return 200 <= status < 300 and not rejected

    async def _emit(self, finding: Finding) -> None:
        """Keep scanner-local state and stream monitor updates."""
        self.findings.append(finding)
        if self.monitor:
            await self.monitor.emit_finding(finding.to_dict())
