"""
GraphQL Vulnerability Scanner (②)
===================================
Auto-detects GraphQL endpoints and tests for:

  1. Introspection enabled (information disclosure)
  2. Batch query support (potential DoS / rate-limit bypass)
  3. Field-level injection — XSS / SQLi / SSTI into string arguments
  4. Sensitive type/field names in the schema (e.g. password, token)

Check types emitted
-------------------
  graphql_introspection  — introspection query returns full schema
  graphql_batch          — array-wrapped batch queries are accepted
  graphql_injection      — injection payload reflected / triggered in field
  graphql_sensitive      — schema contains sensitive-sounding type/field names
"""
from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Optional
from urllib.parse import urljoin, urlparse

import httpx

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Common GraphQL endpoint paths to probe
_GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/graphql/v1",
    "/v1/graphql",
    "/graphql/console",
    "/api/v1/graphql",
    "/api/v2/graphql",
    "/query",
    "/api/query",
]

# Minimal introspection query
_INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name kind ofType { name kind } } }
      }
    }
  }
}
""".strip()

# Injection payloads for string arguments
_INJECTION_PAYLOADS = [
    ("<script>alert('wscan-graphql-xss')</script>", "xss"),
    ("' OR 1=1--", "sqli"),
    ("{{7*7}}", "ssti"),
    ("${7*7}", "ssti"),
    ("<img src=x onerror=alert('wscan')>", "xss"),
    ("' UNION SELECT NULL--", "sqli"),
]

# Field/type names that suggest sensitive data
_SENSITIVE_NAME_RE = re.compile(
    r"(password|passwd|secret|token|api_key|private|credential|credit_card|ssn"
    r"|social_security|bank_account|auth|bearer)",
    re.IGNORECASE,
)

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Content-Type": "application/json",
    "Accept": "application/json",
}

# Signatures that confirm a GraphQL JSON response
_GQL_RESPONSE_RE = re.compile(
    r'"data"\s*:|"errors"\s*:|"__schema"\s*:|"__typename"\s*:',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class GraphQLScanner(BaseScanner):
    """
    Probes well-known GraphQL endpoints on the target host and tests for
    common GraphQL-specific vulnerabilities.
    """

    CHECK_TYPE = "graphql"
    SEVERITY = "medium"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._tested_endpoints: set[str] = set()
        self._confirmed_endpoints: list[str] = []

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        return []  # GraphQL scanning is endpoint-level

    async def scan_page(self, url: str) -> list[Finding]:
        """
        On first call (or whenever a new origin is encountered) probe all
        known GraphQL paths on that origin.
        """
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Only probe each origin once
        if origin in self._tested_endpoints:
            return []
        self._tested_endpoints.add(origin)

        timeout = float(getattr(self.engine, "timeout", 30))

        # Build auth headers from session cookies
        req_headers = dict(_HEADERS)
        cookies_str = getattr(self.engine, "cookies", "") or ""
        if cookies_str:
            req_headers["Cookie"] = cookies_str

        findings: list[Finding] = []

        for path in _GRAPHQL_PATHS:
            endpoint = urljoin(origin, path)
            if await self._is_graphql(endpoint, req_headers, timeout):
                self._confirmed_endpoints.append(endpoint)
                endpoint_findings = await self._test_endpoint(
                    endpoint, req_headers, timeout
                )
                findings.extend(endpoint_findings)

        for f in findings:
            await self._emit(f)

        return findings

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    async def _is_graphql(
        self,
        endpoint: str,
        headers: dict,
        timeout: float,
    ) -> bool:
        """Send a simple query and check for a GraphQL-shaped response."""
        query = {"query": "{ __typename }"}
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=timeout,
                verify=False,
                headers=headers,
            ) as client:
                resp = await client.post(endpoint, json=query)
                if resp.status_code in (200, 400):
                    body = resp.text
                    if _GQL_RESPONSE_RE.search(body):
                        return True
                # Some GQL servers accept GET with query param
                resp2 = await client.get(
                    endpoint,
                    params={"query": "{ __typename }"},
                )
                if resp2.status_code in (200, 400):
                    if _GQL_RESPONSE_RE.search(resp2.text):
                        return True
        except Exception:
            pass
        return False

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    async def _test_endpoint(
        self,
        endpoint: str,
        headers: dict,
        timeout: float,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Introspection
        schema_data = await self._test_introspection(endpoint, headers, timeout, findings)

        # 2. Batch queries
        await self._test_batch(endpoint, headers, timeout, findings)

        # 3. Injection via discovered fields (or generic string args)
        await self._test_injection(endpoint, headers, timeout, findings, schema_data)

        # 4. Sensitive field/type names
        if schema_data:
            self._test_sensitive_schema(endpoint, schema_data, findings)

        return findings

    async def _test_introspection(
        self,
        endpoint: str,
        headers: dict,
        timeout: float,
        findings: list[Finding],
    ) -> Optional[dict]:
        """Test if introspection is enabled.  Returns schema data if successful."""
        query = {"query": _INTROSPECTION_QUERY}
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=timeout,
                verify=False,
                headers=headers,
            ) as client:
                resp = await client.post(endpoint, json=query)
                if resp.status_code != 200:
                    return None
                data = resp.json()
        except Exception:
            return None

        if "data" not in data or "__schema" not in (data.get("data") or {}):
            return None

        schema = data["data"]["__schema"]
        type_count = len(schema.get("types", []))

        findings.append(Finding(
            check_type="graphql_introspection",
            severity="medium",
            url=endpoint,
            field_name="(GraphQL introspection)",
            payload=_INTROSPECTION_QUERY[:120] + "...",
            evidence=(
                f"GraphQL introspection is enabled at {endpoint}. "
                f"The full schema ({type_count} types) is publicly accessible. "
                f"Attackers can enumerate all queries, mutations, and data types "
                f"to discover attack surface. Disable introspection in production."
            ),
            request={"url": endpoint, "method": "POST", "body": json.dumps(query)},
            response={"status": 200, "url": endpoint},
        ))
        return schema

    async def _test_batch(
        self,
        endpoint: str,
        headers: dict,
        timeout: float,
        findings: list[Finding],
    ) -> None:
        """Test if array-wrapped batch queries are accepted."""
        batch_query = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
        ]
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=timeout,
                verify=False,
                headers=headers,
            ) as client:
                resp = await client.post(endpoint, json=batch_query)
                if resp.status_code != 200:
                    return
                body = resp.text
        except Exception:
            return

        # A batched response is a JSON array
        if not body.strip().startswith("["):
            return

        findings.append(Finding(
            check_type="graphql_batch",
            severity="low",
            url=endpoint,
            field_name="(GraphQL batch)",
            payload=json.dumps(batch_query),
            evidence=(
                f"GraphQL batch queries are accepted at {endpoint}. "
                f"Batch querying allows sending many operations in a single HTTP request, "
                f"which can be used to bypass rate limits or amplify data exfiltration. "
                f"Consider restricting batch query size or disabling batching."
            ),
            request={"url": endpoint, "method": "POST", "body": json.dumps(batch_query)},
            response={"status": 200, "url": endpoint},
        ))

    async def _test_injection(
        self,
        endpoint: str,
        headers: dict,
        timeout: float,
        findings: list[Finding],
        schema: Optional[dict],
    ) -> None:
        """
        Build simple queries for string-typed fields and inject test payloads.
        Falls back to generic search/input fields when schema is unavailable.
        """
        # Collect (type_name, field_name, arg_name) tuples that accept strings
        targets: list[tuple[str, str, str]] = []

        if schema:
            for type_def in schema.get("types", []):
                type_name = type_def.get("name", "")
                if type_name.startswith("__"):
                    continue
                for fld in type_def.get("fields") or []:
                    for arg in fld.get("args") or []:
                        arg_type = arg.get("type", {})
                        # Resolve the leaf type
                        leaf = arg_type
                        while leaf.get("ofType"):
                            leaf = leaf["ofType"]
                        if leaf.get("name") in ("String", "ID"):
                            targets.append((type_name, fld["name"], arg["name"]))

        # Generic fallback targets
        if not targets:
            targets = [
                ("Query", "search", "query"),
                ("Query", "user", "id"),
                ("Mutation", "login", "username"),
            ]

        # Cap to avoid excessive requests
        for type_name, field_name, arg_name in targets[:10]:
            for payload_str, vuln_type in _INJECTION_PAYLOADS:
                gql_body = {
                    "query": (
                        f'{{ {field_name}({arg_name}: "{payload_str}") }}'
                    )
                }
                try:
                    async with httpx.AsyncClient(
                        follow_redirects=True,
                        timeout=timeout,
                        verify=False,
                        headers=headers,
                    ) as client:
                        resp = await client.post(endpoint, json=gql_body)
                        body = resp.text[:4000]
                except Exception:
                    continue

                # Check for reflection (XSS/SSTI) or error-based SQLi leakage
                if payload_str in body or (
                    vuln_type == "ssti" and ("49" in body or "7*7" not in body and "49" in body)
                ):
                    findings.append(Finding(
                        check_type="graphql_injection",
                        severity="critical" if vuln_type in ("xss", "sqli") else "high",
                        url=endpoint,
                        field_name=f"{type_name}.{field_name}({arg_name})",
                        payload=payload_str,
                        evidence=(
                            f"GraphQL field injection ({vuln_type.upper()}): "
                            f"Payload '{payload_str[:60]}' was reflected in the response "
                            f"for {type_name}.{field_name}(arg: {arg_name}). "
                            f"Input is not properly sanitised before being included in the response."
                        ),
                        request={"url": endpoint, "method": "POST",
                                 "body": json.dumps(gql_body)},
                        response={"status": resp.status_code, "url": endpoint,
                                  "body": body[:500]},
                    ))
                    break  # One finding per field is sufficient

    def _test_sensitive_schema(
        self,
        endpoint: str,
        schema: dict,
        findings: list[Finding],
    ) -> None:
        """Flag type/field names that sound sensitive."""
        sensitive_names: list[str] = []

        for type_def in schema.get("types", []):
            type_name = type_def.get("name", "")
            if type_name.startswith("__"):
                continue
            if _SENSITIVE_NAME_RE.search(type_name):
                sensitive_names.append(f"type:{type_name}")
            for fld in type_def.get("fields") or []:
                if _SENSITIVE_NAME_RE.search(fld.get("name", "")):
                    sensitive_names.append(f"{type_name}.{fld['name']}")

        if not sensitive_names:
            return

        findings.append(Finding(
            check_type="graphql_sensitive",
            severity="low",
            url=endpoint,
            field_name="(GraphQL schema)",
            payload="introspection",
            evidence=(
                f"GraphQL schema exposes potentially sensitive types/fields: "
                f"{', '.join(sensitive_names[:20])}. "
                f"Ensure these fields are properly access-controlled and that "
                f"introspection is disabled in production environments."
            ),
            request={"url": endpoint, "method": "POST"},
            response={"status": 200, "url": endpoint},
        ))

    async def _emit(self, finding: Finding) -> None:
        """Push finding to engine and monitor."""
        self.findings.append(finding)
        self.engine.all_findings.append(finding)
        if self.monitor:
            await self.monitor.emit_finding(finding.to_dict())
