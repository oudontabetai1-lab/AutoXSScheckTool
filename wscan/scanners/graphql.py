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

_SQL_ERROR_RE = re.compile(
    r"(sql|syntax|mysql|sqlite|postgres|ora-[0-9]+|union|select)",
    re.IGNORECASE,
)

# GraphQL の複雑度/量制限を欠く DoS リスク検査用。
# サーバを実際に痛めないよう「無害だが安くない数」だけを送り、制限の有無を見る。
_DOS_ALIAS_COUNT = 100   # エイリアス増幅（field 重複）の本数
_DOS_NEST_DEPTH = 12     # introspection の深いネストの段数

# 複雑度/深度/量の制限に引っかかったことを示すエラー語彙。これらが返るなら
# サーバ側に保護があるとみなし DoS リスクは報告しない（誤検知抑止）。
_DOS_LIMIT_ERROR_RE = re.compile(
    r"(max(imum)?[\s_-]*(query)?[\s_-]*(depth|complexity|alias|node|cost)"
    r"|query[\s_-]*(is[\s_-]*)?too[\s_-]*(deep|complex|large)"
    r"|depth[\s_-]*limit|complexity[\s_-]*(limit|exceeded)"
    r"|too[\s_-]*many[\s_-]*(aliases|nodes)|cost[\s_-]*limit"
    r"|exceeds[\s_-]*maximum)",
    re.IGNORECASE,
)


def build_alias_amplification_query(count: int) -> str:
    """``count`` 本のエイリアスで同一フィールド(__typename)を増幅するクエリ（純粋）。

    例: ``{ a0: __typename a1: __typename ... }``。alias/複雑度の上限が無ければ
    サーバは全 alias を素直に処理する。__typename は安価なので、上限の有無を
    確かめつつ実害を出さない。
    """
    count = max(1, int(count))
    aliases = " ".join(f"a{i}: __typename" for i in range(count))
    return "{ " + aliases + " }"


def build_deep_introspection_query(depth: int) -> str:
    """``depth`` 段ネストした introspection クエリを組む（純粋）。

    ``__type.ofType.ofType...`` を深く重ね、深度制限の有無を観測する。
    """
    depth = max(1, int(depth))
    inner = "name"
    for _ in range(depth):
        inner = f"ofType {{ name {inner} }}"
    return "{ __schema { types { name kind " + inner + " } } }"


def detect_alias_amplification(data: object, count: int) -> bool:
    """エイリアス増幅クエリが「制限なく」受理されたかを判定する（純粋）。

    ``data`` は ``resp.json()`` 済みの値。最後の alias キー（``a{count-1}``）が
    ``data`` 配下に存在し、かつ complexity/alias 制限エラーが無ければ True。
    制限エラーが含まれていれば（保護あり）False。
    """
    if not isinstance(data, dict):
        return False
    # 制限系エラーがあれば保護されている → 報告しない
    errors = data.get("errors")
    if errors:
        try:
            blob = json.dumps(errors)
        except (TypeError, ValueError):
            blob = str(errors)
        if _DOS_LIMIT_ERROR_RE.search(blob):
            return False
    payload = data.get("data")
    if not isinstance(payload, dict):
        return False
    last_alias = f"a{max(1, int(count)) - 1}"
    return last_alias in payload


def detect_no_depth_limit(data: object) -> bool:
    """深いネスト introspection が深度/複雑度制限なく受理されたか（純粋）。

    深度制限を持つサーバは深いクエリを depth/complexity エラーで弾く。``data`` に
    制限系エラーが無く、かつ ``data.__schema`` が返っていれば「深度制限なし」と
    みなす。エイリアス増幅（breadth）と本判定（depth）の **両方** が成立して初めて
    DoS リスクと報告することで、「安いエイリアスを 100 個受けただけ」では誤検知
    しないようにする。
    """
    if not isinstance(data, dict):
        return False
    errors = data.get("errors")
    if errors:
        try:
            blob = json.dumps(errors)
        except (TypeError, ValueError):
            blob = str(errors)
        if _DOS_LIMIT_ERROR_RE.search(blob):
            return False
        # 深いクエリでエラーが出た（depth 以外でも）なら制限ありとみなし報告しない
        return False
    payload = data.get("data")
    return isinstance(payload, dict) and "__schema" in payload


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class GraphQLScanner(BaseScanner):
    """
    Probes well-known GraphQL endpoints on the target host and tests for
    common GraphQL-specific vulnerabilities.
    """

    HAS_PAGE_LEVEL = True
    CHECK_TYPE = "graphql"
    ALWAYS_STATE_CHANGING = True
    SEVERITY = "medium"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._tested_endpoints: set[str] = set()
        self._tested_urls: set[str] = set()
        self._confirmed_endpoints: list[str] = []

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
        return []  # GraphQL scanning is endpoint-level

    def _is_api_or_graphql_url(self, url: str) -> bool:
        """具体 URL を probe 対象にしてよいか（API スペック由来 or GraphQL らしいパス）。

        全クロールページへ GraphQL probe を撒かないためのゲート。API スペック由来 URL
        （``api_seed_urls`` / ``api_seed_requests``）か、パスが GraphQL を示唆する
        （``graphql`` を含む / ``/gql`` 等）ときだけ True。
        """
        try:
            if url in (getattr(self.engine, "api_seed_urls", None) or ()):
                return True
            for t in (getattr(self.engine, "api_seed_requests", None) or ()):
                if getattr(t, "url", None) == url:
                    return True
        except Exception:
            pass
        path = urlparse(url).path.lower()
        return (
            "graphql" in path
            or path.endswith("/gql")
            or "/gql/" in path
        )

    async def scan_page(self, url: str) -> list[Finding]:
        """
        On first call (or whenever a new origin is encountered) probe all
        known GraphQL paths on that origin. The exact ``url`` is also probed so
        API-spec endpoints on non-standard paths (e.g. ``/gql``) are exercised.
        """
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        candidates: list[str] = []
        # 既知パスは origin ごとに 1 回だけ掃引する
        if origin not in self._tested_endpoints:
            self._tested_endpoints.add(origin)
            candidates.extend(urljoin(origin, p) for p in _GRAPHQL_PATHS)
        # API スペック等から渡された具体 URL（/gql 等の非標準パス）も明示的に検査する。
        # ただし全クロールページ（/about, /account 等）へ GraphQL probe を撒かないよう、
        # API スペック由来 URL か GraphQL らしいパスのときだけ候補に加える（既知パスの
        # origin 掃引は別途無条件で実施済み）。
        norm_url = url.split("#", 1)[0]
        if norm_url and norm_url not in self._tested_urls:
            self._tested_urls.add(norm_url)
            if norm_url not in candidates and self._is_api_or_graphql_url(norm_url):
                candidates.append(norm_url)
        if not candidates:
            return []

        timeout = float(getattr(self.engine, "timeout", 30))

        findings: list[Finding] = []

        for endpoint in candidates:
            # Build per-endpoint headers so candidates on a disallowed origin
            # never inherit HeaderManager custom authentication keys.
            req_headers = dict(_HEADERS)
            if hasattr(self.engine, "auth_headers"):
                req_headers.update(self.auth_headers_for_url(endpoint))
            else:
                cookies_str = getattr(self.engine, "cookies", "") or ""
                if cookies_str:
                    req_headers["Cookie"] = cookies_str
            if await self._is_graphql(endpoint, req_headers, timeout):
                self._confirmed_endpoints.append(endpoint)
                endpoint_findings = await self._test_endpoint(
                    endpoint, req_headers, timeout
                )
                findings.extend(endpoint_findings)

        return findings

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def _note_auth_failure(self, resp, endpoint: str) -> bool:
        """応答がセッション失効（401/ログインフォーム）なら engine へ通知する。

        保護された GraphQL エンドポイントは GET プレフライト（_api_session_looks_expired）
        が 400/405 で失効を検知できない一方、実 POST が 401 を返すことがある。その場合
        engine._api_auth_failed を立てないと、_run_api_template_checks が未認証の空結果を
        「済み」記録し --resume が恒久スキップしてしまう。mass_assignment/proto と同じく
        session_guard で判定して失効を通知する。
        """
        from wscan import session_guard
        try:
            out = session_guard.looks_logged_out(
                status=resp.status_code,
                final_url=str(getattr(resp, "url", endpoint)),
                body=resp.text,
                login_url=getattr(self.engine, "login_url", ""),
                logged_in_marker=getattr(self.engine, "logged_in_marker", ""),
            )
        except Exception:
            return False
        if out:
            try:
                self.engine._api_auth_failed = True
            except Exception:
                pass
        return out

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
                headers=headers,
                **self._client_transport_kwargs(),
            ) as client:
                resp = await client.post(endpoint, json=query)
                self._record_probe_status(resp)
                # 実 POST が 401/ログイン化 → 失効を通知して中断（resume の誤スキップ防止）
                if self._note_auth_failure(resp, endpoint):
                    return False
                if resp.status_code in (200, 400):
                    body = resp.text
                    if _GQL_RESPONSE_RE.search(body):
                        return True
                # Some GQL servers accept GET with query param
                resp2 = await client.get(
                    endpoint,
                    params={"query": "{ __typename }"},
                )
                self._record_probe_status(resp2)
                if self._note_auth_failure(resp2, endpoint):
                    return False
                if resp2.status_code in (200, 400):
                    if _GQL_RESPONSE_RE.search(resp2.text):
                        return True
        except Exception as exc:
            self._record_scan_note(
                f"probe_error:{self.CHECK_TYPE}:{type(exc).__name__}"
            )
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

        # 2b. Complexity/amount limits missing (DoS risk)
        await self._test_dos(endpoint, headers, timeout, findings)

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
                headers=headers,
                **self._client_transport_kwargs(),
            ) as client:
                resp = await client.post(endpoint, json=query)
                self._record_probe_status(resp)
                if resp.status_code != 200:
                    return None
                data = resp.json()
        except Exception as exc:
            self._record_scan_note(
                f"probe_error:{self.CHECK_TYPE}:{type(exc).__name__}"
            )
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
            confidence="likely",
            evidence_type="graphql_introspection",
            evidence_details={"type_count": type_count},
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
                headers=headers,
                **self._client_transport_kwargs(),
            ) as client:
                resp = await client.post(endpoint, json=batch_query)
                self._record_probe_status(resp)
                if resp.status_code != 200:
                    return
                body = resp.text
        except Exception as exc:
            self._record_scan_note(
                f"probe_error:{self.CHECK_TYPE}:{type(exc).__name__}"
            )
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
            confidence="likely",
            evidence_type="graphql_batch",
            evidence_details={"operation_count": len(batch_query)},
        ))

    async def _test_dos(
        self,
        endpoint: str,
        headers: dict,
        timeout: float,
        findings: list[Finding],
    ) -> None:
        """クエリ複雑度/量の制限が無いか（DoS リスク）を検査する。

        誤検知を避けるため **breadth（エイリアス増幅）と depth（深いネスト
        introspection）の両方** が制限エラー無しに受理されたときだけ報告する。
        「安価な __typename を 100 個受け付けた」だけでは（複雑度制限を持つ正常な
        サーバでも起こりうるため）報告しない。実害を出さないよう本数/段数は控えめ。
        """
        alias_query = build_alias_amplification_query(_DOS_ALIAS_COUNT)
        depth_query = build_deep_introspection_query(_DOS_NEST_DEPTH)
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=timeout,
                headers=headers,
                **self._client_transport_kwargs(),
            ) as client:
                r1 = await client.post(endpoint, json={"query": alias_query})
                self._record_probe_status(r1)
                r2 = await client.post(endpoint, json={"query": depth_query})
                self._record_probe_status(r2)
                if r1.status_code != 200 or r2.status_code != 200:
                    return
                alias_data = r1.json()
                depth_data = r2.json()
        except Exception as exc:
            self._record_scan_note(
                f"probe_error:{self.CHECK_TYPE}:{type(exc).__name__}"
            )
            return

        alias_ok = detect_alias_amplification(alias_data, _DOS_ALIAS_COUNT)
        depth_ok = detect_no_depth_limit(depth_data)
        # 両シグナルが揃ったときのみ報告（breadth だけ／depth だけでは不十分）
        if not (alias_ok and depth_ok):
            return

        findings.append(Finding(
            check_type="graphql_dos",
            severity="medium",
            url=endpoint,
            field_name="(GraphQL query cost)",
            payload=f"aliases={_DOS_ALIAS_COUNT}, introspection depth={_DOS_NEST_DEPTH}",
            evidence=(
                f"GraphQL endpoint {endpoint} accepted both a {_DOS_ALIAS_COUNT}-alias "
                f"query (breadth) and a depth-{_DOS_NEST_DEPTH} nested introspection "
                f"query (depth) with no complexity/depth/alias limit error. The absence "
                f"of limits on both axes lets an attacker craft expensive queries to "
                f"exhaust server resources (DoS). Enforce query depth/complexity limits "
                f"and alias/node caps."
            ),
            request={"url": endpoint, "method": "POST",
                     "body": json.dumps({"query": alias_query})[:500]},
            response={"status": 200, "url": endpoint},
            confidence="tentative",
            evidence_type="graphql_dos",
            evidence_details={"alias_count": _DOS_ALIAS_COUNT,
                              "introspection_depth": _DOS_NEST_DEPTH},
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
                        headers=headers,
                        **self._client_transport_kwargs(),
                    ) as client:
                        resp = await client.post(endpoint, json=gql_body)
                        self._record_probe_status(resp)
                        body = resp.text[:4000]
                except Exception as exc:
                    self._record_scan_note(
                        f"probe_error:{self.CHECK_TYPE}:{type(exc).__name__}"
                    )
                    continue

                matched, expected = self._classify_injection_response(
                    vuln_type, payload_str, body
                )
                if matched:
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
                        confidence="likely",
                        evidence_type=f"graphql_injection_{vuln_type}",
                        evidence_details={
                            "vuln_type": vuln_type,
                            "type_name": type_name,
                            "field_name": field_name,
                            "arg_name": arg_name,
                            "expected": expected,
                        },
                    ))
                    break  # One finding per field is sufficient

    def _classify_injection_response(
        self,
        vuln_type: str,
        payload: str,
        body: str,
    ) -> tuple[bool, str]:
        if vuln_type == "sqli":
            match = _SQL_ERROR_RE.search(body or "")
            return bool(match), match.group(0) if match else ""
        if vuln_type == "ssti":
            return "49" in (body or ""), "49"
        return payload in (body or ""), payload

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
            confidence="likely",
            evidence_type="graphql_sensitive_schema",
            evidence_details={"sensitive_names": sensitive_names[:20]},
        ))

    async def verify_finding(self, finding: Finding) -> bool | None:
        headers = dict(_HEADERS)
        if hasattr(self.engine, "auth_headers"):
            headers.update(self.auth_headers_for_url(finding.url))
        else:
            cookies_str = getattr(self.engine, "cookies", "") or ""
            if cookies_str:
                headers["Cookie"] = cookies_str
        timeout = float(getattr(self.engine, "timeout", 30))

        if finding.check_type == "graphql_introspection":
            schema = await self._fetch_schema(finding.url, headers, timeout)
            return bool(schema and schema.get("types"))

        if finding.check_type == "graphql_batch":
            body = (finding.request or {}).get("body")
            try:
                payload = json.loads(body) if body else [
                    {"query": "{ __typename }"},
                    {"query": "{ __typename }"},
                ]
            except json.JSONDecodeError:
                payload = [{"query": "{ __typename }"}, {"query": "{ __typename }"}]
            status, text = await self._post_json(finding.url, payload, headers, timeout)
            return status == 200 and text.strip().startswith("[")

        if finding.check_type == "graphql_injection":
            body = (finding.request or {}).get("body")
            if not body:
                return None
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                return None
            status, text = await self._post_json(finding.url, payload, headers, timeout)
            if status <= 0:
                return None
            details = getattr(finding, "evidence_details", {}) or {}
            expected = details.get("expected") or finding.payload
            vuln_type = details.get("vuln_type")
            if vuln_type == "sqli":
                return bool(_SQL_ERROR_RE.search(text))
            return expected in text

        if finding.check_type == "graphql_sensitive":
            schema = await self._fetch_schema(finding.url, headers, timeout)
            if not schema:
                return None
            names: list[str] = []
            self._test_sensitive_schema(finding.url, schema, findings := [])
            if findings:
                names = findings[0].evidence_details.get("sensitive_names", [])
            original = (getattr(finding, "evidence_details", {}) or {}).get("sensitive_names", [])
            return bool(set(original).intersection(names)) if original else bool(names)

        return None

    async def _post_json(
        self,
        endpoint: str,
        payload,
        headers: dict,
        timeout: float,
    ) -> tuple[int, str]:
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=timeout,
                headers=headers,
                **self._client_transport_kwargs(),
            ) as client:
                resp = await client.post(endpoint, json=payload)
                self._record_probe_status(resp)
                return resp.status_code, resp.text
        except Exception as exc:
            self._record_scan_note(
                f"probe_error:{self.CHECK_TYPE}:{type(exc).__name__}"
            )
            return 0, ""

    async def _fetch_schema(
        self,
        endpoint: str,
        headers: dict,
        timeout: float,
    ) -> Optional[dict]:
        status, text = await self._post_json(
            endpoint,
            {"query": _INTROSPECTION_QUERY},
            headers,
            timeout,
        )
        if status != 200:
            return None
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        return (data.get("data") or {}).get("__schema")
