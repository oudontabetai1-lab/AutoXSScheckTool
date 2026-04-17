"""
NoSQL Injection Scanner (V-7)
Targets MongoDB and similar NoSQL databases by injecting operator-based
payloads into form fields and URL parameters.

Payloads use MongoDB query operators: $gt, $ne, $regex, $where, $or, etc.
Both JSON body and parameter pollution variants are tested.

Detection:
  - Authentication bypass: response length / content differs significantly
    between the normal request and the NoSQL-injected request.
  - Error pattern matching: MongoDB/Mongoose error strings in the response.
  - Boolean-based: response with $ne:null differs from response with a real value.
"""
import asyncio
import re
import json
from typing import TYPE_CHECKING

import httpx

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine

# MongoDB error patterns
_NOSQL_ERROR_PATTERNS = [
    r"MongoError",
    r"MongoServerError",
    r"CastError",
    r"mongoose",
    r"\$where",
    r"BSON",
    r"ObjectId failed",
    r"Mongo.*exception",
    r"mongo.*error",
    r"SyntaxError.*JSON",
    r"Unexpected token.*JSON",
]

# NoSQL operator payloads for form fields (parameter pollution)
_PARAM_PAYLOADS = [
    # Authentication bypass — the field is set to an object with $ne
    '{"$ne": ""}',
    '{"$gt": ""}',
    '{"$regex": ".*"}',
    '{"$ne": null}',
    '{"$in": [""]}',
    # Nested operator arrays
    '{"$or": [{"a": "a"}, {"b": "b"}]}',
]

# JSON-body operator payloads (for APIs that accept JSON)
_JSON_BODY_PAYLOADS = [
    {"$ne": "invalid_value_wscan"},
    {"$gt": ""},
    {"$regex": ".*"},
    {"$ne": None},
]


class NoSQLInjectionScanner(BaseScanner):
    """NoSQL injection scanner targeting MongoDB operator injection."""

    CHECK_TYPE = "nosql"
    SEVERITY = "high"

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        field_name = field.get("name", "unknown")
        field_type = field.get("type", "text").lower()

        # Skip non-text fields
        if field_type in ("file", "checkbox", "radio", "submit", "button", "image", "reset"):
            return []

        if self.monitor:
            await self.monitor.emit_status(
                f"NoSQL injection test: {field_name} on {url}"
            )

        findings = []

        # ── Baseline request ──────────────────────────────────────────
        try:
            if is_url_param:
                baseline_src, baseline_pair = await self.browser.test_url_param(
                    url, field_name, "baseline_value_wscan"
                )
            else:
                await self.browser.navigate(url)
                baseline_src, baseline_pair = await self.browser.fill_and_submit_form(
                    form_index, field_name, "baseline_value_wscan"
                )
        except Exception:
            return []

        baseline_len = len(baseline_src)

        # ── Parameter pollution payloads ──────────────────────────────
        for payload in _PARAM_PAYLOADS:
            if self.monitor:
                await self.monitor.emit_payload_test(field_name, payload, "nosql", url)
            try:
                if is_url_param:
                    # Inject as array: field[$ne]=value
                    # Encode operator as bracket notation
                    op_param = field_name + "[$ne]"
                    src, pair = await self.browser.test_url_param(
                        url, op_param, "wscan_invalid"
                    )
                else:
                    await self.browser.navigate(url)
                    src, pair = await self.browser.fill_and_submit_form(
                        form_index, field_name, payload
                    )

                # Check for error patterns
                err = self.check_response_for_patterns(src, _NOSQL_ERROR_PATTERNS)
                if err:
                    finding = await self.record_finding(
                        url=url,
                        field_name=field_name,
                        payload=payload,
                        evidence=(
                            f"NoSQL injection error response: '{err[:150]}'. "
                            f"The server may be using MongoDB/Mongoose."
                        ),
                        pair=pair,
                        severity="high",
                    )
                    findings.append(finding)
                    break

                # Boolean-based: significant response length difference.
                # Threshold scales with baseline so that tiny/huge responses
                # aren't false-positive-prone. 500 bytes is the floor.
                delta = abs(len(src) - baseline_len)
                min_delta = max(500, int(baseline_len * 0.25))
                if delta > min_delta and len(src) > baseline_len:
                    finding = await self.record_finding(
                        url=url,
                        field_name=field_name,
                        payload=payload,
                        evidence=(
                            f"NoSQL injection (boolean-based): response size increased by "
                            f"{delta} bytes with operator payload vs baseline. "
                            f"Possible authentication bypass or data exfiltration."
                        ),
                        pair=pair,
                        severity="high",
                    )
                    findings.append(finding)
                    break

            except Exception as exc:
                if self.monitor:
                    await self.monitor.emit_status(
                        f"[warn] nosql: probe failed on {field_name} @ {url}: {exc}"
                    )
                continue
            await asyncio.sleep(0.2 * self.sleep_factor)

        # ── JSON body injection (for JSON-accepting endpoints) ─────────
        if not findings:
            findings += await self._test_json_body(url, field_name, baseline_len)

        return findings

    async def scan_page(self, url: str) -> list[Finding]:
        return []

    async def _test_json_body(
        self, url: str, field_name: str, baseline_len: int
    ) -> list[Finding]:
        """Send JSON body with operator payloads to the same URL."""
        findings = []
        proxy = getattr(self.engine, "proxy", "") or None
        timeout = getattr(self.engine, "timeout", 15)
        kwargs: dict = {
            "timeout": timeout,
            "follow_redirects": True,
            "headers": {"Content-Type": "application/json"},
        }
        if proxy:
            kwargs["proxy"] = proxy

        for op_payload in _JSON_BODY_PAYLOADS:
            body = json.dumps({field_name: op_payload})
            try:
                async with httpx.AsyncClient(**kwargs) as client:
                    r = await client.post(url, content=body)
                resp_text = r.text

                err = self.check_response_for_patterns(resp_text, _NOSQL_ERROR_PATTERNS)
                if err:
                    pair = {
                        "request": {"url": url, "body": body},
                        "response": {"status": r.status_code, "body": resp_text[:1000]},
                    }
                    finding = await self.record_finding(
                        url=url,
                        field_name=field_name,
                        payload=body,
                        evidence=(
                            f"NoSQL injection via JSON body: MongoDB error '{err[:150]}' "
                            f"returned when injecting operator in '{field_name}'."
                        ),
                        pair=pair,
                        severity="high",
                    )
                    findings.append(finding)
                    break
            except Exception:
                continue

        return findings
