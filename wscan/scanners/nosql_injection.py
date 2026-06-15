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

    def _boolean_expansion(
        self,
        baseline_src: str,
        probe_src: str,
        baseline_src2: str = "",
    ) -> tuple[bool, dict]:
        baseline_len = len(baseline_src or "")
        probe_len = len(probe_src or "")
        baseline_variance = abs(baseline_len - len(baseline_src2 or "")) if baseline_src2 else 0
        delta = probe_len - baseline_len
        min_delta = max(500, int(baseline_len * 0.25), baseline_variance * 4)
        return (
            bool(baseline_len > 0 and delta > min_delta),
            {
                "baseline_length": baseline_len,
                "probe_length": probe_len,
                "delta": delta,
                "baseline_variance": baseline_variance,
                "min_delta": min_delta,
            },
        )

    async def _apply_payload(
        self,
        url: str,
        form_index: int,
        field_name: str,
        payload: str,
        is_url_param: bool,
    ) -> tuple[str, dict]:
        if is_url_param:
            if payload in _PARAM_PAYLOADS:
                return await self.browser.test_url_param(
                    url,
                    field_name + "[$ne]",
                    "wscan_invalid",
                )
            return await self.browser.test_url_param(url, field_name, payload)
        await self.browser.navigate(url)
        return await self.browser.fill_and_submit_form(form_index, field_name, payload)

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
        # baseline もフィールド投入なので監査ログに残す（log_payload_test 一元化の不変条件）。
        await self.log_payload_test(field_name, "baseline_value_wscan", "nosql_baseline", url)
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
        baseline_src2 = ""
        await self.log_payload_test(field_name, "baseline_value_wscan_2", "nosql_baseline_2", url)
        try:
            if is_url_param:
                baseline_src2, _ = await self.browser.test_url_param(
                    url, field_name, "baseline_value_wscan_2"
                )
            else:
                await self.browser.navigate(url)
                baseline_src2, _ = await self.browser.fill_and_submit_form(
                    form_index, field_name, "baseline_value_wscan_2"
                )
        except Exception:
            baseline_src2 = ""

        async def _test_param_payload(payload: str, check_label: str = "nosql") -> bool:
            await self.log_payload_test(field_name, payload, check_label, url)
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
                        evidence_type="nosql_error",
                        evidence_details={"matched_error": err[:150]},
                    )
                    findings.append(finding)
                    return True

                # Boolean-based: significant response length difference.
                # Threshold scales with baseline and natural baseline variance.
                expanded, details = self._boolean_expansion(
                    baseline_src,
                    src,
                    baseline_src2,
                )
                if expanded:
                    finding = await self.record_finding(
                        url=url,
                        field_name=field_name,
                        payload=payload,
                        evidence=(
                            f"NoSQL injection (boolean-based): response size increased by "
                            f"{details['delta']} bytes with operator payload vs baseline. "
                            f"Possible authentication bypass or data exfiltration."
                        ),
                        pair=pair,
                        severity="high",
                        confidence="likely",
                        evidence_type="nosql_boolean",
                        evidence_details={
                            **details,
                            "injected_param": field_name + "[$ne]" if is_url_param else field_name,
                        },
                    )
                    findings.append(finding)
                    return True

            except Exception as exc:
                if self.monitor:
                    await self.monitor.emit_status(
                        f"[warn] nosql: probe failed on {field_name} @ {url}: {exc}"
                    )
                return False
            await asyncio.sleep(0.2 * self.sleep_factor)
            return False

        # ── Parameter pollution payloads ──────────────────────────────
        for payload in _PARAM_PAYLOADS:
            if await _test_param_payload(payload):
                break

        if not findings:
            extra_payloads = await self.evolved_payloads(
                url, form_index, field_name, is_url_param
            )
            for payload in extra_payloads:
                if await _test_param_payload(payload, "nosql_evolved"):
                    break

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
        hdrs: dict = {"Content-Type": "application/json"}
        if hasattr(self.engine, "auth_headers"):
            base = self.engine.auth_headers()
            base.update(hdrs)
            hdrs = base
        kwargs: dict = {
            "timeout": timeout,
            "follow_redirects": True,
            "headers": hdrs,
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
                        evidence_type="nosql_json_error",
                        evidence_details={"matched_error": err[:150]},
                    )
                    findings.append(finding)
                    break
            except Exception:
                continue

        return findings

    async def verify_finding(self, finding: Finding) -> bool | None:
        from urllib.parse import parse_qs, urlparse

        evidence_type = getattr(finding, "evidence_type", "")
        if evidence_type == "nosql_json_error":
            return await self._verify_json_error(finding)

        is_url_param = finding.field_name in parse_qs(
            urlparse(finding.url).query, keep_blank_values=True
        )
        try:
            # verify 時の再投入（baseline ×2 + payload）も監査ログに残す。
            await self.log_payload_test(
                finding.field_name, "baseline_value_wscan", "nosql_verify_baseline", finding.url
            )
            baseline_src, _ = await self._apply_payload(
                finding.url,
                0,
                finding.field_name,
                "baseline_value_wscan",
                is_url_param,
            )
            await self.log_payload_test(
                finding.field_name, "baseline_value_wscan_2", "nosql_verify_baseline_2", finding.url
            )
            baseline_src2, _ = await self._apply_payload(
                finding.url,
                0,
                finding.field_name,
                "baseline_value_wscan_2",
                is_url_param,
            )
            await self.log_payload_test(
                finding.field_name, finding.payload, "nosql_verify", finding.url
            )
            probe_src, _ = await self._apply_payload(
                finding.url,
                0,
                finding.field_name,
                finding.payload,
                is_url_param,
            )
        except Exception:
            return None

        if evidence_type == "nosql_error":
            baseline_err = self.check_response_for_patterns(
                baseline_src or "",
                _NOSQL_ERROR_PATTERNS,
            )
            probe_err = self.check_response_for_patterns(
                probe_src or "",
                _NOSQL_ERROR_PATTERNS,
            )
            return bool(probe_err and not baseline_err)

        if evidence_type == "nosql_boolean":
            expanded, _details = self._boolean_expansion(
                baseline_src,
                probe_src,
                baseline_src2,
            )
            return expanded

        return None

    async def _verify_json_error(self, finding: Finding) -> bool | None:
        proxy = getattr(self.engine, "proxy", "") or None
        timeout = getattr(self.engine, "timeout", 15)
        hdrs: dict = {"Content-Type": "application/json"}
        if hasattr(self.engine, "auth_headers"):
            base = self.engine.auth_headers()
            base.update(hdrs)
            hdrs = base
        kwargs: dict = {
            "timeout": timeout,
            "follow_redirects": True,
            "headers": hdrs,
        }
        if proxy:
            kwargs["proxy"] = proxy

        try:
            safe_body = json.dumps({finding.field_name: "baseline_value_wscan"})
            async with httpx.AsyncClient(**kwargs) as client:
                baseline_resp = await client.post(finding.url, content=safe_body)
                probe_resp = await client.post(finding.url, content=finding.payload)
        except Exception:
            return None

        baseline_err = self.check_response_for_patterns(
            baseline_resp.text,
            _NOSQL_ERROR_PATTERNS,
        )
        probe_err = self.check_response_for_patterns(
            probe_resp.text,
            _NOSQL_ERROR_PATTERNS,
        )
        return bool(probe_err and not baseline_err)
