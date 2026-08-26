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

from wscan.injection_point import InjectionPoint

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
    ALWAYS_STATE_CHANGING = True
    SEVERITY = "high"
    # json_body の NoSQL 攻撃は pointer に**構造化オペレータ**(dict `{"$ne": ...}`)を入れる戦略が
    # 必要で、文字列 payload をそのまま送ると `"field": "{...}"` になり検出できない（偽陰性）。
    # 構造化 payload 戦略は PR-b（json 実配線）の担当なので、5b では json capability を持たせない。
    SUPPORTS_JSON_BODY = False

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

    async def scan_injection_point(
        self,
        ip: InjectionPoint,
        field: dict,
    ) -> list[Finding]:
        field_name = ip.display_name or ip.parameter_id
        field_type = field.get("type", "text").lower()

        # json_body は未対応（構造化オペレータ戦略は PR-b）。文字列 payload を送って
        # 偽陰性を出さないよう、また `_test_param_payload` の url_param 用 `[$ne]` 変換や
        # `_test_json_body` の別 POST 経路へ流さないよう、ここで明示的に打ち切る。
        if ip.location == "json_body":
            return []

        # Skip non-text fields
        if field_type in ("file", "checkbox", "radio", "submit", "button", "image", "reset"):
            return []

        if self.monitor:
            await self.monitor.emit_status(
                f"NoSQL injection test: {field_name} on {ip.url}"
            )

        findings = []

        # ── Baseline request ──────────────────────────────────────────
        # baseline もフィールド投入なので監査ログに残す（log_payload_test 一元化の不変条件）。
        await self.log_payload_test(
            field_name, "baseline_value_wscan", "nosql_baseline", ip.url
        )
        try:
            baseline_src, baseline_pair = await self._apply_ip(
                ip, "baseline_value_wscan"
            )
        except Exception:
            return []

        baseline_len = len(baseline_src)
        baseline_src2 = ""
        await self.log_payload_test(
            field_name, "baseline_value_wscan_2", "nosql_baseline_2", ip.url
        )
        try:
            baseline_src2, _ = await self._apply_ip(
                ip, "baseline_value_wscan_2"
            )
        except Exception:
            baseline_src2 = ""

        async def _test_param_payload(payload: str, check_label: str = "nosql") -> bool:
            await self.log_payload_test(field_name, payload, check_label, ip.url)
            try:
                # url_param の ``field[$ne]`` 変換は既存 _apply_payload に委譲する。
                src, pair = await self._apply_ip(ip, payload)

                # Check for error patterns
                err = self.check_response_for_patterns(src, _NOSQL_ERROR_PATTERNS)
                if err:
                    finding = await self.record_finding(
                        url=ip.url,
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
                        injection_point=ip,
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
                        url=ip.url,
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
                            "injected_param": (
                                field_name + "[$ne]"
                                if ip.location == "url_param"
                                else field_name
                            ),
                        },
                        injection_point=ip,
                    )
                    findings.append(finding)
                    return True

            except Exception as exc:
                self._record_scan_note(
                    f"probe_error:{self.CHECK_TYPE}:{type(exc).__name__}"
                )
                if self.monitor:
                    await self.monitor.emit_status(
                        f"[warn] nosql: probe failed on {field_name} @ {ip.url}: {exc}"
                    )
                return False
            await asyncio.sleep(0.2 * self.sleep_factor)
            return False

        # ── Parameter pollution payloads ──────────────────────────────
        for payload in _PARAM_PAYLOADS:
            if await _test_param_payload(payload):
                break

        # evolution wave は legacy browser transport 専用なので JSON では実行しない。
        if not findings and ip.location != "json_body":
            extra_payloads = await self.evolved_payloads(
                ip.url,
                ip.form_index,
                ip.parameter_id,
                ip.legacy_is_url_param(),
                dom_index=ip.submit_index,
            )
            for payload in extra_payloads:
                if await _test_param_payload(payload, "nosql_evolved"):
                    break

        # ── JSON body injection (for JSON-accepting endpoints) ─────────
        # whole-body fallback は pointer 注入ではないため JSON IP ごとに重複実行しない。
        if not findings and ip.location != "json_body":
            findings += await self._test_json_body(ip.url, field_name, baseline_len)

        return findings

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        """従来 API を InjectionPoint 駆動へ接続する互換 wrapper。"""
        name = field.get("name", "unknown")
        ip = (
            InjectionPoint.for_url_param(url, name)
            if is_url_param
            else InjectionPoint.for_form(url, name, form_index)
        )
        return await self.scan_injection_point(ip, field)

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
            base = self.auth_headers_for_url(url)
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
                self._record_probe_status(r)
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
            except Exception as exc:
                self._record_scan_note(
                    f"probe_error:{self.CHECK_TYPE}:{type(exc).__name__}"
                )
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
        if hasattr(finding, "injection_location"):
            ip = self._verify_injection_point(finding, is_url_param)
            if ip is None:
                return None
        else:
            # provenance 属性を持たない旧 Finding 互換。
            ip = (
                InjectionPoint.for_url_param(finding.url, finding.field_name)
                if is_url_param
                else InjectionPoint.for_form(finding.url, finding.field_name, 0)
            )
        try:
            # verify 時の再投入（baseline ×2 + payload）も監査ログに残す。
            await self.log_payload_test(
                finding.field_name, "baseline_value_wscan", "nosql_verify_baseline", finding.url
            )
            baseline_src, _ = await self._apply_ip(ip, "baseline_value_wscan")
            await self.log_payload_test(
                finding.field_name, "baseline_value_wscan_2", "nosql_verify_baseline_2", finding.url
            )
            baseline_src2, _ = await self._apply_ip(
                ip, "baseline_value_wscan_2"
            )
            await self.log_payload_test(
                finding.field_name, finding.payload, "nosql_verify", finding.url
            )
            probe_src, _ = await self._apply_ip(ip, finding.payload)
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
            base = self.auth_headers_for_url(finding.url)
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
                self._record_probe_status(baseline_resp)
                probe_resp = await client.post(finding.url, content=finding.payload)
                self._record_probe_status(probe_resp)
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
