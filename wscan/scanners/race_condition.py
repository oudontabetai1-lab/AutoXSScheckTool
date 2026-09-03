"""
Race Condition / TOCTOU Scanner
Sends a burst of identical state-changing requests in parallel and checks
whether the server processes them more than once (double-spend, duplicate
registration, inventory oversell, etc.).

Only active on endpoints that look like state-changing operations (charge,
buy, register, transfer, submit, coupon, apply, vote, etc.).
"""
import asyncio
import re
from typing import TYPE_CHECKING
from urllib.parse import urlencode, urljoin

import httpx

from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    PayloadShape, Prerequisite, ScannerContract, StateChangeClass, TransportKind,
    ValueKind,
)

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine

_STATE_CHANGE_RE = re.compile(
    r"(?:buy|purchase|order|checkout|pay(?:ment)?|charge|transfer|"
    r"register|signup|sign.up|coupon|promo|discount|apply|redeem|"
    r"submit|vote|like|follow|confirm|activate|withdraw|refund)",
    re.IGNORECASE,
)

_DUPLICATE_RE = re.compile(
    r"(?:already|duplicate|exists|conflict|twice|double|"
    r"insufficient|balance|limit\s+exceeded|only\s+once)",
    re.IGNORECASE,
)

_SUCCESS_RE = re.compile(
    r"(?:success|confirmed|completed|accepted|processed|approved|thank)",
    re.IGNORECASE,
)

_BURST_SIZE = 8  # simultaneous requests per race probe


def _looks_like_state_change(url: str, field: dict) -> bool:
    name = (field.get("name") or field.get("id") or "").lower()
    return bool(_STATE_CHANGE_RE.search(url) or _STATE_CHANGE_RE.search(name))


class RaceConditionScanner(BaseScanner):
    """Race condition / TOCTOU vulnerability scanner."""

    HAS_PAGE_LEVEL = True
    CHECK_TYPE = "race_condition"
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
                reason="page/response 解析でありパラメータ注入をしない",
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
        prerequisites=frozenset({Prerequisite.SECOND_REQUEST}),
        state_change=StateChangeClass.CONDITIONAL,
        cost=CostClass.HIGH,
    )

    SEVERITY = "high"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._checked_urls: set[str] = set()

    async def _form_request_template(
        self,
        page_url: str,
        form_index: int,
    ) -> tuple[str, str, str, dict]:
        await self.browser.navigate(page_url)
        form = await self.browser.page.evaluate(
            """
            ([formIndex]) => {
                const form = document.querySelectorAll('form')[formIndex];
                if (!form) return null;
                const fields = {};
                const els = form.querySelectorAll(
                    'input:not([type=submit]):not([type=button]):not([type=reset]):not([type=image]):not([type=file]), textarea, select'
                );
                els.forEach((el) => {
                    const name = el.name || el.id;
                    if (!name || el.type === 'checkbox' || el.type === 'radio') return;
                    fields[name] = el.value || 'wscan-race';
                });
                return {
                    action: form.action || window.location.href,
                    method: (form.method || 'GET').toUpperCase(),
                    fields,
                };
            }
            """,
            [form_index],
        )
        if not form:
            return page_url, "GET", "", {}
        action_url = urljoin(page_url, form.get("action") or page_url)
        method = (form.get("method") or "GET").upper()
        body = urlencode(form.get("fields") or {})
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
        }
        return action_url, method, body, headers

    async def _send_burst(
        self,
        url: str,
        method: str,
        body: str,
        headers: dict,
    ) -> list:
        timeout = getattr(self.engine, "timeout", 15)
        client_kwargs: dict = {
            "timeout": timeout,
            "follow_redirects": False,
        }
        if hasattr(self.engine, "httpx_client_kwargs"):
            client_kwargs = self.engine.httpx_client_kwargs(**client_kwargs)
        elif getattr(self.engine, "proxy", ""):
            client_kwargs["proxy"] = getattr(self.engine, "proxy", "")
            client_kwargs["verify"] = False
        if hasattr(self.engine, "auth_headers"):
            base_headers = self.auth_headers_for_url(url)
            base_headers.update(headers or {})
            headers = base_headers

        async def _one_request(session: httpx.AsyncClient) -> httpx.Response:
            if method == "POST":
                return await session.post(url, content=body, headers=headers)
            return await session.get(url, headers=headers)

        async with httpx.AsyncClient(**client_kwargs) as session:
            responses = await asyncio.gather(
                *[_one_request(session) for _ in range(_BURST_SIZE)],
                return_exceptions=True,
            )
            for response in responses:
                if not isinstance(response, Exception):
                    self._record_probe_status(response)
        return responses

    def _classify_responses(self, responses: list, url: str) -> tuple[str, dict] | None:
        ok_responses = [
            r for r in responses
            if not isinstance(r, Exception)
            and hasattr(r, "text")
            and _SUCCESS_RE.search(r.text)
        ]
        dup_responses = [
            r for r in responses
            if not isinstance(r, Exception)
            and hasattr(r, "text")
            and _DUPLICATE_RE.search(r.text)
        ]
        if len(ok_responses) >= 2:
            evidence = (
                f"Race condition: {len(ok_responses)}/{_BURST_SIZE} parallel requests "
                f"to {url} returned a success response, "
                + (f"while {len(dup_responses)} returned a duplicate/conflict error. " if dup_responses else "")
                + "The endpoint may process the same state change multiple times under concurrent load."
            )
            return evidence, {
                "success_count": len(ok_responses),
                "duplicate_count": len(dup_responses),
                "burst_size": _BURST_SIZE,
            }
        return None

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        if is_url_param:
            return []
        action_url, method, body, headers = await self._form_request_template(url, form_index)
        key = f"{method} {action_url} {body}"
        if key in self._checked_urls:
            return []
        if not (
            _STATE_CHANGE_RE.search(action_url)
            or _looks_like_state_change(url, field)
            or _STATE_CHANGE_RE.search(body)
        ):
            return []
        self._checked_urls.add(key)

        if self.monitor:
            await self.monitor.emit_status(f"Race condition form probe on {action_url}")

        try:
            responses = await self._send_burst(action_url, method, body, headers)
        except Exception as exc:
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] race_condition: form burst failed on {action_url}: {exc}"
                )
            return []

        classified = self._classify_responses(responses, action_url)
        if not classified:
            return []
        evidence, details = classified
        details.update({"method": method, "body": body, "headers": headers})
        finding = await self.record_finding(
            url=action_url,
            field_name=field.get("name") or field.get("id") or "(form race)",
            payload=f"{_BURST_SIZE}x simultaneous {method} requests",
            evidence=evidence,
            pair={
                "request": {"url": action_url, "method": method, "body": body},
                "response": {
                    "status": "mixed",
                    "body": f"{details['success_count']} success, {details['duplicate_count']} duplicate",
                },
            },
            severity="high",
            confidence="likely",
            evidence_type="race_condition_burst",
            evidence_details=details,
        )
        return [finding]

    async def scan_page(self, url: str) -> list[Finding]:
        if url in self._checked_urls:
            return []
        if not _STATE_CHANGE_RE.search(url):
            return []
        self._checked_urls.add(url)

        if self.monitor:
            await self.monitor.emit_status(f"Race condition probe on {url}")

        # Capture the last form submission body from the browser's network log
        pair = self.current_page_pair(url)
        req = pair.get("request", {})
        method = req.get("method", "GET").upper()
        body = req.get("post_data") or req.get("body") or ""
        headers = {
            k: v for k, v in req.get("headers", {}).items()
            if k.lower() not in ("content-length",)
        }
        if not headers.get("User-Agent") and not headers.get("user-agent"):
            headers["User-Agent"] = (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )

        # state profile gate: page-level burst は捕捉済み POST を 8 回リプレイするため、
        # _scan_field の事前 gate を通らない。ここで profile を適用し、read-only や
        # controlled-write の破壊的操作（purchase/transfer 等）の反復送信を防ぐ。
        from wscan.state_profile import may_submit
        if not may_submit(
            getattr(self.engine, "state_profile", "unrestricted"),
            method=method,
            action=url,
        ):
            self._record_scan_note(f"state_change_skipped:{self.CHECK_TYPE}")
            return []

        try:
            responses = await self._send_burst(url, method, body, headers)
        except Exception as exc:
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] race_condition: burst failed on {url}: {exc}"
                )
            return []

        classified = self._classify_responses(responses, url)
        if classified:
            evidence, details = classified
            details.update({"method": method, "body": body, "headers": headers})
            finding = await self.record_finding(
                url=url,
                field_name="(page-level race)",
                payload=f"{_BURST_SIZE}x simultaneous {method} requests",
                evidence=evidence,
                pair=pair,
                severity="high",
                confidence="likely",
                evidence_type="race_condition_burst",
                evidence_details=details,
            )
            return [finding]

        return []

    async def verify_finding(self, finding: Finding) -> bool | None:
        details = getattr(finding, "evidence_details", {}) or {}
        method = details.get("method")
        body = details.get("body", "")
        headers = details.get("headers", {})
        if not method:
            return None
        try:
            responses = await self._send_burst(finding.url, method, body, headers)
        except Exception:
            return None
        return bool(self._classify_responses(responses, finding.url))
