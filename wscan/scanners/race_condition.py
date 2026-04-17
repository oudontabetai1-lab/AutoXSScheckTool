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

import httpx

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

    CHECK_TYPE = "race_condition"
    SEVERITY = "high"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._checked_urls: set[str] = set()

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        return []

    async def scan_page(self, url: str) -> list[Finding]:
        if url in self._checked_urls:
            return []
        if not _STATE_CHANGE_RE.search(url):
            return []
        self._checked_urls.add(url)

        if self.monitor:
            await self.monitor.emit_status(f"Race condition probe on {url}")

        proxy = getattr(self.engine, "proxy", "") or None
        timeout = getattr(self.engine, "timeout", 15)

        # Capture the last form submission body from the browser's network log
        pair = self.browser.network.latest() or {}
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

        client_kwargs: dict = {
            "timeout": timeout,
            "follow_redirects": False,
            "verify": False,
        }
        if proxy:
            client_kwargs["proxy"] = proxy

        async def _one_request(session: httpx.AsyncClient) -> httpx.Response:
            if method == "POST":
                return await session.post(url, content=body, headers=headers)
            return await session.get(url, headers=headers)

        try:
            async with httpx.AsyncClient(**client_kwargs) as session:
                responses = await asyncio.gather(
                    *[_one_request(session) for _ in range(_BURST_SIZE)],
                    return_exceptions=True,
                )
        except Exception as exc:
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] race_condition: burst failed on {url}: {exc}"
                )
            return []

        ok_responses = [
            r for r in responses
            if isinstance(r, httpx.Response) and _SUCCESS_RE.search(r.text)
        ]
        dup_responses = [
            r for r in responses
            if isinstance(r, httpx.Response) and _DUPLICATE_RE.search(r.text)
        ]

        # Suspicious if multiple requests got "success" AND at least one got a
        # duplicate/conflict error (server caught the race but too late)
        # OR if all _BURST_SIZE returned success (server never deduped).
        if len(ok_responses) >= 2 or (len(ok_responses) >= 1 and len(dup_responses) >= 1):
            evidence = (
                f"Race condition: {len(ok_responses)}/{_BURST_SIZE} parallel requests "
                f"to {url} returned a success response, "
                + (f"and {len(dup_responses)} returned a duplicate/conflict error. " if dup_responses else "")
                + "The endpoint may process the same state change multiple times under concurrent load."
            )
            finding = await self.record_finding(
                url=url,
                field_name="(page-level race)",
                payload=f"{_BURST_SIZE}x simultaneous {method} requests",
                evidence=evidence,
                pair=pair,
                severity="high",
            )
            return [finding]

        return []
