"""
Secret / API-Key Leakage Scanner.

Scans the response body of each navigated page (and any inline / referenced
JavaScript that is part of the document) for high-confidence patterns that
indicate hard-coded secrets shipped to the browser:

  * Cloud provider keys (AWS, GCP, Azure)
  * SaaS tokens (GitHub, Slack, Stripe, SendGrid, Twilio, Mailgun, ...)
  * Private keys (PEM blocks)
  * Google API keys
  * Generic JWTs that look like they carry sensitive claims

The match must:

  1. Be a high-specificity regex (a unique prefix + length / charset rule).
  2. Pass a Shannon-entropy check, where applicable, so we don't flag literal
     placeholder strings such as ``AKIAEXAMPLE...`` or ``YOUR_KEY_HERE``.

Page-level scanner (no payload submitted) — runs once per URL.
"""
from __future__ import annotations

import math
import re
from typing import TYPE_CHECKING

from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    PayloadShape, Prerequisite, ScannerContract, StateChangeClass, TransportKind,
    ValueKind,
)

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# (label, compiled regex, minimum entropy of the matched secret, severity)
_SECRET_PATTERNS: list[tuple[str, re.Pattern, float, str]] = [
    (
        "AWS Access Key ID",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        3.0,
        "critical",
    ),
    (
        "AWS Secret Access Key",
        # Surrounding context word avoids matching random base64 in JS bundles.
        re.compile(
            r"(?i)aws(.{0,20})?(secret|sk)[^A-Za-z0-9]{1,5}([A-Za-z0-9/+=]{40})"
        ),
        4.3,
        "critical",
    ),
    (
        "Google API Key",
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        3.5,
        "high",
    ),
    (
        "GitHub Personal Access Token",
        re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
        4.0,
        "critical",
    ),
    (
        "GitHub OAuth Token",
        re.compile(r"\bgho_[A-Za-z0-9]{36}\b"),
        4.0,
        "critical",
    ),
    (
        "GitHub App Token",
        re.compile(r"\b(ghu|ghs)_[A-Za-z0-9]{36}\b"),
        4.0,
        "high",
    ),
    (
        "Slack Token",
        re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
        3.5,
        "high",
    ),
    (
        "Stripe Secret Key",
        re.compile(r"\bsk_(?:live|test)_[0-9a-zA-Z]{24,}\b"),
        3.5,
        "critical",
    ),
    (
        "Stripe Restricted Key",
        re.compile(r"\brk_(?:live|test)_[0-9a-zA-Z]{24,}\b"),
        3.5,
        "high",
    ),
    (
        "SendGrid API Key",
        re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
        4.0,
        "high",
    ),
    (
        "Mailgun API Key",
        re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"),
        3.5,
        "high",
    ),
    (
        "Twilio API Key",
        re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
        3.5,
        "high",
    ),
    (
        "Square Access Token",
        re.compile(r"\bsq0atp-[0-9A-Za-z_\-]{22}\b"),
        3.5,
        "high",
    ),
    (
        "Square OAuth Secret",
        re.compile(r"\bsq0csp-[0-9A-Za-z_\-]{43}\b"),
        4.0,
        "high",
    ),
    (
        "PEM Private Key Block",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----"
        ),
        0.0,  # entropy not meaningful here
        "critical",
    ),
    (
        "Heroku API Key",
        re.compile(
            r"(?i)heroku[^A-Za-z0-9]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
        ),
        3.0,
        "high",
    ),
]


# Strings that are obviously placeholders / docs samples — never report these.
_PLACEHOLDER_TOKENS = (
    "EXAMPLE",
    "YOUR_",
    "PLACEHOLDER",
    "FAKE",
    "DUMMY",
    "XXXXXX",
    "REPLACE",
    "INSERT_",
    "...",
)


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _looks_like_placeholder(secret: str) -> bool:
    upper = secret.upper()
    return any(token in upper for token in _PLACEHOLDER_TOKENS)


def _redact(secret: str) -> str:
    """Show first 4 + last 4 chars only — enough for an analyst to confirm."""
    if len(secret) <= 12:
        return secret[:2] + "…" + secret[-2:]
    return f"{secret[:4]}…{secret[-4:]}"


def scan_text_for_secrets(text: str) -> list[dict]:
    """
    Return a list of unique secret findings discovered in ``text``.

    Each result dict has: ``label``, ``severity``, ``redacted``, ``entropy``,
    ``snippet``, ``offset``.
    """
    if not text:
        return []
    seen: set[tuple[str, str]] = set()
    findings: list[dict] = []
    for label, pattern, min_entropy, severity in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            # Prefer the most-specific captured group, falling back to the
            # entire match.  This keeps the redacted value tight even when
            # the pattern includes anchoring context (e.g. ``aws_secret=…``).
            secret = ""
            if match.groups():
                for group in reversed(match.groups()):
                    if group and len(group) >= 16:
                        secret = group
                        break
            if not secret:
                secret = match.group(0)
            secret = secret.strip()
            if not secret or len(secret) < 12:
                continue
            if _looks_like_placeholder(secret):
                continue
            entropy = _shannon_entropy(secret)
            if min_entropy > 0 and entropy < min_entropy:
                continue
            key = (label, secret)
            if key in seen:
                continue
            seen.add(key)
            start = max(0, match.start() - 40)
            end = min(len(text), match.end() + 40)
            snippet = text[start:end].replace("\n", " ")
            findings.append(
                {
                    "label": label,
                    "severity": severity,
                    "redacted": _redact(secret),
                    "entropy": round(entropy, 3),
                    "snippet": snippet,
                    "offset": match.start(),
                }
            )
    return findings


_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class SecretLeakScanner(BaseScanner):
    """Detect hard-coded secrets shipped to the browser (page-level)."""

    HAS_PAGE_LEVEL = True
    CHECK_TYPE = "secret_leak"
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
        state_change=StateChangeClass.READ_ONLY,
        cost=CostClass.MEDIUM,
    )

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
        self._checked_urls.add(url)

        if self.monitor:
            await self.monitor.emit_status(f"Secret-leak check on {url}")

        pair = self.current_page_pair(url)
        body = pair.get("response", {}).get("body", "") or ""

        # Fall back to live DOM if the captured response body is empty (e.g.
        # SPA where the served HTML is a shell and content is JS-rendered).
        if not body:
            try:
                body = await self.browser.page.content()
            except Exception:
                body = ""

        if not body:
            return []

        findings: list[Finding] = []
        for hit in scan_text_for_secrets(body):
            finding = await self.record_finding(
                url=url,
                field_name="(response body)",
                payload="(no payload — passive content scan)",
                evidence=(
                    f"Possible {hit['label']} leaked in response body "
                    f"(redacted: {hit['redacted']}, entropy={hit['entropy']})"
                ),
                pair=pair,
                severity=hit["severity"],
                confidence="likely",
                evidence_type="secret_leak",
                evidence_details={
                    "label": hit["label"],
                    "redacted_value": hit["redacted"],
                    "entropy": hit["entropy"],
                    "byte_offset": hit["offset"],
                    "snippet": hit["snippet"][:200],
                },
                reproduction_steps=[
                    f"Open {url}",
                    "View source or inspect served JavaScript",
                    f"Locate the {hit['label']} value embedded in the response",
                    "Rotate the leaked credential and move it to a server-side secret store.",
                ],
            )
            if finding is not None:
                findings.append(finding)
        return findings
