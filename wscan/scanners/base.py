"""
Base Scanner Class
Provides common utilities for all vulnerability scanners.
"""
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# CVSS 3.1 base score lookup table: check_type → (vector_string, numeric_score)
# Vectors use worst-case assumptions for web scanner context.
_CVSS_TABLE: dict[str, tuple[str, float]] = {
    "sqli":              ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "sqli_auth_bypass":  ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "xss":               ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",  8.8),
    "dom_xss":           ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",  8.8),
    "os":                ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "ssti":              ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "path_traversal":    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  7.5),
    "open_redirect":     ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",  6.1),
    "csrf":              ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",  6.5),
    "header_injection":  ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",  5.3),
    "mail_header":       ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",  5.3),
    "clickjacking":      ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",  4.3),
    "session":           ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",  7.4),
    "privesc_unauth":    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  9.1),
    "privesc_vertical":  ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",  8.1),
    "privesc_horizontal":("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",  6.5),
    # V-1〜V-9 new scanners
    "stored_xss":        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",  9.6),
    "cors":              ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",  7.4),
    "info_disclosure":   ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  7.5),
    "host_header":       ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",  5.4),
    "security_headers":  ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",  3.1),
    "nosql":             ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  9.1),
    "deserialization":   ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "request_smuggling": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",  8.7),
    "ssrf":              ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",  9.8),
    # ② GraphQL scanner
    "graphql_introspection": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  5.3),
    "graphql_injection":     ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "graphql_batch":         ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",  5.3),
    "graphql_sensitive":     ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  5.3),
    # ④ JWT scanner
    "jwt_alg_none":      ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",  9.6),
    "jwt_weak_secret":   ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",  9.6),
    "jwt_kid_injection": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "jwt_payload_tamper":("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",  9.6),
    "jwt_no_expiry":     ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  5.3),
    "jwt_sensitive_data":("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  5.3),
    # A: Additional privesc check types
    "privesc_param_idor":("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",  6.5),
    "privesc_cross_acct":("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",  8.1),
    "privesc_action":    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",  8.1),
    "privesc_bypass":    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",  8.1),
    # Phase-4 new scanners
    "xxe":               ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "ldap":              ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",  9.6),
    "file_upload":       ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "race_condition":    ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",  6.8),
    "websocket":         ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",  9.6),
}


def _cvss_for(check_type: str) -> tuple[str, float]:
    """Return (vector, score) for a check type, or empty defaults."""
    base = check_type.split("_")[0] if "_" in check_type else check_type
    return _CVSS_TABLE.get(check_type) or _CVSS_TABLE.get(base, ("", 0.0))


def finding_dedup_key(
    check_type: str,
    url: str,
    field_name: str,
    evidence_type: str = "",
) -> tuple[str, str, str, str]:
    """
    Deduplicate exact evidence, not entire inputs.

    A single parameter can legitimately produce distinct vulnerability evidence
    (for example SQL error disclosure and authentication bypass).  Treating the
    whole (url, field, check) tuple as duplicate loses those findings.
    """
    return (url, field_name, check_type, evidence_type or check_type)


def finding_dedup_key_for(finding: "Finding") -> tuple[str, str, str, str]:
    return finding_dedup_key(
        finding.check_type,
        finding.url,
        finding.field_name,
        finding.evidence_type,
    )


@dataclass
class Finding:
    """A security vulnerability finding."""
    check_type: str          # sqli, xss, os, etc.
    severity: str            # critical, high, medium, low, info
    url: str
    field_name: str
    payload: str
    evidence: str            # Description of what triggered the finding
    request: dict = field(default_factory=dict)
    response: dict = field(default_factory=dict)
    screenshot_b64: str = ""
    dialog_confirmed: bool = False   # True when JS alert() was actually triggered
    dialog_message: str = ""         # The alert message that appeared
    timestamp: float = field(default_factory=time.time)
    verified: bool = True            # False = could not reproduce on second attempt
    verification_note: str = ""      # Reason when verified=False
    confidence: str = "tentative"   # "confirmed" | "likely" | "tentative"
    evidence_type: str = ""          # Structured signal, e.g. xss_dialog, sqli_error
    evidence_details: dict = field(default_factory=dict)
    reproduction_steps: list[str] = field(default_factory=list)

    @property
    def cvss_vector(self) -> str:
        return _cvss_for(self.check_type)[0]

    @property
    def cvss_score(self) -> float:
        return _cvss_for(self.check_type)[1]

    def to_dict(self) -> dict:
        from wscan.compliance_map import get_refs
        return {
            "check_type": self.check_type,
            "severity": self.severity,
            "url": self.url,
            "field_name": self.field_name,
            "payload": self.payload,
            "evidence": self.evidence,
            "request": self.request,
            "response": {k: v for k, v in self.response.items() if k != "body"},
            "response_body_excerpt": (self.response.get("body", "") or "")[:500],
            "screenshot_b64": self.screenshot_b64,
            "dialog_confirmed": self.dialog_confirmed,
            "dialog_message": self.dialog_message,
            "timestamp": self.timestamp,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "verified": self.verified,
            "verification_note": self.verification_note,
            "confidence": self.confidence,
            "evidence_type": self.evidence_type,
            "evidence_details": self.evidence_details,
            "reproduction_steps": self.reproduction_steps,
            "compliance_refs": get_refs(self.check_type),
        }


class BaseScanner(ABC):
    """Base class for all vulnerability scanners."""

    CHECK_TYPE = "base"
    SEVERITY = "medium"

    def __init__(self, engine: "ScanEngine"):
        self.engine = engine
        self.browser = engine.browser
        self.monitor = engine.monitor
        self.payload_gen = engine.payload_gen
        self.findings: list[Finding] = []

    @abstractmethod
    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        """Scan a single input field for vulnerabilities."""
        ...

    async def scan_page(self, url: str) -> list[Finding]:
        """
        Optional page-level check called once per URL, before per-field scanning.
        Override in scanners that inspect HTTP headers, cookies, or page structure
        (e.g. Clickjacking, Session, CSRF) rather than injecting payloads into fields.
        Default: returns empty list (no-op).
        """
        return []

    async def verify_finding(self, finding: Finding) -> Optional[bool]:
        """
        Scanner-specific reproduction check.

        Return True/False when the scanner can verify the finding, or None to
        let the engine use its generic fallback.
        """
        return None

    @property
    def sleep_factor(self) -> float:
        """Scaling factor for sleep durations (0.5 in CTF mode, 1.0 otherwise)."""
        return getattr(self.engine, "sleep_factor", 1.0)

    async def log_payload_test(
        self, field_name: str, payload: str, check_type: str, url: str = ""
    ) -> None:
        """Record a tested payload to the audit log and (if present) the dashboard.

        Monitor-independent: writes to ``engine.request_logger`` so
        ``payloads.jsonl`` is produced even in ``--no-monitor`` / batch runs
        (where ``monitor`` is ``None``), then emits the live dashboard event
        only when a monitor is attached. The file write happens here — not in
        ``MonitorServer.emit_payload_test`` — so it is never skipped just
        because the dashboard is absent, and not duplicated when present.
        """
        logger = getattr(self.engine, "request_logger", None)
        if logger is not None:
            logger.log_payload(field_name, payload, check_type, url)
        if self.monitor:
            await self.monitor.emit_payload_test(field_name, payload, check_type, url)

    async def get_payloads(self, field_name: str, url: str) -> list[str]:
        """Get payloads for this scanner's check type, sorted by learning data."""
        # Check per-task ContextVar override first (set by engine for parallel isolation),
        # fall back to the engine-level custom_payloads dict.
        from wscan.engine import _FIELD_PAYLOAD_OVERRIDES
        _overrides = _FIELD_PAYLOAD_OVERRIDES.get()
        _custom = (
            _overrides.get(self.CHECK_TYPE)
            if _overrides
            else self.engine.custom_payloads.get(self.CHECK_TYPE)
        )
        payloads = await self.payload_gen.generate(
            check_type=self.CHECK_TYPE,
            field_name=field_name,
            url=url,
            custom_payloads=_custom,
        )
        # A-3 / ⑩: re-order by historical success rate (domain-aware)
        learner = getattr(self.engine, "payload_learner", None)
        if learner and getattr(self.engine, "enable_payload_learning", True):
            from urllib.parse import urlparse as _up
            _domain = _up(getattr(self.engine, "target_url", "")).hostname or None
            payloads = learner.sort_payloads(self.CHECK_TYPE, payloads, domain=_domain)
        # Fast mode: cap payload count (highest-priority payloads are already first)
        cap = getattr(self.engine, "max_payloads", 0)
        if cap > 0:
            payloads = payloads[:cap]
        return payloads

    def check_response_for_patterns(self, body: str, patterns: list[str]) -> Optional[str]:
        """Check response body for any of the given regex patterns."""
        for pattern in patterns:
            match = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(0)[:200]
        return None

    def response_time_exceeded(self, pair: dict, threshold: float = 3.0) -> bool:
        """Check if response time suggests a time-based injection."""
        req = pair.get("request", {})
        resp = pair.get("response", {})
        req_ts = req.get("timestamp", 0)
        resp_ts = resp.get("timestamp", 0)
        if req_ts and resp_ts:
            return (resp_ts - req_ts) >= threshold
        return False

    async def run_equivalence_probe(
        self,
        url: str,
        form_index: int,
        field_name: str,
        is_url_param: bool,
        *,
        context: str = "sql",
    ) -> "Optional[tuple]":
        """文字列結合の等価性プローブを 1 フィールドに対して実行する。

        ``context`` に応じたプローブ群を生成して順に投入し、応答本文から
        ``equivalence_probe.evaluate`` で注入可否を判定する。判定が陽性なら
        ``(ProbeVerdict, last_pair)`` を、そうでなければ ``None`` を返す。

        SQLi / XSS の両スキャナから再利用する共通ロジック。投入は各スキャナの
        ``_apply_payload`` に委譲するため、フォーム/URLパラメータ双方に対応する。
        """
        from wscan import equivalence_probe as eqp

        builders = {
            "sql": eqp.sql_probe_set,
            "html_attr": eqp.html_attr_probe_set,
            "js_string": eqp.js_string_probe_set,
        }
        builder = builders.get(context)
        if builder is None:
            return None

        probe_set = builder()
        responses: dict[str, str] = {}
        pairs: dict[str, dict] = {}
        for probe in probe_set.probes:
            # Log probe payloads to the audit trail just like the normal scanner
            # loops, so payloads.jsonl can reproduce a verdict's matched payload.
            await self.log_payload_test(
                field_name, probe.value, f"{self.CHECK_TYPE}_equiv", url
            )
            try:
                source, pair = await self._apply_payload(
                    url, form_index, field_name, probe.value, is_url_param
                )
            except Exception:
                continue
            pairs[probe.name] = pair or {}
            body = (pair.get("response", {}) or {}).get("body") or source or ""
            responses[probe.name] = body

        verdict = eqp.evaluate(probe_set, responses)
        if verdict.injectable:
            # Attach the request/response pair of the probe that actually
            # triggered the verdict, not whichever probe happened to run last
            # (otherwise the recorded evidence points at a different payload).
            matched_pair = pairs.get(verdict.matched_probe, {})
            return verdict, matched_pair
        return None

    async def _evolution_probe(
        self,
        url: str,
        form_index: int,
        field_name: str,
        is_url_param: bool,
    ) -> tuple[str, set[str], dict]:
        """文脈適応 payload 用の特殊文字生存 probe を投入する。

        個別 scanner の検知判定は呼ばず、marker 付き文字列の反射状態だけを
        観測する。失敗時は呼び出し側が従来挙動へ戻れるよう空値を返す。
        """
        try:
            from wscan import context_mutator

            marker = context_mutator.make_marker()
            probe = context_mutator.make_char_probe(marker)
            await self.log_payload_test(
                field_name,
                probe,
                f"{self.CHECK_TYPE}_evolution_probe",
                url,
            )
            if is_url_param:
                source, pair = await self.browser.test_url_param(url, field_name, probe)
            else:
                await self.browser.navigate(url)
                source, pair = await self.browser.fill_and_submit_form(
                    form_index,
                    field_name,
                    probe,
                )
            response_source = (pair.get("response", {}) or {}).get("body") or source or ""
            surviving = context_mutator.surviving_chars(response_source, marker)
            context = context_mutator.detect_context(response_source, marker)
            context["marker"] = marker
            return response_source, surviving, context
        except Exception:
            return "", set(), {}

    async def evolved_payloads(
        self,
        url: str,
        form_index: int,
        field_name: str,
        is_url_param: bool,
    ) -> list[str]:
        """追加 wave 用の決定論的 payload 候補を返す。

        ``enable_payload_evolution`` が無効、または probe/mutation が失敗した
        場合は空 list を返し、既存の検知ループを壊さない。
        """
        if not getattr(self.engine, "enable_payload_evolution", True):
            return []
        try:
            from wscan import context_mutator

            _source, surviving, context = await self._evolution_probe(
                url,
                form_index,
                field_name,
                is_url_param,
            )
            marker = context.get("marker") or context_mutator.make_marker()
            payloads = context_mutator.mutate(
                self.CHECK_TYPE,
                context=context,
                surviving=surviving,
                marker=marker,
            )
            cap = getattr(self.engine, "max_payloads", 0)
            if cap and cap > 0:
                payloads = payloads[:cap]
            return payloads
        except Exception:
            return []

    def current_page_pair(self, url: str) -> dict:
        """
        Return the captured request/response for the page under test.

        Page-level scanners run after navigation, when the browser may already
        have loaded scripts, stylesheets, or images.  Falling back to the latest
        network pair can make header/cookie findings describe an asset instead
        of the document URL.
        """
        network = getattr(self.browser, "network", None)
        if not network:
            return {}
        latest_for_url = getattr(network, "latest_for_url", None)
        if latest_for_url:
            return latest_for_url(url, match_query=False) or {}
        return network.latest() or {}

    async def record_finding(
        self,
        url: str,
        field_name: str,
        payload: str,
        evidence: str,
        pair: dict,
        severity: Optional[str] = None,
        screenshot_b64: Optional[str] = None,
        dialog_confirmed: bool = False,
        dialog_message: str = "",
        confidence: Optional[str] = None,
        evidence_type: str = "",
        evidence_details: Optional[dict] = None,
        reproduction_steps: Optional[list[str]] = None,
    ) -> Finding:
        """Create and record a finding."""
        if screenshot_b64 is None:
            # When an alert dialog fired, the browser already captured a
            # screenshot at that exact instant -- prefer it so the evidence
            # image actually corresponds to the payload that triggered it.
            dlg_shot = getattr(self.browser, "dialog_screenshot_b64", "") or ""
            if dialog_confirmed and dlg_shot:
                screenshot_b64 = dlg_shot
                if self.monitor:
                    await self.monitor.emit_screenshot(
                        dlg_shot,
                        label=f"[FINDING] {self.CHECK_TYPE} on {field_name}",
                    )
            else:
                screenshot_b64 = await self.browser.screenshot_b64(
                    label=f"[FINDING] {self.CHECK_TYPE} on {field_name}"
                )
        # Dedup: skip exact evidence repeats while preserving distinct signals
        # on the same input.
        dedup_key = finding_dedup_key(
            self.CHECK_TYPE,
            url,
            field_name,
            evidence_type,
        )
        if dedup_key in self.engine._finding_dedup:
            return None  # duplicate
        self.engine._finding_dedup.add(dedup_key)

        # Auto-assign confidence level
        if confidence is None and dialog_confirmed:
            confidence = "confirmed"
        elif confidence is None:
            # "baseline_response" is never populated in the pair dict by any scanner,
            # so the comparison len(resp_body) - len(base_body) was always equal to
            # len(resp_body), making nearly every finding "likely" regardless of
            # whether the response actually changed.  Default to "tentative" so
            # scanners that care about confidence set it explicitly.
            confidence = "tentative"

        finding = Finding(
            check_type=self.CHECK_TYPE,
            severity=severity or self.SEVERITY,
            url=url,
            field_name=field_name,
            payload=payload,
            evidence=evidence,
            request=pair.get("request", {}),
            response=pair.get("response", {}),
            screenshot_b64=screenshot_b64,
            dialog_confirmed=dialog_confirmed,
            dialog_message=dialog_message,
            confidence=confidence,
            evidence_type=evidence_type or self.CHECK_TYPE,
            evidence_details=evidence_details or {},
            reproduction_steps=reproduction_steps or self._default_reproduction_steps(
                url, field_name, payload
            ),
        )
        self.findings.append(finding)
        self.engine.all_findings.append(finding)
        if self.monitor:
            await self.monitor.emit_finding(finding.to_dict())
        return finding

    def _default_reproduction_steps(self, url: str, field_name: str, payload: str) -> list[str]:
        return [
            f"Open {url}",
            f"Submit payload to field or parameter '{field_name}'",
            "Compare the resulting response and browser behavior with the baseline.",
        ]
