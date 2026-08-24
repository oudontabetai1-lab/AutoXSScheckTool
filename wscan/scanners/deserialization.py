"""
Insecure Deserialization Scanner (V-8)
Detects unsafe deserialization endpoints by sending malformed/probe payloads
and observing error messages that reveal deserialization is in use.

Tests:
  1. PHP serialized object pattern (detect/trigger unserialize() errors)
  2. Java serialized object magic bytes (detect ObjectInputStream usage)
  3. Python pickle header (detect pickle.loads() usage)
  4. YAML deserialization probe (detect yaml.load() usage)

NOTE: This scanner DOES NOT attempt RCE payloads. It only sends
probe payloads that trigger recognizable error messages, indicating
that deserialization is occurring. This allows safe detection without
executing arbitrary code on target systems.

If the application errors on recognizable deserialization input,
it is likely vulnerable to a real deserialization attack.
"""
import asyncio
import base64
from typing import TYPE_CHECKING

import httpx

from wscan.injection_point import InjectionPoint

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine

# Error patterns that reveal deserialization is in use
_DESER_ERROR_PATTERNS = [
    # PHP
    r"unserialize\(\)",
    r"O:\d+:\"[A-Za-z_]",
    r"unserialization.*failed",
    r"could not be unserialized",
    # Java
    r"java\.io\.InvalidClassException",
    r"java\.io\.StreamCorruptedException",
    r"java\.io\.ObjectStreamException",
    r"java\.lang\.ClassNotFoundException",
    r"com\.fasterxml\.jackson",
    r"JsonMappingException",
    # Python
    r"pickle\.loads",
    r"_pickle\.UnpicklingError",
    r"AttributeError.*__reduce__",
    # Ruby Marshal
    r"Marshal\.load",
    r"ArgumentError.*marshal",
    # YAML
    r"Psych::DisallowedClass",
    r"yaml\.load.*unsafe",
    r"YAML::PermittedClassesError",
    # Generic
    r"deserialization.*error",
    r"deserialization.*failed",
]

# Probe payloads for each platform
_PROBES = [
    # PHP: minimal serialized string (boolean true)
    (
        "php_serialize",
        "PHP serialized object",
        "b:1;",
        "text/plain",
    ),
    # PHP: corrupted serialized string to trigger error
    (
        "php_serialize_malformed",
        "PHP malformed serialized data",
        "O:1:\"A\":1:{s:1:\"a\";R:99999999;}",
        "application/x-www-form-urlencoded",
    ),
    # Java: first 4 bytes of a Java serialized object (magic bytes)
    # AC ED 00 05 → base64: rO0ABQ==
    (
        "java_serialize",
        "Java serialized object (magic bytes)",
        base64.b64encode(b"\xac\xed\x00\x05\x73\x72").decode(),
        "application/octet-stream",
    ),
    # Python: pickle protocol 2 header (only the header, no opcode payload)
    # \x80\x02 → protocol 2 marker
    (
        "python_pickle",
        "Python pickle header",
        base64.b64encode(b"\x80\x02").decode(),
        "application/octet-stream",
    ),
    # YAML: probe that triggers Psych::DisallowedClass in Ruby/Rails
    (
        "yaml_probe",
        "YAML deserialization probe",
        "--- !ruby/object:OpenStruct\ntable:\n  :a: 1\n",
        "application/yaml",
    ),
]


class DeserializationScanner(BaseScanner):
    """Insecure deserialization detection scanner."""

    CHECK_TYPE = "deserialization"
    SEVERITY = "critical"
    SUPPORTS_JSON_BODY = True

    def _probe_by_id(self, probe_id: str) -> tuple[str, str, str, str] | None:
        for probe in _PROBES:
            if probe[0] == probe_id:
                return probe
        return None

    async def _apply_payload(
        self,
        url: str,
        form_index: int,
        field_name: str,
        payload: str,
        is_url_param: bool,
    ) -> tuple[str, dict]:
        if is_url_param:
            return await self.browser.test_url_param(url, field_name, payload)
        await self.browser.navigate(url)
        return await self.browser.fill_and_submit_form(form_index, field_name, payload)

    async def scan_injection_point(
        self,
        ip: InjectionPoint,
        field: dict,
    ) -> list[Finding]:
        field_name = field.get("name", "unknown")
        field_type = field.get("type", "text").lower()

        # Only relevant for hidden fields and data fields, not UI elements
        if field_type in ("file", "submit", "button", "image", "reset", "checkbox", "radio"):
            return []

        if self.monitor:
            await self.monitor.emit_status(
                f"Deserialization probe: {field_name} on {ip.url}"
            )

        findings = []

        baseline_src = ""
        # baseline も送信なので単層ログ(＋abort checkpoint)を呼び出し側で通す
        # （_apply_json_payload は log しない＝json でも payloads.jsonl に残す）。
        await self.log_payload_test(
            field_name, "wscan_deser_baseline", "deserialization_baseline", ip.url
        )
        try:
            baseline_src, _ = await self._apply_ip(ip, "wscan_deser_baseline")
        except Exception:
            baseline_src = ""

        for probe_id, description, payload, content_type in _PROBES:
            # 監査ログには **実際に送る payload** を記録する（probe_id はラベルでなく
            # check_type 側に残す）。transport 側 log を撤去したため、ここがラベルのままだと
            # json 経路で送信値が payloads.jsonl/dashboard から欠落し再現できない。
            await self.log_payload_test(
                field_name, payload, f"deserialization[{probe_id}]", ip.url
            )
            try:
                src, pair = await self._apply_ip(ip, payload)

                err = self.check_response_for_patterns(src, _DESER_ERROR_PATTERNS)
                baseline_err = self.check_response_for_patterns(
                    baseline_src or "",
                    _DESER_ERROR_PATTERNS,
                )
                if err and not baseline_err:
                    finding = await self.record_finding(
                        url=ip.url,
                        field_name=field_name,
                        payload=payload,
                        evidence=(
                            f"Insecure deserialization detected via {description}: "
                            f"error pattern '{err[:150]}' returned. "
                            f"The endpoint may be vulnerable to deserialization attacks."
                        ),
                        pair=pair,
                        severity="critical",
                        confidence="likely",
                        evidence_type="deserialization_error",
                        evidence_details={
                            "probe_id": probe_id,
                            "description": description,
                            "content_type": content_type,
                            "matched_error": err[:150],
                            "transport": "field",
                        },
                        injection_point=ip,
                    )
                    findings.append(finding)
                    break  # One confirmed finding per field is enough

            except Exception as exc:
                self._record_scan_note(
                    f"probe_error:{self.CHECK_TYPE}:{type(exc).__name__}"
                )
                continue
            await asyncio.sleep(0.2 * self.sleep_factor)

        # Also test via raw HTTP POST with appropriate Content-Type headers。
        # raw POST は payload を **body 全体** として送る endpoint 単位の検査。json_body の
        # 葉ごとに呼ぶと同一 endpoint 応答に対する重複 Finding になる（dedup キーの field_name
        # が葉ごとに違うため）。json では葉単位で走らせず、endpoint 単位のスケジューリングは
        # PR-b に委ねる（form/url_param は従来どおり）。
        if not findings and ip.location != "json_body":
            findings += await self._test_raw_post(ip, field_name)

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

    async def _test_raw_post(
        self,
        ip: InjectionPoint,
        field_name: str,
    ) -> list[Finding]:
        """Send raw probe payloads with deserialization-specific Content-Types."""
        findings = []
        url = ip.url
        proxy = getattr(self.engine, "proxy", "") or None
        timeout = getattr(self.engine, "timeout", 15)

        for probe_id, description, payload, content_type in _PROBES:
            if content_type == "application/x-www-form-urlencoded":
                continue  # Already covered by form submission
            try:
                hdrs: dict = {"Content-Type": content_type}
                if hasattr(self.engine, "auth_headers"):
                    # Underlay engine auth headers (Cookie / custom) so requests
                    # against authenticated endpoints don't 401.
                    base = self.auth_headers_for_url(url)
                    base.update(hdrs)
                    hdrs = base
                kwargs: dict = {
                    "timeout": timeout,
                    "follow_redirects": True,
                    "headers": hdrs,
                }
                if hasattr(self.engine, "httpx_client_kwargs"):
                    kwargs = self.engine.httpx_client_kwargs(**kwargs)
                elif proxy:
                    kwargs["proxy"] = proxy

                # Convert base64-encoded binary payloads back to bytes
                raw_payload: bytes
                try:
                    raw_payload = base64.b64decode(payload)
                except Exception:
                    raw_payload = payload.encode()

                async with httpx.AsyncClient(**kwargs) as client:
                    baseline = await client.post(url, content=b"wscan_deser_baseline")
                    self._record_probe_status(baseline)
                    r = await client.post(url, content=raw_payload)
                    self._record_probe_status(r)

                err = self.check_response_for_patterns(r.text, _DESER_ERROR_PATTERNS)
                baseline_err = self.check_response_for_patterns(
                    baseline.text,
                    _DESER_ERROR_PATTERNS,
                )
                if err and not baseline_err:
                    pair = {
                        "request": {"url": url, "content_type": content_type},
                        "response": {"status": r.status_code, "body": r.text[:1000]},
                    }
                    finding = await self.record_finding(
                        url=url,
                        field_name=field_name,
                        payload=payload,
                        evidence=(
                            f"Insecure deserialization via raw POST: {description} "
                            f"triggered error: '{err[:150]}'"
                        ),
                        pair=pair,
                        severity="critical",
                        confidence="likely",
                        evidence_type="deserialization_error",
                        evidence_details={
                            "probe_id": probe_id,
                            "description": description,
                            "content_type": content_type,
                            "matched_error": err[:150],
                            "transport": "raw_post",
                        },
                        # raw POST は payload を body 全体として送る（ip.parameter_id には注入しない）。
                        # 特定 pointer の脆弱性として provenance を付けると、複数葉スキャンで同一の
                        # endpoint 全体レスポンスに対し pointer 別の重複 Finding が出て、再現メタが実際に
                        # 撃っていない注入位置を指してしまう。よって field IP の provenance は付けない。
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
        details = getattr(finding, "evidence_details", {}) or {}
        probe_id = details.get("probe_id")
        probe = self._probe_by_id(probe_id) if probe_id else None
        if not probe:
            return None

        _probe_id, _description, payload, content_type = probe
        transport = details.get("transport", "field")
        if transport == "raw_post":
            return await self._verify_raw_post(finding.url, payload, content_type)

        from urllib.parse import parse_qs, urlparse

        is_url_param = finding.field_name in parse_qs(
            urlparse(finding.url).query, keep_blank_values=True
        )
        ip = self._verify_injection_point(finding, is_url_param)
        if ip is None:
            return None
        # verify の再送(baseline + probe)も単層ログ(＋abort checkpoint)を呼び出し側で通す。
        await self.log_payload_test(
            finding.field_name, "wscan_deser_baseline",
            "deserialization_verify_baseline", finding.url,
        )
        try:
            baseline_src, _ = await self._apply_ip(ip, "wscan_deser_baseline")
            await self.log_payload_test(
                finding.field_name, payload, "deserialization_verify", finding.url
            )
            probe_src, _ = await self._apply_ip(ip, payload)
        except Exception:
            return None

        baseline_err = self.check_response_for_patterns(
            baseline_src or "",
            _DESER_ERROR_PATTERNS,
        )
        probe_err = self.check_response_for_patterns(
            probe_src or "",
            _DESER_ERROR_PATTERNS,
        )
        return bool(probe_err and not baseline_err)

    async def _verify_raw_post(
        self,
        url: str,
        payload: str,
        content_type: str,
    ) -> bool | None:
        proxy = getattr(self.engine, "proxy", "") or None
        timeout = getattr(self.engine, "timeout", 15)
        hdrs: dict = {"Content-Type": content_type}
        if hasattr(self.engine, "auth_headers"):
            base = self.auth_headers_for_url(url)
            base.update(hdrs)
            hdrs = base
        kwargs: dict = {
            "timeout": timeout,
            "follow_redirects": True,
            "headers": hdrs,
        }
        if hasattr(self.engine, "httpx_client_kwargs"):
            kwargs = self.engine.httpx_client_kwargs(**kwargs)
        elif proxy:
            kwargs["proxy"] = proxy

        try:
            try:
                raw_payload = base64.b64decode(payload)
            except Exception:
                raw_payload = payload.encode()
            async with httpx.AsyncClient(**kwargs) as client:
                baseline = await client.post(url, content=b"wscan_deser_baseline")
                self._record_probe_status(baseline)
                probe = await client.post(url, content=raw_payload)
                self._record_probe_status(probe)
        except Exception:
            return None

        baseline_err = self.check_response_for_patterns(
            baseline.text,
            _DESER_ERROR_PATTERNS,
        )
        probe_err = self.check_response_for_patterns(
            probe.text,
            _DESER_ERROR_PATTERNS,
        )
        return bool(probe_err and not baseline_err)
