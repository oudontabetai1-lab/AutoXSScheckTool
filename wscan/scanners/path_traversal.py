"""
Path Traversal / Directory Traversal Scanner
Detects parameter-based directory traversal (IPA: 1.3 パス名パラメータの未チェック).
"""
import asyncio
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

from wscan.injection_point import InjectionPoint

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# Patterns indicating successful file content retrieval
PATH_TRAVERSAL_PATTERNS = [
    r"root:x:\d+:\d+:",        # /etc/passwd
    r"nobody:x:\d+",
    r"daemon:x:\d+",
    r"www-data:x:\d+",
    r"mysql:x:\d+",
    r"\[extensions\]",          # Windows win.ini
    r"for 16-bit app support",  # Windows win.ini
    r"\[boot loader\]",         # Windows boot.ini
    r"WINDOWS\\system32",
    r"<\?php",                  # PHP source leak (literal <?php opening tag)
    r"#!/usr/bin/perl",         # CGI source leak
    r"#!/usr/bin/python",
    r"# /etc/hosts",
    r"127\.0\.0\.1\s+localhost",  # /etc/hosts
]


class PathTraversalScanner(BaseScanner):
    """Directory / path traversal vulnerability scanner (IPA 1.3)."""

    CHECK_TYPE = "path_traversal"
    SEVERITY = "high"
    SUPPORTS_JSON_BODY = True

    async def scan_injection_point(
        self,
        ip: InjectionPoint,
        field: dict,
    ) -> list[Finding]:
        """Scan a form field or URL parameter for path traversal."""
        findings = []
        field_name = field.get("name", "unknown")
        payloads = await self.get_payloads(field_name, ip.url)

        if self.monitor:
            await self.monitor.emit_status(
                f"Path traversal testing: {field_name} on {ip.url}"
            )

        # Baseline: capture what patterns already appear in a neutral response
        # baseline もフィールド投入なので監査ログに残す（log_payload_test 一元化の不変条件）。
        await self.log_payload_test(
            field_name, "baseline_test_value", "path_traversal_baseline", ip.url
        )
        baseline_source, baseline_pair = await self._apply_ip(
            ip, "baseline_test_value"
        )

        async def _test_payload(payload: str, check_label: str = "path_traversal") -> bool:
            await self.log_payload_test(field_name, payload, check_label, ip.url)

            source, pair = await self._apply_ip(ip, payload)
            await asyncio.sleep(0.2 * self.sleep_factor)

            match = self.check_response_for_patterns(source, PATH_TRAVERSAL_PATTERNS)
            if match:
                # baseline が *まったく取れなかった*（本文も pair も無い＝リクエスト
                # 失敗）ときだけ「既存 vs 新規」を判別できないので finding を出さない。
                # 本文 or 成功 pair のどちらかが有れば対照として使う（フォーム送信で
                # pair 未捕捉でも本文はある場合／空 200 でも本文比較できる場合を
                # 偽陰性にしない）。黙って見逃すと気づけないので scan note に記録する。
                if not baseline_source and not baseline_pair:
                    self._record_scan_note(
                        f"baseline_unavailable:{self.CHECK_TYPE}: "
                        f"suppressed match '{match}' at {ip.url}"
                    )
                    return False
                baseline_match = self.check_response_for_patterns(
                    baseline_source, PATH_TRAVERSAL_PATTERNS
                )
                if baseline_match:
                    return False  # Pattern pre-existed — not caused by our payload

                finding = await self.record_finding(
                    url=ip.url,
                    field_name=field_name,
                    payload=payload,
                    evidence=(
                        f"Path traversal successful — file content in response: '{match}'"
                    ),
                    pair=pair,
                    severity="high",
                    confidence="likely",
                    injection_point=ip,
                )
                findings.append(finding)
                return True
            return False

        for payload in payloads:
            if await _test_payload(payload):
                break

        # evolution wave は legacy browser transport(is_url_param 前提)。json_body では
        # ip.legacy_is_url_param() が例外になり、かつ適用不能なので skip する（json は標準 payload のみ）。
        if not findings and ip.location != "json_body":
            extra_payloads = await self.evolved_payloads(
                ip.url,
                ip.form_index,
                ip.parameter_id,
                ip.legacy_is_url_param(),
            )
            for payload in extra_payloads:
                if await _test_payload(payload, "path_traversal_evolved"):
                    break

        # --- Mutation wave: 二重エンコード + NULL バイト + 拡張子で素朴な防御を回避 ---
        if not findings:
            mutated = await self.mutated_payloads(field_name, ip.url, payloads)
            for payload in mutated:
                if await _test_payload(payload, "path_traversal_mutation"):
                    break

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

    async def verify_finding(self, finding: Finding) -> bool | None:
        is_url_param = finding.field_name in parse_qs(
            urlparse(finding.url).query, keep_blank_values=True
        )
        ip = self._verify_injection_point(finding, is_url_param)
        # verify 時の再投入（baseline + payload）も監査ログに残す。
        await self.log_payload_test(
            finding.field_name, "baseline_test_value",
            "path_traversal_verify_baseline", finding.url,
        )
        baseline_source, _ = await self._apply_ip(ip, "baseline_test_value")
        await self.log_payload_test(
            finding.field_name, finding.payload,
            "path_traversal_verify", finding.url,
        )
        source, _pair = await self._apply_ip(ip, finding.payload)
        match = self.check_response_for_patterns(source or "", PATH_TRAVERSAL_PATTERNS)
        if not match:
            return False
        if baseline_source:
            baseline_match = self.check_response_for_patterns(
                baseline_source,
                PATH_TRAVERSAL_PATTERNS,
            )
            if baseline_match:
                return False
        return True

    async def _apply_payload(
        self,
        url: str,
        form_index: int,
        field_name: str,
        payload: str,
        is_url_param: bool,
    ) -> tuple[str, dict]:
        try:
            if is_url_param:
                return await self.browser.test_url_param(url, field_name, payload)
            else:
                await self.browser.navigate(url)
                return await self.browser.fill_and_submit_form(
                    form_index, field_name, payload
                )
        except Exception as exc:
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] path_traversal: _apply_payload failed on {field_name} @ {url}: {exc}"
                )
            return "", {}
