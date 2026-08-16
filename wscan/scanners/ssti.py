"""
SSTI (Server-Side Template Injection) Scanner
Detects template injection using math-probe technique.
"""
import asyncio
from typing import TYPE_CHECKING

from wscan.injection_point import InjectionPoint

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# Probe tuples: (payload, expected_substring, template_engine_name)
# Use product of two large primes — astronomically unlikely to appear naturally in page HTML.
# 2654435761 * 2654435761 = 7045744422742119121
SSTI_PROBES = [
    ("{{2654435761*2654435761}}", "7045744422742119121", "Jinja2/Twig"),
    ("${2654435761*2654435761}", "7045744422742119121", "Mako/Freemarker"),
    ("<%= 2654435761*2654435761 %>", "7045744422742119121", "ERB"),
    ("#{2654435761*2654435761}", "7045744422742119121", "Ruby/Pebble"),
    ("{{3*'wscan99991'}}", "wscan99991wscan99991wscan99991", "Jinja2-str"),
    ("*{2654435761*2654435761}", "7045744422742119121", "SpEL"),
    ("%{2654435761*2654435761}", "7045744422742119121", "OGNL"),
    ("[[${2654435761*2654435761}]]", "7045744422742119121", "Thymeleaf"),
]


class SSTIScanner(BaseScanner):
    """SSTI vulnerability scanner."""

    CHECK_TYPE = "ssti"
    SEVERITY = "critical"
    SUPPORTS_JSON_BODY = True

    async def scan_injection_point(
        self,
        ip: InjectionPoint,
        field: dict,
    ) -> list[Finding]:
        """Scan a field for SSTI vulnerabilities."""
        findings = []
        field_name = field.get("name", "unknown")

        if self.monitor:
            await self.monitor.emit_status(
                f"SSTI testing: {field_name} on {ip.url}"
            )

        # Baseline: submit a neutral value to capture any pre-existing numbers in the response.
        # baseline もフィールド投入なので監査ログに残す（log_payload_test 一元化の不変条件）。
        await self.log_payload_test(
            field_name, "wscan_ssti_baseline", "ssti_baseline", ip.url
        )
        baseline_source, _ = await self._apply_ip(ip, "wscan_ssti_baseline")

        async def _test_payload(
            payload: str,
            expected: str,
            engine_name: str,
            check_label: str = "ssti",
            confidence: str = "confirmed",
        ) -> bool:
            await self.log_payload_test(field_name, payload, check_label, ip.url)

            source, pair = await self._apply_ip(ip, payload)

            await asyncio.sleep(0.2 * self.sleep_factor)

            if not source or expected not in source:
                return False

            # Reduce false positives: only skip if baseline already contained the
            # expected value at least as many times. When baseline has 0 occurrences,
            # any appearance after injection is evidence of SSTI.
            base_count = baseline_source.count(expected) if baseline_source else 0
            if base_count > 0 and source.count(expected) <= base_count:
                return False

            finding = await self.record_finding(
                url=ip.url,
                field_name=field_name,
                payload=payload,
                evidence=(
                    f"SSTI detected ({engine_name}): "
                    f"payload '{payload}' evaluated to '{expected}' in response"
                ),
                pair=pair,
                severity="critical",
                # 算術評価（例: {{2654435761*2654435761}} → 巨大素数積が本文に出現）は
                # サーバ側でテンプレートが評価された確証シグナルなので "confirmed"。
                # ただし進化wave の {{7*7}}→"49" は自然出現しうる弱い値のため呼び出し側で
                # "likely" に落とす（baseline 増分ガード付き）。
                confidence=confidence,
                # 進化wave など SSTI_PROBES 外の payload でも verify が再現確認できる
                # よう、期待出力を finding に持たせる。
                evidence_details={"expected": expected, "engine": engine_name},
                injection_point=ip,
            )
            findings.append(finding)
            return True

        for payload, expected, engine_name in SSTI_PROBES:
            if await _test_payload(payload, expected, engine_name):
                break  # Confirmed - no need to test more probes

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
                if await _test_payload(
                    payload, "49", "evolved", "ssti_evolved", confidence="likely"
                ):
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
                    f"[warn] ssti: _apply_payload failed on {field_name} @ {url}: {exc}"
                )
            return "", {}

    async def verify_finding(self, finding: Finding) -> bool | None:
        """Reproduce the exact SSTI probe that created the finding."""
        field_name = finding.field_name
        payload = finding.payload
        # 検知時に保存した期待出力を優先（進化wave 等 SSTI_PROBES 外の payload に対応）。
        expected = (getattr(finding, "evidence_details", None) or {}).get("expected")
        if not expected:
            expected = next(
                (exp for probe, exp, _engine in SSTI_PROBES if probe == payload),
                None,
            )
        if not expected:
            return None

        from urllib.parse import parse_qs, urlparse

        is_url_param = field_name in parse_qs(
            urlparse(finding.url).query,
            keep_blank_values=True,
        )
        ip = (
            InjectionPoint.for_url_param(finding.url, field_name)
            if is_url_param
            else InjectionPoint.for_form(finding.url, field_name, 0)
        )
        # verify 時の再投入（baseline + payload）も監査ログに残す。
        await self.log_payload_test(field_name, "wscan_ssti_baseline", "ssti_verify_baseline", finding.url)
        baseline_source, _ = await self._apply_ip(ip, "wscan_ssti_baseline")
        await self.log_payload_test(field_name, payload, "ssti_verify", finding.url)
        source, _ = await self._apply_ip(ip, payload)
        if not source or expected not in source:
            return False

        base_count = baseline_source.count(expected) if baseline_source else 0
        return base_count == 0 or source.count(expected) > base_count
