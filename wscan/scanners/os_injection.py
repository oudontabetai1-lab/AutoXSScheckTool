"""
OS Command Injection Scanner
Detects OS command injection vulnerabilities.
"""
import asyncio
import re
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# Patterns indicating command execution in response.
OS_OUTPUT_PATTERNS = [
    # Linux/Mac — output from 'id' command (flexible: gid optional)
    r"uid=\d+",
    r"gid=\d+",
    # /etc/passwd entries (partial match is sufficient)
    r"root:x:\d+",
    r"nobody:x:\d+",
    r"daemon:x:\d+",
    r"www-data:x:\d+",
    # Shell paths
    r"/bin/(?:bash|sh|zsh|dash)",
    # ls -la output (relaxed)
    r"(?:total \d+|drwx|drwxr|drwxrwx)",
    # uname output
    r"Linux \S+ \d+\.\d+",
    r"Darwin Kernel Version",
    # Windows
    r"Windows IP Configuration",
    r"Microsoft Windows \[Version",
    r"(?:Volume in drive|Directory of [A-Z]:\\)",
    r"for 16-bit app support",
    r"WINDOWS\\system32\\cmd\.exe",
]

# Blind/time-based payloads
TIME_BASED_PAYLOADS = [
    "; sleep 3",
    "| sleep 3",
    "& sleep 3",
    "&& sleep 3",
    "; ping -c 3 127.0.0.1",
    "| ping -c 3 127.0.0.1",
    "& ping -n 3 127.0.0.1",
]

# community/任意方言の遅延プローブ（`|| sleep 10`、`& ping -n 5 127.0.0.1` 等）でも
# 時間ベース判定を走らせるため、固定リストに加えてディレクティブ有無でも判定する。
_TIME_BASED_OS_RE = re.compile(
    r"\bsleep\s+\d|\bping\s+-[cn]\s*\d|\btimeout\s+/?t?\s*\d", re.IGNORECASE
)


def _is_time_based_os(payload: str) -> bool:
    """ペイロードに時間遅延ディレクティブ（sleep/ping/timeout）が含まれるか（純粋関数）。"""
    return bool(payload and _TIME_BASED_OS_RE.search(payload))


def _count_executed_markers(source: str, marker: str) -> int:
    """``echo`` を伴わない（=実行出力とみなせる）marker 出現数を数える純粋関数。

    反射ページでは ``echo {marker}`` の並びで現れる（生でも HTML エスケープ後でも
    ``echo wscanEVO…``）。一方コマンドが実行された場合は ``echo`` が消費され marker
    単体が出力される。よって「marker 直前の小窓に ``echo`` が無い出現」を実行出力として数える。
    """
    if not source or not marker:
        return 0
    low = source.lower()
    needle = marker.lower()
    count = 0
    start = 0
    while True:
        idx = low.find(needle, start)
        if idx == -1:
            return count
        window = low[max(0, idx - 24):idx]
        if "echo" not in window:
            count += 1
        start = idx + len(needle)


def _echo_marker_executed(source: str, marker: str) -> bool:
    """``echo {marker}`` がシェル実行された（=単なる反射ではない）かを判定する純粋関数。"""
    return _count_executed_markers(source, marker) > 0


class OSInjectionScanner(BaseScanner):
    """OS Command Injection vulnerability scanner."""

    CHECK_TYPE = "os"
    SEVERITY = "critical"

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        """Scan a form field or URL parameter for OS command injection."""
        findings = []
        field_name = field.get("name", "unknown")
        payloads = await self.get_payloads(field_name, url)

        if self.monitor:
            await self.monitor.emit_status(
                f"OS injection testing: {field_name} on {url}"
            )

        # Baseline: capture pre-existing patterns and response time
        baseline_source, baseline_pair = await self._apply_payload(
            url, form_index, field_name, "baseline_os_test", is_url_param
        )
        _b_req = baseline_pair.get("request", {})
        _b_resp = baseline_pair.get("response", {})
        _b_ts_req = _b_req.get("timestamp", 0)
        _b_ts_resp = _b_resp.get("timestamp", 0)
        baseline_time = (
            float(_b_ts_resp - _b_ts_req)
            if _b_ts_req and _b_ts_resp
            else 0.0
        )
        # Threshold = baseline + 2.8 s (injected sleep) with 0.5 s margin
        time_threshold = max(2.8, baseline_time + 2.8)

        async def _test_payload(
            payload: str, check_label: str = "os", echo_baseline: str = ""
        ) -> bool:
            await self.log_payload_test(field_name, payload, check_label, url)

            # Apply payload
            source, pair = await self._apply_payload(
                url, form_index, field_name, payload, is_url_param
            )

            # --- Check 1: Command output in response (not pre-existing in baseline) ---
            match = self.check_response_for_patterns(source, OS_OUTPUT_PATTERNS)
            # 進化wave の echo マーカーは「シェル実行された出力」のときだけ採用する。
            # 入力を反射するだけのページでは marker が応答に現れるが、それは
            # `echo {marker}` の反射であって実行ではない（誤検知）。
            marker_match = re.search(r"\bwscanEVO\d+\b", payload)
            marker = marker_match.group(0) if marker_match else ""
            if (
                not match
                and check_label.endswith("_evolved")
                and marker
                # stored/反射エンドポイントでは evolution probe の素の marker が永続化され、
                # 後続ペイロードの応答（一覧）にもそのまま現れる。そこで「実行出力とみなせる
                # marker 出現数」が probe 後 baseline より**増えた**ときだけ実行と判定する。
                # 単に baseline に marker があるだけでは握り潰さないため、stored かつ実際に
                # 注入可能なケース（出力が baseline より1つ増える）も取りこぼさない。
                and _count_executed_markers(source or "", marker)
                > _count_executed_markers(echo_baseline or "", marker)
            ):
                match = marker
            if match:
                # If baseline request failed (empty body), we can't reliably say
                # whether the pattern was pre-existing. Skip the baseline check
                # only when baseline was actually captured.
                pattern_pre_existed = False
                if baseline_source:
                    baseline_match = self.check_response_for_patterns(
                        baseline_source, OS_OUTPUT_PATTERNS
                    )
                    if baseline_match:
                        pattern_pre_existed = True
                if not pattern_pre_existed:
                    evidence_suffix = (
                        "" if baseline_source else " (baseline unavailable — verify manually)"
                    )
                    finding = await self.record_finding(
                        url=url,
                        field_name=field_name,
                        payload=payload,
                        evidence=(
                            f"OS command output detected in response: '{match}'"
                            f"{evidence_suffix}"
                        ),
                        pair=pair,
                        severity="critical",
                        confidence="likely",
                    )
                    findings.append(finding)
                    return True

            # --- Check 2: Time-based blind injection ---
            # 固定リストに加え、sleep/ping/timeout を含む任意のペイロード
            # （community・進化wave 由来）でも遅延判定を行う。
            if payload in TIME_BASED_PAYLOADS or _is_time_based_os(payload):
                if self.response_time_exceeded(pair, threshold=time_threshold):
                    finding = await self.record_finding(
                        url=url,
                        field_name=field_name,
                        payload=payload,
                        evidence=f"Time-based blind OS injection: response delayed (>{time_threshold:.1f}s, baseline {baseline_time:.2f}s)",
                        pair=pair,
                        severity="high",
                    )
                    findings.append(finding)
                    return True

            await asyncio.sleep(0.2 * self.sleep_factor)
            return False

        for payload in payloads:
            if await _test_payload(payload):
                break

        if not findings:
            extra_payloads = await self.evolved_payloads(
                url, form_index, field_name, is_url_param
            )
            # evolved_payloads は内部で marker 付き probe を投入する。stored 系では
            # この probe が一覧へ永続化されるため、probe 後の状態を baseline 化して
            # echo マーカー誤検知ガード（_test_payload 内）に渡す。
            echo_baseline = ""
            if extra_payloads:
                echo_baseline, _ = await self._apply_payload(
                    url, form_index, field_name, "baseline_os_test", is_url_param
                )
            for payload in extra_payloads:
                if await _test_payload(payload, "os_evolved", echo_baseline):
                    break

        # --- Mutation wave: キャップで漏れた time-based(blind) 等を確実に投入 ---
        if not findings:
            mutated = await self.mutated_payloads(field_name, url, payloads)
            for payload in mutated:
                if await _test_payload(payload, "os_mutation"):
                    break

        return findings

    async def verify_finding(self, finding: Finding) -> bool | None:
        is_url_param = finding.field_name in parse_qs(
            urlparse(finding.url).query, keep_blank_values=True
        )
        baseline_source, baseline_pair = await self._apply_payload(
            finding.url,
            0,
            finding.field_name,
            "baseline_os_test",
            is_url_param,
        )
        source, pair = await self._apply_payload(
            finding.url,
            0,
            finding.field_name,
            finding.payload,
            is_url_param,
        )

        body = pair.get("response", {}).get("body", "") or source or ""
        match = self.check_response_for_patterns(body, OS_OUTPUT_PATTERNS)
        if match:
            baseline_body = (
                baseline_pair.get("response", {}).get("body", "")
                or baseline_source
                or ""
            )
            if baseline_body:
                baseline_match = self.check_response_for_patterns(
                    baseline_body,
                    OS_OUTPUT_PATTERNS,
                )
                if baseline_match:
                    return False
            return True

        # 進化wave の echo マーカー型 finding は検知と同じ判定で再現確認する
        # （OS_OUTPUT_PATTERNS には該当しないため、ここを欠くと verify で未確証になる）。
        marker_match = re.search(r"\bwscanEVO\d+\b", finding.payload or "")
        if marker_match:
            marker = marker_match.group(0)
            baseline_body = (
                baseline_pair.get("response", {}).get("body", "")
                or baseline_source
                or ""
            )
            if _count_executed_markers(body, marker) > _count_executed_markers(
                baseline_body, marker
            ):
                return True

        if finding.payload in TIME_BASED_PAYLOADS or _is_time_based_os(finding.payload):
            _b_req = baseline_pair.get("request", {})
            _b_resp = baseline_pair.get("response", {})
            _b_ts_req = _b_req.get("timestamp", 0)
            _b_ts_resp = _b_resp.get("timestamp", 0)
            baseline_time = (
                float(_b_ts_resp - _b_ts_req)
                if _b_ts_req and _b_ts_resp
                else 0.0
            )
            time_threshold = max(2.8, baseline_time + 2.8)
            return self.response_time_exceeded(pair, threshold=time_threshold)

        return False

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
                    f"[warn] os: _apply_payload failed on {field_name} @ {url}: {exc}"
                )
            return "", {}
