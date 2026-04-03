"""
Chain Scanner
=============
Detects second-order (stored) vulnerabilities and cross-parameter chains.

Phase 3c — runs AFTER all individual field scans have completed:

  1. "Injection pass": navigate to each page with a form, fill "content-likely"
     fields with a distinctive probe payload that embeds a unique marker (UID).
     The probe is safe (self-contained, no alert unless XSS fires) but visibly
     distinctive enough to detect if it appears on any OTHER page.

  2. "Observation pass": navigate to EVERY crawled page (including the source)
     and check:
       a. JS alert dialog fired → the probe executed (Stored XSS)
       b. Unencoded probe marker in HTML → HTML injection / content injection
          (injected content rendered without escaping → potential XSS vector)
       c. Rendered template output (for SSTI chain): "49wscc_UID"

  Findings are tagged with "[ChainDetect]" and include both the injection source
  (URL + field) and the page where the payload triggered.

Heuristics used:
  - "Content fields": field names that suggest user-controlled persistent content
    (comment, body, message, post, content, text, bio, description, note, …)
  - "Any form field" mode: if LLM planning flagged a field as high-risk for XSS
    or SSTI, include it in the chain probe set regardless of name.
"""
from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING

from rich.console import Console
from rich.rule import Rule

from .scanners.base import Finding

if TYPE_CHECKING:
    from .browser import BrowserManager
    from .attack_planner import PageAttackPlan

console = Console()


# ---------------------------------------------------------------------------
# Probe payload templates
# ---------------------------------------------------------------------------

# XSS probe: sets document.title to the UID so we can detect it without a
# real alert (some pages use alert suppression middleware).
_XSS_PROBE_TMPL = (
    '<img src=x id="wscc_{uid}" '
    'onerror="document.title=\'wscc_{uid}\';try{{alert(\'wscc_{uid}\')}}catch(e){{}}">'
)

# HTML injection probe: just a unique element — if this appears UNENCODED in
# another page's HTML, it means our content is being stored and rendered as HTML.
_HTML_PROBE_TMPL = (
    '<span id="wscc_{uid}" style="display:none">wscanchain_{uid}</span>'
)

# SSTI probe: Jinja2/Twig evaluate {{7*7}} → 49.
# Appending the UID makes the expected output unique: "49wscc_{uid}".
_SSTI_PROBE_TMPL = "{{7*7}}wscc_{uid}"

# Keywords that suggest a field stores user-visible content
_CONTENT_FIELD_HINTS = {
    "comment", "body", "message", "post", "content", "text", "bio",
    "description", "note", "feedback", "review", "reply", "input",
    "data", "title", "subject", "username", "name", "nick",
    "firstname", "lastname", "fullname", "profile", "about",
    "signature", "status", "tweet", "blog", "article",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ChainProbe:
    """A single probe injection record."""
    uid: str
    source_url: str
    field_name: str
    form_index: int
    probe_type: str    # "xss" | "html" | "ssti"
    payload: str


@dataclass
class ChainFinding:
    """A chain vulnerability finding returned by the scanner."""
    finding: Finding
    chain_type: str          # "stored_xss" | "html_injection" | "ssti_chain"
    source_url: str
    source_field: str
    trigger_url: str         # page where the payload fired


# ---------------------------------------------------------------------------
# Chain Scanner
# ---------------------------------------------------------------------------

class ChainScanner:
    """
    Detects stored/second-order vulnerabilities by:
    1. Injecting distinctive probe payloads into content-likely fields.
    2. Navigating to all observation pages and checking for execution.
    """

    MAX_PROBES = 20      # cap total injections to avoid very long scans
    MAX_OBS_PAGES = 30   # cap observation pages per probe cycle

    def __init__(
        self,
        browser: "BrowserManager",
        sleep_factor: float = 1.0,
        exclude_fields: Optional[set] = None,
        enabled_checks: Optional[list] = None,
    ):
        self.browser = browser
        self.sleep_factor = sleep_factor
        self.exclude_fields = exclude_fields or set()
        self.enabled_checks = set(enabled_checks or ["xss"])
        self.probes: list[ChainProbe] = []

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(
        self,
        source_pages: list,
        observation_pages: list,
        attack_plans: Optional[dict] = None,
        max_forms: int = 50,
    ) -> list[ChainFinding]:
        """
        Full chain detection cycle.
        Returns list of ChainFinding (may be empty).
        """
        console.print(Rule(
            "[bold yellow] Phase 3c / 4  ·  Chain Detection [/bold yellow]",
            style="yellow",
        ))
        console.print(
            "  クロスページ脆弱性を検査します。"
            "  (保存型XSS / コンテンツインジェクション → XSS)\n"
        )

        attack_plans = attack_plans or {}
        self.probes.clear()

        # ── Injection pass ─────────────────────────────────────────────
        await self._injection_pass(source_pages, attack_plans, max_forms)

        if not self.probes:
            console.print("  [dim]チェーン検査対象フィールドが見つかりませんでした。[/dim]")
            return []

        console.print(
            f"  [dim]{len(self.probes)}[/dim] 件のプローブを注入しました。"
            f"  観察ページ数: [dim]{min(len(observation_pages), self.MAX_OBS_PAGES)}[/dim]\n"
        )

        # ── Observation pass ───────────────────────────────────────────
        chain_findings = await self._observation_pass(
            observation_pages[:self.MAX_OBS_PAGES]
        )

        if chain_findings:
            console.print(
                f"\n  [bold red][ChainDetect][/bold red] "
                f"[red]{len(chain_findings)}[/red] 件のチェーン脆弱性を検出！"
            )
        else:
            console.print("  [dim green][ChainDetect] チェーン脆弱性は検出されませんでした。[/dim green]")

        return chain_findings

    # ------------------------------------------------------------------
    # Injection pass
    # ------------------------------------------------------------------

    async def _injection_pass(
        self,
        pages: list,
        attack_plans: dict,
        max_forms: int,
    ):
        """Navigate to each page and inject probe payloads into target fields."""
        probe_count = 0
        for page in pages:
            if probe_count >= self.MAX_PROBES:
                break
            plan: Optional["PageAttackPlan"] = attack_plans.get(page.url)

            for fi, form in enumerate(page.forms[:max_forms]):
                if probe_count >= self.MAX_PROBES:
                    break
                for inp in form.get("inputs", []):
                    if probe_count >= self.MAX_PROBES:
                        break
                    field_name = inp.get("name", "")
                    if not field_name or field_name.lower() in self.exclude_fields:
                        continue

                    if not self._is_chain_target(field_name, plan, fi, inp):
                        continue

                    # Determine which probe types to use for this field
                    probe_types = self._select_probe_types(field_name, plan, fi)

                    for ptype in probe_types:
                        uid = self._make_uid(page.url, field_name, ptype)
                        payload = self._make_payload(ptype, uid)

                        self.browser.reset_dialog()
                        ok = await self.browser.navigate(page.url)
                        if not ok:
                            continue
                        await self.browser.fill_and_submit_form(
                            fi, field_name, payload
                        )
                        await asyncio.sleep(0.4 * self.sleep_factor)

                        probe = ChainProbe(
                            uid=uid,
                            source_url=page.url,
                            field_name=field_name,
                            form_index=fi,
                            probe_type=ptype,
                            payload=payload,
                        )
                        self.probes.append(probe)
                        probe_count += 1
                        console.print(
                            f"  [dim]  + Probe [{ptype}] → "
                            f"{page.url}  field={field_name}  uid={uid}[/dim]"
                        )

    # ------------------------------------------------------------------
    # Observation pass
    # ------------------------------------------------------------------

    async def _observation_pass(self, pages: list) -> list[ChainFinding]:
        """Navigate to each observation page and detect chain executions."""
        chain_findings: list[ChainFinding] = []
        uid_to_probe = {p.uid: p for p in self.probes}

        for page in pages:
            self.browser.reset_dialog()
            ok = await self.browser.navigate(page.url)
            if not ok:
                continue
            await asyncio.sleep(0.5 * self.sleep_factor)

            # ── a) Alert dialog fired (Stored XSS) ───────────────────
            if self.browser.dialog_fired:
                msg = self.browser.dialog_message
                matched_probe = next(
                    (p for uid, p in uid_to_probe.items() if uid in msg), None
                )
                cf = await self._make_xss_finding(
                    probe=matched_probe,
                    trigger_url=page.url,
                    evidence=(
                        f"[ChainDetect] Stored XSS dialog fired: '{msg[:120]}'"
                        + (f" (injected via {matched_probe.source_url} "
                           f"field '{matched_probe.field_name}')"
                           if matched_probe else " (source unknown)")
                    ),
                    severity="critical",
                )
                if cf:
                    chain_findings.append(cf)
                    self.browser.reset_dialog()
                continue  # move on if we already have a confirmed XSS

            html = await self.browser.get_page_source()
            if not html:
                continue

            # ── b) Unencoded probe marker in HTML (HTML/content injection) ──
            for uid, probe in uid_to_probe.items():
                # Skip probes injected ON this very page (same-page reflection
                # is caught by the regular XSS scanner already)
                if probe.source_url == page.url:
                    continue

                if probe.probe_type == "xss":
                    # Check for unencoded tag (id attribute survived rendering)
                    marker = f'id="wscc_{uid}"'
                    if marker in html:
                        cf = await self._make_html_injection_finding(
                            probe=probe,
                            trigger_url=page.url,
                            evidence=(
                                f"[ChainDetect] Stored HTML injection: probe marker "
                                f"'{marker}' found unencoded on {page.url} "
                                f"(injected via {probe.source_url} "
                                f"field '{probe.field_name}')"
                            ),
                        )
                        if cf:
                            chain_findings.append(cf)
                            break  # one finding per page is enough

                elif probe.probe_type == "html":
                    # Simple text marker appeared without encoding
                    if f"wscanchain_{uid}" in html:
                        cf = await self._make_html_injection_finding(
                            probe=probe,
                            trigger_url=page.url,
                            evidence=(
                                f"[ChainDetect] Content injection: "
                                f"'wscanchain_{uid}' appeared on {page.url} "
                                f"(injected via {probe.source_url} "
                                f"field '{probe.field_name}')"
                            ),
                        )
                        if cf:
                            chain_findings.append(cf)
                            break

                elif probe.probe_type == "ssti":
                    # SSTI: {{7*7}}wscc_{uid} → "49wscc_{uid}" if Jinja2/Twig evaluates
                    if f"49wscc_{uid}" in html:
                        cf = await self._make_ssti_chain_finding(
                            probe=probe,
                            trigger_url=page.url,
                            evidence=(
                                f"[ChainDetect] SSTI chain: template evaluated "
                                f"on {page.url} "
                                f"(injected via {probe.source_url} "
                                f"field '{probe.field_name}')"
                            ),
                        )
                        if cf:
                            chain_findings.append(cf)
                            break

            # ── c) Page title changed (XSS via document.title) ────────
            try:
                title = await self.browser.page.title()
                for uid, probe in uid_to_probe.items():
                    if uid in title and probe.source_url != page.url:
                        cf = await self._make_xss_finding(
                            probe=probe,
                            trigger_url=page.url,
                            evidence=(
                                f"[ChainDetect] Stored XSS: document.title modified "
                                f"on {page.url} → '{title[:80]}' "
                                f"(injected via {probe.source_url} "
                                f"field '{probe.field_name}')"
                            ),
                            severity="high",
                        )
                        if cf:
                            chain_findings.append(cf)
                            break
            except Exception:
                pass

        return chain_findings

    # ------------------------------------------------------------------
    # Heuristics: which fields to probe, which probe types to use
    # ------------------------------------------------------------------

    def _is_chain_target(
        self,
        field_name: str,
        plan: Optional["PageAttackPlan"],
        form_index: int,
        inp: dict,
    ) -> bool:
        """Return True if this field should receive chain probes."""
        fname_lower = field_name.lower()

        # Always probe content-hint fields
        for hint in _CONTENT_FIELD_HINTS:
            if hint in fname_lower:
                return True

        # Probe fields that the attack plan rated as high-risk for XSS / SSTI
        if plan:
            fp = plan.get_field_plan(field_name, form_index, False)
            if fp and fp.risk_score >= 6:
                if any(c in ("xss", "ssti") for c in fp.priority_checks):
                    return True

        return False

    def _select_probe_types(
        self,
        field_name: str,
        plan: Optional["PageAttackPlan"],
        form_index: int,
    ) -> list[str]:
        """Return list of probe types to inject into this field."""
        types = []
        if "xss" in self.enabled_checks:
            types.append("xss")
        # HTML probe adds noise — only inject for very content-likely names
        fname_lower = field_name.lower()
        if any(h in fname_lower for h in ("comment", "body", "message", "content", "post", "text")):
            types.append("html")
        if "ssti" in self.enabled_checks:
            if any(h in fname_lower for h in ("template", "theme", "layout", "view")):
                types.append("ssti")
        return types

    # ------------------------------------------------------------------
    # Finding factories
    # ------------------------------------------------------------------

    async def _make_xss_finding(
        self,
        probe: Optional[ChainProbe],
        trigger_url: str,
        evidence: str,
        severity: str = "high",
    ) -> Optional[ChainFinding]:
        screenshot = await self.browser.screenshot_b64("[ChainDetect] XSS")
        f = Finding(
            check_type="xss",
            severity=severity,
            url=trigger_url,
            field_name=probe.field_name if probe else "unknown",
            payload=probe.payload if probe else "",
            evidence=evidence,
            screenshot_b64=screenshot,
            dialog_confirmed=(severity == "critical"),
            dialog_message=self.browser.dialog_message if severity == "critical" else "",
        )
        return ChainFinding(
            finding=f,
            chain_type="stored_xss",
            source_url=probe.source_url if probe else "",
            source_field=probe.field_name if probe else "",
            trigger_url=trigger_url,
        )

    async def _make_html_injection_finding(
        self,
        probe: ChainProbe,
        trigger_url: str,
        evidence: str,
    ) -> Optional[ChainFinding]:
        screenshot = await self.browser.screenshot_b64("[ChainDetect] HTML injection")
        f = Finding(
            check_type="xss",
            severity="medium",
            url=trigger_url,
            field_name=probe.field_name,
            payload=probe.payload,
            evidence=evidence,
            screenshot_b64=screenshot,
        )
        return ChainFinding(
            finding=f,
            chain_type="html_injection",
            source_url=probe.source_url,
            source_field=probe.field_name,
            trigger_url=trigger_url,
        )

    async def _make_ssti_chain_finding(
        self,
        probe: ChainProbe,
        trigger_url: str,
        evidence: str,
    ) -> Optional[ChainFinding]:
        screenshot = await self.browser.screenshot_b64("[ChainDetect] SSTI chain")
        f = Finding(
            check_type="ssti",
            severity="high",
            url=trigger_url,
            field_name=probe.field_name,
            payload=probe.payload,
            evidence=evidence,
            screenshot_b64=screenshot,
        )
        return ChainFinding(
            finding=f,
            chain_type="ssti_chain",
            source_url=probe.source_url,
            source_field=probe.field_name,
            trigger_url=trigger_url,
        )

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _make_uid(url: str, field_name: str, ptype: str) -> str:
        raw = f"{url}:{field_name}:{ptype}:{time.time()}"
        return hashlib.md5(raw.encode()).hexdigest()[:8]

    @staticmethod
    def _make_payload(probe_type: str, uid: str) -> str:
        if probe_type == "xss":
            return _XSS_PROBE_TMPL.format(uid=uid)
        if probe_type == "html":
            return _HTML_PROBE_TMPL.format(uid=uid)
        if probe_type == "ssti":
            return _SSTI_PROBE_TMPL.format(uid=uid)
        return ""
