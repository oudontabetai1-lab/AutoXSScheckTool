"""
WScan Scan Engine — 4-Phase Pipeline
=====================================
Phase 1: Crawl   — BFS crawl, collect page info. No payload injection.
Phase 2: Plan    — Build per-page attack plans (LLM or heuristic).
                   Cross-page XSS/stored-injection awareness.
                   User confirms before attack begins.
Phase 3: Attack  — Execute attacks guided by the plan.
                   LLM adaptively re-ranks remaining pages when new findings appear.
                   Payloads = default + LLM-generated extras (combined, not replaced).
Phase 4: Report  — Save evidence JSON and generate HTML report.
"""
import asyncio
import datetime
import json
from collections import deque
from dataclasses import dataclass, field as dc_field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import yaml
from rich.console import Console
from rich.rule import Rule
from rich.table import Table
from rich import box as rbox

from .attack_planner import AttackPlanner, FieldAttackPlan, PageAttackPlan
from .browser import BrowserManager
from .monitor import MonitorServer
from .payload_gen import PayloadGenerator
from .scanners.base import Finding
from .scanners.sqli import SQLiScanner
from .scanners.xss import XSSScanner
from .scanners.os_injection import OSInjectionScanner
from .scanners.ssti import SSTIScanner
from .scanners.path_traversal import PathTraversalScanner
from .scanners.csrf import CSRFScanner
from .scanners.header_injection import HeaderInjectionScanner
from .scanners.mail_header import MailHeaderInjectionScanner
from .scanners.open_redirect import OpenRedirectScanner
from .scanners.clickjacking import ClickjackingScanner
from .scanners.session import SessionScanner

console = Console()

CONFIG_DIR = Path(__file__).parent.parent / "config"
OUTPUT_BASE = Path(__file__).parent.parent / "output"


# ---------------------------------------------------------------------------
# Data class for crawled pages
# ---------------------------------------------------------------------------

@dataclass
class CrawledPage:
    """Page data collected during Phase 1 crawl (no payload injection)."""
    url: str
    html: str
    forms: list
    url_params: list
    depth: int


# ---------------------------------------------------------------------------
# Scan Engine
# ---------------------------------------------------------------------------

class ScanEngine:
    """Main scanning engine — 4-phase pipeline."""

    def __init__(
        self,
        url: str,
        monitor: Optional[MonitorServer] = None,
        payloads_file: Optional[str] = None,
        depth: int = 2,
        headless: bool = False,
        llm_provider: str = "ollama",
        ollama_model: str = "llama3",
        openai_model: str = "gpt-4o-mini",
        gemini_model: str = "gemini-2.0-flash",
        checks: Optional[list] = None,
        output_dir: Optional[str] = None,
        timeout: int = 30,
        max_forms: int = 50,
        exclude_fields: Optional[list] = None,
        ctf_mode: bool = False,
        cookies: str = "",
        auth_user: str = "",
        auth_pass: str = "",
        use_planner: bool = True,
    ):
        self.target_url = url.rstrip("/")
        self.monitor = monitor
        self.depth = depth
        self.checks = list(checks or ["sqli", "xss", "os"])
        self.timeout = timeout
        self.max_forms = max_forms
        self.ctf_mode = ctf_mode
        self.sleep_factor = 0.5 if ctf_mode else 1.0
        self.cookies = cookies
        self.use_planner = use_planner
        if ctf_mode and "ssti" not in self.checks:
            self.checks.append("ssti")

        # Output directory
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = Path(output_dir) if output_dir else OUTPUT_BASE / ts
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "screenshots").mkdir(exist_ok=True)

        # Payloads
        default_payloads_path = CONFIG_DIR / "default_payloads.yaml"
        payloads_data = self._load_yaml(payloads_file or str(default_payloads_path))
        self.default_payloads = payloads_data
        self.custom_payloads: dict = {}
        if payloads_file and payloads_file != str(default_payloads_path):
            custom = self._load_yaml(payloads_file)
            for ct in ["sqli", "xss", "os", "ssti", "path_traversal", "header_injection", "open_redirect"]:
                if ct in custom:
                    self.custom_payloads[ct] = custom[ct]

        prompt_templates = payloads_data.get("llm_prompts", {})

        # Components
        self.browser = BrowserManager(
            headless=headless, timeout=timeout, monitor=monitor,
            auth_user=auth_user, auth_pass=auth_pass,
        )
        self.payload_gen = PayloadGenerator(
            provider=llm_provider,
            ollama_model=ollama_model,
            openai_model=openai_model,
            gemini_model=gemini_model,
            default_payloads=payloads_data,
            prompt_templates=prompt_templates,
        )

        scanner_map = {
            "sqli":             SQLiScanner,
            "xss":              XSSScanner,
            "os":               OSInjectionScanner,
            "ssti":             SSTIScanner,
            "path_traversal":   PathTraversalScanner,
            "csrf":             CSRFScanner,
            "header_injection": HeaderInjectionScanner,
            "mail_header":      MailHeaderInjectionScanner,
            "open_redirect":    OpenRedirectScanner,
            "clickjacking":     ClickjackingScanner,
            "session":          SessionScanner,
        }
        self.scanners = {n: cls(self) for n, cls in scanner_map.items() if n in self.checks}

        self.attack_planner = AttackPlanner(
            payload_gen=self.payload_gen,
            enabled_checks=self.checks,
        )

        self.exclude_fields: set = {f.lower() for f in (exclude_fields or [])}

        # State
        self.all_findings: list = []
        self.attack_plans: list = []
        self.visited_urls: set = set()
        self.scanned_forms: set = set()
        self.completed_fields: int = 0
        self.total_fields: int = 0

    # =========================================================================
    # Public entry point
    # =========================================================================

    async def run(self):
        """4-phase scan pipeline."""
        if self.monitor:
            await self.monitor.emit_status(f"Starting scan of {self.target_url}", "running")

        try:
            await self.browser.init()
            if self.cookies:
                await self.browser.set_cookies(self.cookies, self.target_url)

            # ── Phase 1: Crawl ───────────────────────────────────────────
            crawled_pages = await self._phase_crawl()

            # ── Phase 2: Plan ────────────────────────────────────────────
            plans = await self._phase_plan(crawled_pages)

            # ── Phase 3: Attack ──────────────────────────────────────────
            await self._phase_attack(crawled_pages, plans)

        finally:
            await self.browser.close()

            # ── Phase 4: Report ──────────────────────────────────────────
            self._phase_report()

            if self.monitor:
                await self.monitor.emit("scan_complete", {
                    "total_findings": len(self.all_findings),
                    "report_path": str(self.output_dir / "report.html"),
                })

    # =========================================================================
    # Phase 1: Crawl
    # =========================================================================

    async def _phase_crawl(self) -> list:
        """BFS crawl — navigate every reachable page, collect forms/HTML. No payloads."""
        console.print(Rule("[bold blue] Phase 1 / 4  ·  Crawl [/bold blue]", style="blue"))
        console.print(f"  Target: [cyan]{self.target_url}[/cyan]  depth={self.depth}\n")

        pages: list = []
        queue: deque = deque([(self.target_url, 0)])
        self.visited_urls.add(self.target_url)

        while queue:
            url, depth = queue.popleft()
            console.print(f"  [dim]Crawling[/dim] ({depth}/{self.depth}): {url}")
            if self.monitor:
                await self.monitor.emit_page_start(url)

            success = await self.browser.navigate(url)
            if not success:
                console.print(f"  [yellow]  ✘ could not load[/yellow]")
                continue

            try:
                html = await self.browser.page.content()
            except Exception:
                html = ""

            forms = await self.browser.find_forms()
            url_params = await self.browser.get_url_params()
            await self.browser.screenshot_b64(f"Crawl: {url}")

            input_count = sum(len(f.get("inputs", [])) for f in forms) + len(url_params)
            console.print(
                f"    [dim]forms:[/dim] {len(forms)}  "
                f"[dim]url params:[/dim] {len(url_params)}  "
                f"[dim]inputs:[/dim] {input_count}"
            )

            pages.append(CrawledPage(url=url, html=html, forms=forms,
                                     url_params=url_params, depth=depth))

            if depth < self.depth:
                links = await self.browser.collect_links(url, same_domain=True)
                for link in links:
                    clean = link.split("#")[0].split("?")[0]
                    if clean not in self.visited_urls and len(self.visited_urls) < 50:
                        self.visited_urls.add(clean)
                        queue.append((link, depth + 1))

        total_inputs = sum(
            sum(len(f.get("inputs", [])) for f in p.forms) + len(p.url_params)
            for p in pages
        )
        console.print(
            f"\n  [bold green]Crawl complete[/bold green]  "
            f"[cyan]{len(pages)}[/cyan] page(s) · "
            f"[cyan]{total_inputs}[/cyan] input(s) discovered"
        )
        return pages

    # =========================================================================
    # Phase 2: Plan
    # =========================================================================

    async def _phase_plan(self, pages: list) -> dict:
        """Build per-page attack plans with cross-page awareness, then confirm with user."""
        console.print(Rule("[bold cyan] Phase 2 / 4  ·  Attack Planning [/bold cyan]", style="cyan"))

        plans: dict = {}

        if not self.use_planner:
            console.print("  [dim]Planner disabled — all checks will run on every field.[/dim]")
            return plans

        # Build a site map string so LLM can reason about cross-page flows
        # (e.g., stored XSS: input on /post, reflected on /feed)
        site_map_lines = []
        for i, p in enumerate(pages):
            inp_count = sum(len(f.get("inputs", [])) for f in p.forms) + len(p.url_params)
            site_map_lines.append(
                f"  [{i+1}] {p.url}  ({len(p.forms)} form(s), {len(p.url_params)} URL param(s), "
                f"{inp_count} input(s) total)"
            )
        site_map = "\n".join(site_map_lines)

        console.print(f"  Site map ({len(pages)} page(s)):")
        console.print(f"[dim]{site_map}[/dim]\n")

        for page in pages:
            if not page.forms and not page.url_params:
                console.print(f"  [dim]No inputs on {page.url}, skipping[/dim]")
                continue

            console.print(f"  [dim cyan]Planning:[/dim cyan] {page.url}")
            plan = await self.attack_planner.analyze_page(
                url=page.url,
                page_html=page.html,
                forms=page.forms[:self.max_forms],
                url_params=page.url_params,
                site_map=site_map,
            )
            plans[page.url] = plan
            self.attack_plans.append(plan)

            if self.monitor:
                await self.monitor.emit_status(f"Plan: {plan.page_purpose[:60]}")

        # Print all plans summary and ask user to confirm
        if plans:
            self._print_all_plans(plans)

        console.print()
        console.print("[bold]  Plans are ready.[/bold] Review above, then press [green]Enter[/green] to start the attack, or [red]Ctrl+C[/red] to abort.")
        try:
            await asyncio.get_event_loop().run_in_executor(None, input, "  → ")
        except (KeyboardInterrupt, EOFError):
            raise SystemExit("\nAborted by user.")

        return plans

    def _print_all_plans(self, plans: dict):
        """Print a summary table of all page attack plans."""
        t = Table(
            title="Attack Plan Summary",
            show_header=True,
            header_style="bold magenta",
            box=rbox.ROUNDED,
        )
        t.add_column("#",           justify="right",  style="dim")
        t.add_column("Page",        style="cyan",      no_wrap=False, max_width=40)
        t.add_column("Purpose",     style="white",     max_width=30)
        t.add_column("Fields",      justify="center")
        t.add_column("Top risk",    justify="center",  style="bold")
        t.add_column("Planned by",  style="dim")

        for i, (url, plan) in enumerate(plans.items(), 1):
            top = max((fp.risk_score for fp in plan.fields), default=0)
            risk_color = "red" if top >= 8 else ("yellow" if top >= 5 else "green")
            t.add_row(
                str(i),
                url[-40:] if len(url) > 40 else url,
                plan.page_purpose[:30],
                str(len(plan.fields)),
                f"[{risk_color}]{top}[/{risk_color}]",
                plan.planned_by,
            )
        console.print(t)

    # =========================================================================
    # Phase 3: Attack
    # =========================================================================

    async def _phase_attack(self, pages: list, plans: dict):
        """Execute attacks guided by the plan. Re-rank remaining pages on new findings."""
        console.print(Rule("[bold red] Phase 3 / 4  ·  Attack [/bold red]", style="red"))

        attacked_urls: set = set()

        for page in pages:
            attacked_urls.add(page.url)

            # ── Page-level checks (header inspection, clickjacking, session, etc.) ──
            for check_name, scanner in self.scanners.items():
                try:
                    page_findings = await scanner.scan_page(page.url)
                    for f in (page_findings or []):
                        self._record_finding(f, source="page-level")
                except Exception as e:
                    console.print(f"  [yellow]Page-level ({check_name}): {e}[/yellow]")

            if not page.forms and not page.url_params:
                continue

            # Navigate back to page for form interaction
            success = await self.browser.navigate(page.url)
            if not success:
                continue

            console.print(f"\n  [bold]Attacking:[/bold] {page.url}")
            plan = plans.get(page.url)
            findings_before = len(self.all_findings)

            await self._attack_page(page, plan)

            # Adaptive re-planning: if new findings appeared, elevate risk on similar fields
            new_findings = self.all_findings[findings_before:]
            if new_findings and self.use_planner:
                remaining = [p for p in pages if p.url not in attacked_urls]
                if remaining:
                    self._adaptive_rerank(new_findings, remaining, plans)

    async def _attack_page(self, page: CrawledPage, plan: Optional[PageAttackPlan]):
        """Run all scanners on all fields of a single page."""
        forms = page.forms[:self.max_forms]

        # Build ordered field list
        field_queue: list = []
        for fi, form in enumerate(forms):
            for inp in form.get("inputs", []):
                field_queue.append((fi, inp, False))
        for param in page.url_params:
            field_queue.append((0, {"name": param, "type": "text"}, True))

        # Sort by risk score from the plan
        if plan:
            def _sort_key(item):
                fi, inp, is_url = item
                fp = plan.get_field_plan(inp.get("name", ""), fi, is_url)
                return -(fp.risk_score if fp else 5)
            field_queue.sort(key=_sort_key)

        skipped = sum(
            1 for _, inp, _ in field_queue
            if inp.get("name", "").lower() in self.exclude_fields
        )
        console.print(
            f"  [cyan]{len(forms)}[/cyan] form(s) · "
            f"[cyan]{len(page.url_params)}[/cyan] URL param(s)"
            + (f" · [yellow]{skipped} excluded[/yellow]" if skipped else "")
        )
        self.total_fields += len(field_queue) - skipped

        for fi, field, is_url_param in field_queue:
            field_name = field.get("name", f"field_{fi}")
            key = (f"{page.url}||url_param||{field_name}" if is_url_param
                   else f"{page.url}||{fi}||{field_name}")
            if key in self.scanned_forms:
                continue
            self.scanned_forms.add(key)

            if field_name.lower() in self.exclude_fields:
                console.print(f"  [dim]Skip excluded: {field_name}[/dim]")
                continue

            field_plan = plan.get_field_plan(field_name, fi, is_url_param) if plan else None
            await self._scan_field(page.url, fi, field, is_url_param, field_plan)

            if not is_url_param:
                await self.browser.navigate(page.url)

    def _adaptive_rerank(self, new_findings: list, remaining_pages: list, plans: dict):
        """
        Elevate risk scores on remaining pages for fields matching the newly found
        vulnerability types. This allows the attack to prioritise similar targets.
        """
        affected_checks = {f.check_type for f in new_findings}
        elevated = 0
        for page in remaining_pages:
            plan = plans.get(page.url)
            if not plan:
                continue
            for fp in plan.fields:
                if any(c in affected_checks for c in fp.priority_checks):
                    old = fp.risk_score
                    fp.risk_score = min(10, fp.risk_score + 2)
                    if fp.risk_score != old:
                        elevated += 1
        if elevated:
            checks_str = ", ".join(affected_checks)
            console.print(
                f"\n  [bold yellow][Adaptive Replan][/bold yellow] "
                f"New findings ({checks_str}) → "
                f"elevated risk on [cyan]{elevated}[/cyan] field(s) in remaining pages"
            )

    async def _scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
        field_plan: Optional[FieldAttackPlan] = None,
    ):
        """Run enabled scanners on a single field, guided by the attack plan."""
        field_name = field.get("name", "unknown")
        location = "URL param" if is_url_param else "form field"

        if field_plan and field_plan.priority_checks:
            planned = [c for c in field_plan.priority_checks if c in self.scanners]
            rest = [c for c in self.scanners if c not in set(planned)]
            ordered_checks = planned + rest
            risk_label = f"risk={field_plan.risk_score}/10"
        else:
            ordered_checks = list(self.scanners.keys())
            risk_label = "risk=?"

        console.print(
            f"  [dim]Testing {location}:[/dim] [green]{field_name}[/green] "
            f"[dim]({risk_label})[/dim]"
        )
        if field_plan and field_plan.rationale:
            console.print(f"    [dim cyan]Plan:[/dim cyan] [dim]{field_plan.rationale[:100]}[/dim]")

        for check_name in ordered_checks:
            scanner = self.scanners.get(check_name)
            if scanner is None:
                continue

            # Merge plan payloads with defaults (LLM extras come first, defaults appended)
            plan_payloads = field_plan.custom_payloads.get(check_name) if field_plan else None
            _prev = self.custom_payloads.get(check_name)
            if plan_payloads:
                defaults = self.payload_gen.default_payloads.get(check_name, [])
                merged = plan_payloads + [p for p in defaults if p not in plan_payloads]
                self.custom_payloads[check_name] = merged

            try:
                findings = await scanner.scan_field(url, form_index, field, is_url_param)
                for f in (findings or []):
                    self._record_finding(f, source=field_name)
            except Exception as e:
                console.print(f"    [yellow]Scanner error ({check_name}): {e}[/yellow]")
            finally:
                if plan_payloads:
                    if _prev is None:
                        self.custom_payloads.pop(check_name, None)
                    else:
                        self.custom_payloads[check_name] = _prev

        self.completed_fields += 1
        if self.monitor and self.total_fields > 0:
            await self.monitor.emit_progress(
                current=self.completed_fields,
                total=self.total_fields,
                message=f"{field_name} ({url})",
            )

    def _record_finding(self, f: Finding, source: str = ""):
        self.all_findings.append(f)
        label = f.check_type.upper()
        loc = f" on [yellow]{source}[/yellow]" if source else ""
        console.print(
            f"    [bold red][FINDING][/bold red] {label}{loc} — {f.evidence[:80]}"
        )

    # =========================================================================
    # Phase 4: Report
    # =========================================================================

    def _phase_report(self):
        console.print(Rule("[bold green] Phase 4 / 4  ·  Report [/bold green]", style="green"))
        self._save_evidence()
        self._generate_report()
        self._print_summary()

    def _save_evidence(self):
        evidence = {
            "target": self.target_url,
            "scan_date": datetime.datetime.now().isoformat(),
            "checks": self.checks,
            "visited_urls": list(self.visited_urls),
            "findings": [f.to_dict() for f in self.all_findings],
            "attack_plans": [
                {
                    "url": p.url,
                    "page_purpose": p.page_purpose,
                    "planned_by": p.planned_by,
                    "fields": [
                        {
                            "name": fp.name,
                            "risk_score": fp.risk_score,
                            "priority_checks": fp.priority_checks,
                            "rationale": fp.rationale,
                        }
                        for fp in p.fields
                    ],
                }
                for p in self.attack_plans
            ],
        }
        evidence_path = self.output_dir / "evidence.json"
        with open(evidence_path, "w", encoding="utf-8") as fp:
            json.dump(evidence, fp, ensure_ascii=False, indent=2)
        console.print(f"  [dim]Evidence:[/dim] {evidence_path}")

    def _generate_report(self):
        from .report import ReportGenerator
        gen = ReportGenerator(self.output_dir)
        gen.generate(
            target=self.target_url,
            findings=self.all_findings,
            visited_urls=list(self.visited_urls),
            checks=self.checks,
            attack_plans=self.attack_plans,
        )

    def _print_summary(self):
        console.print()
        console.print(f"  Target   : [cyan]{self.target_url}[/cyan]")
        console.print(f"  Pages    : [cyan]{len(self.visited_urls)}[/cyan]")
        console.print(f"  Plans    : [cyan]{len(self.attack_plans)}[/cyan]")
        color = "red" if self.all_findings else "green"
        console.print(f"  Findings : [{color}]{len(self.all_findings)}[/{color}]")

        if self.all_findings:
            t = Table(show_header=True, header_style="bold magenta", box=rbox.SIMPLE)
            t.add_column("Type",     style="cyan")
            t.add_column("Severity", style="red")
            t.add_column("Field")
            t.add_column("Evidence")
            for f in self.all_findings:
                sc = {"critical": "red", "high": "yellow", "medium": "blue", "low": "green"}.get(f.severity, "white")
                t.add_row(
                    f.check_type.upper(),
                    f"[{sc}]{f.severity}[/{sc}]",
                    f.field_name,
                    f.evidence[:60],
                )
            console.print(t)

        console.print(f"\n  [bold green]Report:[/bold green] [cyan]{self.output_dir / 'report.html'}[/cyan]")

    # =========================================================================
    # Helpers
    # =========================================================================

    def _load_yaml(self, path: str) -> dict:
        try:
            with open(path, encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            console.print(f"[yellow]Warning: Could not load {path}: {e}[/yellow]")
            return {}
