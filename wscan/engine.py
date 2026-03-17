"""
WScan Scan Engine
Orchestrates the crawling and scanning pipeline.
"""
import asyncio
import datetime
import json
from collections import deque
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import yaml
from rich.console import Console
from rich.table import Table

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


class ScanEngine:
    """Main scanning engine - orchestrates crawl, scan, and evidence collection."""

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
        checks: Optional[list[str]] = None,
        output_dir: Optional[str] = None,
        timeout: int = 30,
        max_forms: int = 50,
        exclude_fields: Optional[list[str]] = None,
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

        # Set up output directory
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = OUTPUT_BASE / ts
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "screenshots").mkdir(exist_ok=True)

        # Load payloads
        default_payloads_path = CONFIG_DIR / "default_payloads.yaml"
        payloads_data = self._load_yaml(payloads_file or str(default_payloads_path))
        self.default_payloads = payloads_data
        self.custom_payloads: dict[str, list[str]] = {}

        # If a custom payloads file was specified, override defaults for those types
        if payloads_file and payloads_file != str(default_payloads_path):
            custom = self._load_yaml(payloads_file)
            for check_type in [
                "sqli", "xss", "os", "ssti",
                "path_traversal", "header_injection", "open_redirect",
            ]:
                if check_type in custom:
                    self.custom_payloads[check_type] = custom[check_type]

        prompt_templates = payloads_data.get("llm_prompts", {})

        # Initialize components
        self.browser = BrowserManager(
            headless=headless,
            timeout=timeout,
            monitor=monitor,
            auth_user=auth_user,
            auth_pass=auth_pass,
        )
        self.payload_gen = PayloadGenerator(
            provider=llm_provider,
            ollama_model=ollama_model,
            openai_model=openai_model,
            gemini_model=gemini_model,
            default_payloads=payloads_data,
            prompt_templates=prompt_templates,
        )

        # Initialize scanners — covers all IPA "安全なウェブサイトの作り方" categories
        scanner_map = {
            "sqli":             SQLiScanner,              # IPA 1.1
            "xss":              XSSScanner,               # IPA 1.5
            "os":               OSInjectionScanner,       # IPA 1.2
            "ssti":             SSTIScanner,              # bonus
            "path_traversal":   PathTraversalScanner,     # IPA 1.3
            "csrf":             CSRFScanner,              # IPA 1.6
            "header_injection": HeaderInjectionScanner,   # IPA 1.7
            "mail_header":      MailHeaderInjectionScanner, # IPA 1.8
            "open_redirect":    OpenRedirectScanner,      # IPA 1.11
            "clickjacking":     ClickjackingScanner,      # IPA 1.9
            "session":          SessionScanner,           # IPA 1.4
        }
        self.scanners = {
            name: cls(self)
            for name, cls in scanner_map.items()
            if name in self.checks
        }

        # Attack planner (AeyeScan / VEX-style AI-driven strategy)
        self.attack_planner = AttackPlanner(
            payload_gen=self.payload_gen,
            enabled_checks=self.checks,
        )
        self.attack_plans: list[PageAttackPlan] = []

        # Exclude list (case-insensitive field name matching)
        self.exclude_fields: set[str] = {f.lower() for f in (exclude_fields or [])}

        # State
        self.all_findings: list[Finding] = []
        self.visited_urls: set[str] = set()
        self.scan_queue: deque = deque()
        self.scanned_forms: set[str] = set()  # url + form_index + field_name
        self.completed_fields: int = 0  # fields fully tested
        self.total_fields: int = 0      # total fields discovered

    def _load_yaml(self, path: str) -> dict:
        try:
            with open(path, encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            console.print(f"[yellow]Warning: Could not load {path}: {e}[/yellow]")
            return {}

    async def run(self):
        """Main scan entry point."""
        console.print(f"\n[bold]Starting scan of:[/bold] [cyan]{self.target_url}[/cyan]")
        if self.use_planner:
            console.print("[dim cyan]Attack planner:[/dim cyan] enabled (AeyeScan/VEX-style)")
        if self.monitor:
            await self.monitor.emit_status(f"Starting scan of {self.target_url}", "running")

        try:
            await self.browser.init()
            if self.cookies:
                await self.browser.set_cookies(self.cookies, self.target_url)
            await self._crawl_and_scan()
        finally:
            await self.browser.close()
            self._save_evidence()
            self._generate_report()
            self._print_summary()

            if self.monitor:
                await self.monitor.emit("scan_complete", {
                    "total_findings": len(self.all_findings),
                    "report_path": str(self.output_dir / "report.html"),
                })

    async def _crawl_and_scan(self):
        """BFS crawl + scan pipeline."""
        self.scan_queue.append((self.target_url, 0))
        self.visited_urls.add(self.target_url)

        while self.scan_queue:
            url, current_depth = self.scan_queue.popleft()

            console.print(f"[dim]Visiting:[/dim] {url}")
            if self.monitor:
                await self.monitor.emit_page_start(url)

            # Navigate to page
            success = await self.browser.navigate(url)
            if not success:
                console.print(f"[yellow]  Could not navigate to {url}[/yellow]")
                continue

            # Take page screenshot
            await self.browser.screenshot_b64(f"Page: {url}")

            # Scan this page
            await self._scan_page(url)

            # Collect links for next depth level
            if current_depth < self.depth:
                links = await self.browser.collect_links(url, same_domain=True)
                for link in links:
                    clean = link.split("#")[0].split("?")[0]
                    if clean not in self.visited_urls:
                        self.visited_urls.add(clean)
                        self.scan_queue.append((link, current_depth + 1))
                        if len(self.visited_urls) > 50:  # limit crawl scope
                            break

    async def _scan_page(self, url: str):
        """Scan all forms and URL parameters on the current page."""
        # --- Page-level checks (run once per URL, no payload injection needed) ---
        for check_name, scanner in self.scanners.items():
            try:
                page_findings = await scanner.scan_page(url)
                if page_findings:
                    for f in page_findings:
                        console.print(
                            f"    [bold red][FINDING][/bold red] "
                            f"{f.check_type.upper()} (page-level) on [yellow]{url}[/yellow] "
                            f"- {f.evidence[:80]}"
                        )
            except Exception as e:
                console.print(
                    f"    [yellow]Page-level scanner error ({check_name}): {e}[/yellow]"
                )

        forms = await self.browser.find_forms()
        url_params = await self.browser.get_url_params()

        if not forms and not url_params:
            console.print(f"  [dim]No inputs found on {url}[/dim]")
            return

        form_count = min(len(forms), self.max_forms)

        # ---------------------------------------------------------------
        # Attack planning phase
        # ---------------------------------------------------------------
        attack_plan: Optional[PageAttackPlan] = None
        if self.use_planner:
            try:
                page_html = await self.browser.page.content()
            except Exception:
                page_html = ""
            attack_plan = await self.attack_planner.analyze_page(
                url, page_html, forms[:form_count], url_params
            )
            self.attack_plans.append(attack_plan)
            if self.monitor:
                await self.monitor.emit_status(
                    f"Attack plan ready: {attack_plan.page_purpose[:60]}"
                )

        # Count new testable fields to update total (for progress bar)
        new_fields = 0
        for fi, form in enumerate(forms[:form_count]):
            for field in form.get("inputs", []):
                name = field.get("name", f"field_{fi}")
                key = f"{url}||{fi}||{name}"
                if key not in self.scanned_forms and name.lower() not in self.exclude_fields:
                    new_fields += 1
        for param in url_params:
            key = f"{url}||url_param||{param}"
            if key not in self.scanned_forms and param.lower() not in self.exclude_fields:
                new_fields += 1
        self.total_fields += new_fields

        skipped = sum(
            1 for f in [fld.get("name", "") for fm in forms[:form_count]
                        for fld in fm.get("inputs", [])]
            + list(url_params)
            if f.lower() in self.exclude_fields
        )
        console.print(
            f"  Found [cyan]{form_count}[/cyan] form(s), "
            f"[cyan]{len(url_params)}[/cyan] URL param(s)"
            + (f", [yellow]{skipped} excluded[/yellow]" if skipped else "")
        )

        # ---------------------------------------------------------------
        # Determine field order: prioritised by attack plan risk score
        # ---------------------------------------------------------------
        # Build a flat list of (fi, field, is_url_param) in priority order
        field_queue: list[tuple[int, dict, bool]] = []
        for fi, form in enumerate(forms[:form_count]):
            for inp in form.get("inputs", []):
                field_queue.append((fi, inp, False))
        for param in url_params:
            field_queue.append((0, {"name": param, "type": "text"}, True))

        if attack_plan:
            def _sort_key(item: tuple[int, dict, bool]) -> int:
                fi, inp, is_url = item
                fp = attack_plan.get_field_plan(
                    inp.get("name", ""), fi, is_url
                )
                return -(fp.risk_score if fp else 5)  # higher risk first
            field_queue.sort(key=_sort_key)

        # ---------------------------------------------------------------
        # Scan fields
        # ---------------------------------------------------------------
        for fi, field, is_url_param in field_queue:
            field_name = field.get("name", f"field_{fi}")
            key = (f"{url}||url_param||{field_name}" if is_url_param
                   else f"{url}||{fi}||{field_name}")
            if key in self.scanned_forms:
                continue
            self.scanned_forms.add(key)

            if field_name.lower() in self.exclude_fields:
                console.print(f"  [dim]Skipping excluded field: {field_name}[/dim]")
                continue

            # Get field-level plan (may be None if planner disabled)
            field_plan: Optional[FieldAttackPlan] = None
            if attack_plan:
                field_plan = attack_plan.get_field_plan(field_name, fi, is_url_param)

            await self._scan_field(url, fi, field, is_url_param, field_plan)

            if not is_url_param:
                await self.browser.navigate(url)

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

        # Determine which scanners to run
        if field_plan and field_plan.priority_checks:
            # Planner's ordered list comes first, remaining enabled checks appended
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
            console.print(
                f"    [dim cyan]Plan:[/dim cyan] [dim]{field_plan.rationale[:100]}[/dim]"
            )

        for check_name in ordered_checks:
            scanner = self.scanners.get(check_name)
            if scanner is None:
                continue

            # Temporarily inject planner's targeted payloads for this check
            plan_payloads = (
                field_plan.custom_payloads.get(check_name) if field_plan else None
            )
            _prev = self.custom_payloads.get(check_name)
            if plan_payloads:
                self.custom_payloads[check_name] = plan_payloads

            try:
                findings = await scanner.scan_field(url, form_index, field, is_url_param)
                if findings:
                    for f in findings:
                        console.print(
                            f"    [bold red][FINDING][/bold red] "
                            f"{f.check_type.upper()} on [yellow]{field_name}[/yellow] "
                            f"- {f.evidence[:80]}"
                        )
            except Exception as e:
                console.print(f"    [yellow]Scanner error ({check_name}): {e}[/yellow]")
            finally:
                # Restore previous custom payloads
                if plan_payloads:
                    if _prev is None:
                        self.custom_payloads.pop(check_name, None)
                    else:
                        self.custom_payloads[check_name] = _prev

        # Update progress
        self.completed_fields += 1
        if self.monitor and self.total_fields > 0:
            await self.monitor.emit_progress(
                current=self.completed_fields,
                total=self.total_fields,
                message=f"{field_name} ({url})",
            )

    def _save_evidence(self):
        """Save all evidence to JSON file."""
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
        console.print(f"\n[dim]Evidence saved:[/dim] {evidence_path}")

    def _generate_report(self):
        """Generate HTML report."""
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
        """Print scan summary to console."""
        console.print("\n" + "=" * 60)
        console.print("[bold]Scan Summary[/bold]")
        console.print(f"Target: [cyan]{self.target_url}[/cyan]")
        console.print(f"Pages visited: [cyan]{len(self.visited_urls)}[/cyan]")
        console.print(f"Attack plans: [cyan]{len(self.attack_plans)}[/cyan]")
        console.print(
            f"Total findings: "
            f"[{'red' if self.all_findings else 'green'}]"
            f"{len(self.all_findings)}"
            f"[/{'red' if self.all_findings else 'green'}]"
        )

        if self.all_findings:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Type", style="cyan")
            table.add_column("Severity", style="red")
            table.add_column("Field")
            table.add_column("Evidence")

            for f in self.all_findings:
                sev_color = {
                    "critical": "red", "high": "yellow",
                    "medium": "blue", "low": "green",
                }.get(f.severity, "white")
                table.add_row(
                    f.check_type.upper(),
                    f"[{sev_color}]{f.severity}[/{sev_color}]",
                    f.field_name,
                    f.evidence[:60],
                )
            console.print(table)

        console.print(f"\nReport: [cyan]{self.output_dir / 'report.html'}[/cyan]")
        console.print("=" * 60)
