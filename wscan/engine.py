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

from .browser import BrowserManager
from .monitor import MonitorServer
from .payload_gen import PayloadGenerator
from .scanners.base import Finding
from .scanners.sqli import SQLiScanner
from .scanners.xss import XSSScanner
from .scanners.os_injection import OSInjectionScanner

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
        checks: Optional[list[str]] = None,
        output_dir: Optional[str] = None,
        timeout: int = 30,
        max_forms: int = 50,
        exclude_fields: Optional[list[str]] = None,
    ):
        self.target_url = url.rstrip("/")
        self.monitor = monitor
        self.depth = depth
        self.checks = checks or ["sqli", "xss", "os"]
        self.timeout = timeout
        self.max_forms = max_forms

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
            for check_type in ["sqli", "xss", "os", "header", "path"]:
                if check_type in custom:
                    self.custom_payloads[check_type] = custom[check_type]

        prompt_templates = payloads_data.get("llm_prompts", {})

        # Initialize components
        self.browser = BrowserManager(headless=headless, timeout=timeout, monitor=monitor)
        self.payload_gen = PayloadGenerator(
            provider=llm_provider,
            ollama_model=ollama_model,
            default_payloads=payloads_data,
            prompt_templates=prompt_templates,
        )

        # Initialize scanners
        scanner_map = {
            "sqli": SQLiScanner,
            "xss": XSSScanner,
            "os": OSInjectionScanner,
        }
        self.scanners = {
            name: cls(self)
            for name, cls in scanner_map.items()
            if name in self.checks
        }

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
        if self.monitor:
            await self.monitor.emit_status(f"Starting scan of {self.target_url}", "running")

        try:
            await self.browser.init()
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
        forms = await self.browser.find_forms()
        url_params = await self.browser.get_url_params()

        if not forms and not url_params:
            console.print(f"  [dim]No inputs found on {url}[/dim]")
            return

        form_count = min(len(forms), self.max_forms)

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
            1 for f in [fld.get("name","") for fm in forms[:form_count] for fld in fm.get("inputs",[])]
            + list(url_params)
            if f.lower() in self.exclude_fields
        )
        console.print(
            f"  Found [cyan]{form_count}[/cyan] form(s), "
            f"[cyan]{len(url_params)}[/cyan] URL param(s)"
            + (f", [yellow]{skipped} excluded[/yellow]" if skipped else "")
        )

        # Scan form fields
        for fi, form in enumerate(forms[:form_count]):
            for field in form.get("inputs", []):
                field_name = field.get("name", f"field_{fi}")
                key = f"{url}||{fi}||{field_name}"
                if key in self.scanned_forms:
                    continue
                self.scanned_forms.add(key)
                # Skip excluded fields
                if field_name.lower() in self.exclude_fields:
                    console.print(f"  [dim]Skipping excluded field: {field_name}[/dim]")
                    continue

                await self._scan_field(url, fi, field, is_url_param=False)
                await self.browser.navigate(url)

        # Scan URL parameters
        for param in url_params:
            field = {"name": param, "type": "text"}
            key = f"{url}||url_param||{param}"
            if key in self.scanned_forms:
                continue
            self.scanned_forms.add(key)
            if param.lower() in self.exclude_fields:
                console.print(f"  [dim]Skipping excluded param: {param}[/dim]")
                continue
            await self._scan_field(url, 0, field, is_url_param=True)

    async def _scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ):
        """Run all enabled scanners on a single field."""
        field_name = field.get("name", "unknown")
        location = "URL param" if is_url_param else "form field"
        console.print(f"  [dim]Testing {location}:[/dim] [green]{field_name}[/green]")

        for check_name, scanner in self.scanners.items():
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

        # Update progress after all checks on this field
        self.completed_fields += 1
        if self.monitor and self.total_fields > 0:
            pct = int(self.completed_fields / self.total_fields * 100)
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
        )

    def _print_summary(self):
        """Print scan summary to console."""
        console.print("\n" + "=" * 60)
        console.print("[bold]Scan Summary[/bold]")
        console.print(f"Target: [cyan]{self.target_url}[/cyan]")
        console.print(f"Pages visited: [cyan]{len(self.visited_urls)}[/cyan]")
        console.print(f"Total findings: [{'red' if self.all_findings else 'green'}]{len(self.all_findings)}[/{'red' if self.all_findings else 'green'}]")

        if self.all_findings:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Type", style="cyan")
            table.add_column("Severity", style="red")
            table.add_column("Field")
            table.add_column("Evidence")

            for f in self.all_findings:
                sev_color = {"critical": "red", "high": "yellow", "medium": "blue", "low": "green"}.get(f.severity, "white")
                table.add_row(
                    f.check_type.upper(),
                    f"[{sev_color}]{f.severity}[/{sev_color}]",
                    f.field_name,
                    f.evidence[:60],
                )
            console.print(table)

        console.print(f"\nReport: [cyan]{self.output_dir / 'report.html'}[/cyan]")
        console.print("=" * 60)
