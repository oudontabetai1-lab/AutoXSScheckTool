"""
Agent Engine
============
Orchestrates an AgentBrowserScanner run, converts results to standard
Finding objects, generates an HTML report, and integrates with
MonitorServer for real-time dashboard updates.

Usage (CLI-level — see main.py `agent` subcommand):
    scanner = AgentEngine(url, llm_provider="claude", ...)
    await scanner.run()
"""
from __future__ import annotations

import datetime
import webbrowser
from pathlib import Path
from typing import Optional, TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel

if TYPE_CHECKING:
    from wscan.monitor import MonitorServer

console = Console()

# Base output directory (same convention as ScanEngine)
OUTPUT_BASE = Path(__file__).parent.parent / "output"


class AgentEngine:
    """
    High-level orchestrator for agent-browser mode scans.

    Parameters
    ----------
    url             : Target URL to scan
    llm_provider    : 'claude' | 'openai' | 'ollama'
    llm_model       : Model name (empty = provider default)
    ollama_url      : Ollama endpoint URL
    checks          : List of vulnerability types to test
    headless        : Run browser headless
    auth_user       : Login username
    auth_pass       : Login password
    login_url       : Login page URL
    max_steps       : Max agent steps
    output_dir      : Output directory path (auto-generated if None)
    open_report     : Auto-open HTML report in browser on completion
    monitor         : Optional MonitorServer for real-time updates
    port            : Dashboard port (used when started with dashboard)
    """

    def __init__(
        self,
        url: str,
        llm_provider: str = "claude",
        llm_model: str = "",
        ollama_url: str = "http://localhost:11434",
        checks: Optional[list[str]] = None,
        headless: bool = True,
        auth_user: str = "",
        auth_pass: str = "",
        login_url: str = "",
        max_steps: int = 50,
        output_dir: Optional[str] = None,
        open_report: bool = True,
        monitor: Optional["MonitorServer"] = None,
        port: int = 8765,
    ):
        self.url = url.rstrip("/")
        self.llm_provider = llm_provider
        self.llm_model = llm_model
        self.ollama_url = ollama_url
        self.checks = checks or ["xss", "sqli", "ssti", "os", "path_traversal", "ssrf"]
        self.headless = headless
        self.auth_user = auth_user
        self.auth_pass = auth_pass
        self.login_url = login_url
        self.max_steps = max_steps
        self.open_report = open_report
        self.monitor = monitor
        self.port = port

        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = Path(output_dir) if output_dir else OUTPUT_BASE / f"agent_{ts}"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(self):
        """Run the agent browser scan end-to-end."""
        from wscan.llm_agent_browser import AgentBrowserScanner, AgentScanResult
        from wscan.scanners.base import Finding
        from wscan.report import ReportGenerator

        console.print(Panel.fit(
            f"[bold magenta]WScan — Agent Browser Mode[/bold magenta]\n"
            f"Target  : [yellow]{self.url}[/yellow]\n"
            f"LLM     : [blue]{self.llm_provider}[/blue]"
            + (f" / {self.llm_model}" if self.llm_model else "") + "\n"
            f"Checks  : [green]{', '.join(self.checks)}[/green]\n"
            f"Steps   : [dim]max {self.max_steps}[/dim]",
            border_style="magenta",
        ))

        scanner = AgentBrowserScanner(
            target_url=self.url,
            llm_provider=self.llm_provider,
            llm_model=self.llm_model,
            ollama_url=self.ollama_url,
            checks=self.checks,
            headless=self.headless,
            auth_user=self.auth_user,
            auth_pass=self.auth_pass,
            login_url=self.login_url,
            max_steps=self.max_steps,
            monitor=self.monitor,
        )

        result: AgentScanResult = await scanner.run()

        # Convert AgentFindings → Finding (standard format)
        findings: list[Finding] = []
        for af in result.findings:
            findings.append(Finding(
                check_type=af.check_type,
                severity=af.severity,
                url=af.url,
                field_name=af.field_name,
                payload=af.payload,
                evidence=af.evidence,
            ))

        # Save evidence JSON
        evidence_path = self.output_dir / "evidence.json"
        import json
        evidence_path.write_text(
            json.dumps(
                {
                    "target": self.url,
                    "llm_provider": self.llm_provider,
                    "llm_model": self.llm_model,
                    "checks": self.checks,
                    "steps_taken": result.steps_taken,
                    "success": result.success,
                    "error": result.error,
                    "final_summary": result.final_summary,
                    "findings": [f.to_dict() for f in findings],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        # Save final agent summary as markdown
        if result.final_summary:
            summary_path = self.output_dir / "agent_summary.md"
            summary_path.write_text(result.final_summary, encoding="utf-8")

        # Generate HTML report
        gen = ReportGenerator(self.output_dir)
        report_path = gen.generate(
            target=self.url,
            findings=findings,
            visited_urls=[self.url],
            checks=self.checks,
        )

        console.print(
            f"\n[bold green]Agent scan complete![/bold green]  "
            f"[cyan]{len(findings)}[/cyan] finding(s)  "
            f"Report: [cyan]{report_path}[/cyan]"
        )

        if self.open_report and report_path.exists():
            webbrowser.open(str(report_path))

        if self.monitor:
            await self.monitor.emit_status(
                f"Agent scan complete — {len(findings)} finding(s)", "done"
            )
            # Push findings to dashboard
            for f in findings:
                try:
                    await self.monitor.emit_finding(f.to_dict())
                except Exception:
                    pass

        return result
