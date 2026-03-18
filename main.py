#!/usr/bin/env python3
"""
WScan - Web Security Scanner
Automated security testing with real-time monitoring dashboard.

Usage:
  python main.py scan <url>
  python main.py scan <url> --payloads custom_payloads.yaml
  python main.py scan <url> --checks sqli xss
  python main.py scan <url> --depth 3 --headless --llm ollama
"""
import asyncio
import argparse
import sys
import webbrowser
from pathlib import Path

# Ensure the wscan package is importable
sys.path.insert(0, str(Path(__file__).parent))


def parse_args():
    parser = argparse.ArgumentParser(
        description="WScan - Web Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py scan https://example.com
  python main.py scan https://example.com --payloads my_payloads.yaml
  python main.py scan https://example.com --checks sqli xss --depth 3
  python main.py scan https://example.com --headless --llm claude
  python main.py scan https://example.com --no-monitor
        """,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── scan subcommand ────────────────────────────────────────────
    scan = sub.add_parser("scan", help="Run a security scan")
    scan.add_argument("url", help="Target URL (e.g. https://example.com)")

    scan.add_argument(
        "--payloads", "-p", metavar="FILE",
        help="Custom payloads YAML file (see config/default_payloads.yaml for format)",
    )
    _ALL_CHECKS = [
        "sqli", "xss", "os", "path_traversal",
        "session", "csrf", "header_injection", "mail_header",
        "clickjacking", "open_redirect", "ssti",
    ]
    scan.add_argument(
        "--checks", nargs="+",
        choices=_ALL_CHECKS,
        default=["sqli", "xss", "os"],
        metavar="CHECK",
        help=(
            "Security checks to run (default: sqli xss os). "
            "Available: " + ", ".join(_ALL_CHECKS)
        ),
    )
    scan.add_argument(
        "--depth", "-d", type=int, default=2, metavar="N",
        help="Crawl depth: how many links deep to follow (default: 2)",
    )
    scan.add_argument(
        "--headless", action="store_true",
        help="Run browser in headless mode (no visible window)",
    )
    scan.add_argument(
        "--no-monitor", action="store_true",
        help="Disable the real-time monitoring dashboard",
    )
    scan.add_argument(
        "--llm",
        choices=["ollama", "claude", "openai", "gemini", "none"],
        default="ollama",
        help=(
            "LLM for context-aware payload generation (default: ollama). "
            "openai requires OPENAI_API_KEY env var. "
            "gemini requires GEMINI_API_KEY env var."
        ),
    )
    scan.add_argument(
        "--ollama-model", default="llama3", metavar="MODEL",
        help="Ollama model name (default: llama3)",
    )
    scan.add_argument(
        "--openai-model", default="gpt-4o-mini", metavar="MODEL",
        help="OpenAI model name (default: gpt-4o-mini)",
    )
    scan.add_argument(
        "--gemini-model", default="gemini-2.0-flash", metavar="MODEL",
        help="Google Gemini model name (default: gemini-2.0-flash)",
    )
    scan.add_argument(
        "--output", "-o", metavar="DIR",
        help="Output directory for evidence and reports (default: output/<timestamp>)",
    )
    scan.add_argument(
        "--port", type=int, default=8765,
        help="Monitoring dashboard port (default: 8765)",
    )
    scan.add_argument(
        "--timeout", type=int, default=30, metavar="SECS",
        help="Request timeout in seconds (default: 30)",
    )
    scan.add_argument(
        "--max-forms", type=int, default=50, metavar="N",
        help="Max forms to test per page (default: 50)",
    )
    scan.add_argument(
        "--exclude", "-e", nargs="+", metavar="PARAM", default=[],
        help="Parameter/field names to skip (e.g. --exclude csrf_token __token)",
    )
    scan.add_argument(
        "--exclude-file", metavar="FILE",
        help="Text file with one excluded parameter name per line",
    )
    scan.add_argument(
        "--exclude-urls-file", metavar="FILE",
        help=(
            "Text file with URLs/prefixes to skip during crawl and attack "
            "(one entry per line, lines starting with # are ignored). "
            "Prefix match: 'http://host/admin' skips all /admin/* URLs."
        ),
    )
    scan.add_argument(
        "--ctf", action="store_true",
        help="CTF mode: adds SSTI scanner and halves sleep delays for faster scanning",
    )
    scan.add_argument(
        "--ctf-flag-format", metavar="REGEX", default="",
        help=(
            "Regex pattern to search for CTF flags (default: auto-detect FLAG/CTF/HTB formats). "
            "Example: 'HTB{[^}]+}' or 'picoCTF{[^}]+}'"
        ),
    )
    scan.add_argument(
        "--cookie", metavar="COOKIES", default="",
        help="Pre-set cookies before scanning (e.g. 'session=abc; token=xyz')",
    )
    scan.add_argument(
        "--auth-user", metavar="USER", default="",
        help="Username/email for login form auto-fill",
    )
    scan.add_argument(
        "--auth-pass", metavar="PASS", default="",
        help="Password for login form auto-fill",
    )
    scan.add_argument(
        "--no-planner", action="store_true",
        help=(
            "Disable the AI attack planner. "
            "Runs all checks on all fields without strategic prioritisation."
        ),
    )
    scan.add_argument(
        "--interactive-plan", action="store_true",
        help=(
            "After crawling, open the interactive plan editor to review and "
            "adjust risk scores, checks, and payloads per field before attacking. "
            "Enabled automatically when --llm none."
        ),
    )

    return parser.parse_args()


def _llm_model_display(args) -> str:
    """Return a short model info string for the startup banner."""
    if args.llm == "ollama":
        return f"Model    : [blue]{args.ollama_model}[/blue] (Ollama)"
    if args.llm == "openai":
        return f"Model    : [blue]{args.openai_model}[/blue] (OpenAI)"
    if args.llm == "gemini":
        return f"Model    : [blue]{args.gemini_model}[/blue] (Gemini)"
    if args.llm == "claude":
        return "Model    : [blue]claude-haiku-4-5-20251001[/blue] (Claude)"
    return "Model    : [dim]none[/dim]"


async def run_scan(args):
    from rich.console import Console
    from rich.panel import Panel

    console = Console()

    checks_display = ', '.join(args.checks) if args.checks else "all IPA checks"
    planner_display = "off" if getattr(args, "no_planner", False) else "on (AI-driven)"
    console.print(Panel.fit(
        f"[bold cyan]WScan - Web Security Scanner[/bold cyan]\n"
        f"Target   : [yellow]{args.url}[/yellow]\n"
        f"Checks   : [green]{checks_display}[/green]\n"
        f"Planner  : [cyan]{planner_display}[/cyan]\n"
        f"Depth    : [blue]{args.depth}[/blue]   "
        f"LLM: [blue]{args.llm}[/blue]   "
        f"Headless: [blue]{args.headless}[/blue]\n"
        + _llm_model_display(args),
        border_style="cyan",
    ))

    # Build exclude list from --exclude and --exclude-file
    exclude_fields = list(args.exclude)
    if args.exclude_file:
        try:
            lines = Path(args.exclude_file).read_text(encoding="utf-8").splitlines()
            exclude_fields += [l.strip() for l in lines if l.strip() and not l.startswith("#")]
        except Exception as ex:
            console.print(f"[yellow]Warning: Could not read exclude file: {ex}[/yellow]")

    if exclude_fields:
        console.print(f"Excluded params : [yellow]{', '.join(exclude_fields)}[/yellow]")

    # Build exclude-urls list from --exclude-urls-file
    exclude_urls: list = []
    excl_urls_file = getattr(args, "exclude_urls_file", None)
    if excl_urls_file:
        try:
            lines = Path(excl_urls_file).read_text(encoding="utf-8").splitlines()
            exclude_urls = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
            console.print(f"Excluded URLs   : [yellow]{len(exclude_urls)} entry/entries from {excl_urls_file}[/yellow]")
        except Exception as ex:
            console.print(f"[yellow]Warning: Could not read exclude-urls file: {ex}[/yellow]")

    if args.no_monitor:
        # Simple mode - no web dashboard
        from wscan.engine import ScanEngine
        from wscan.monitor import MonitorServer

        monitor = MonitorServer(port=args.port)
        engine = ScanEngine(
            url=args.url,
            monitor=monitor,
            payloads_file=args.payloads,
            depth=args.depth,
            headless=args.headless,
            llm_provider=args.llm,
            ollama_model=args.ollama_model,
            openai_model=args.openai_model,
            gemini_model=args.gemini_model,
            checks=args.checks,
            output_dir=args.output,
            timeout=args.timeout,
            max_forms=args.max_forms,
            exclude_fields=exclude_fields,
            exclude_urls=exclude_urls,
            ctf_mode=getattr(args, "ctf", False),
            ctf_flag_pattern=getattr(args, "ctf_flag_format", "") or "",
            cookies=getattr(args, "cookie", "") or "",
            auth_user=getattr(args, "auth_user", "") or "",
            auth_pass=getattr(args, "auth_pass", "") or "",
            use_planner=not getattr(args, "no_planner", False),
            interactive_plan=getattr(args, "interactive_plan", False) or args.llm == "none",
        )
        await engine.run()
        return

    # ── With monitoring dashboard ──────────────────────────────────
    import uvicorn
    from wscan.monitor import MonitorServer
    from wscan.engine import ScanEngine

    monitor = MonitorServer(port=args.port)
    config = uvicorn.Config(
        app=monitor.app,
        host="0.0.0.0",
        port=args.port,
        log_level="error",
    )
    server = uvicorn.Server(config)

    async def run_scanner_task():
        # Wait for uvicorn to be ready
        await asyncio.sleep(1.5)

        console.print(
            f"\n[cyan]Monitoring dashboard:[/cyan] "
            f"[underline]http://localhost:{args.port}[/underline]"
        )
        webbrowser.open(f"http://localhost:{args.port}")

        try:
            engine = ScanEngine(
                url=args.url,
                monitor=monitor,
                payloads_file=args.payloads,
                depth=args.depth,
                headless=args.headless,
                llm_provider=args.llm,
                ollama_model=args.ollama_model,
                openai_model=args.openai_model,
                gemini_model=args.gemini_model,
                checks=args.checks,
                output_dir=args.output,
                timeout=args.timeout,
                max_forms=args.max_forms,
                exclude_fields=exclude_fields,
                exclude_urls=exclude_urls,
                ctf_mode=getattr(args, "ctf", False),
                ctf_flag_pattern=getattr(args, "ctf_flag_format", "") or "",
                cookies=getattr(args, "cookie", "") or "",
                auth_user=getattr(args, "auth_user", "") or "",
                auth_pass=getattr(args, "auth_pass", "") or "",
                use_planner=not getattr(args, "no_planner", False),
                interactive_plan=getattr(args, "interactive_plan", False) or args.llm == "none",
            )
            await engine.run()

            console.print(
                f"\n[bold green]Scan complete![/bold green]  "
                f"Report: [cyan]{engine.output_dir / 'report.html'}[/cyan]"
            )
            console.print(
                "[dim]Dashboard is still running — press Ctrl+C to stop.[/dim]"
            )
            # Keep dashboard alive so the user can review findings
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            console.print(f"\n[red]Error: {exc}[/red]")
            raise
        finally:
            server.should_exit = True

    await asyncio.gather(
        server.serve(),
        run_scanner_task(),
    )


def main():
    args = parse_args()
    try:
        asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)


if __name__ == "__main__":
    main()
