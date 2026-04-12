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
import json
import sys
import webbrowser
from pathlib import Path

# Ensure the wscan package is importable
sys.path.insert(0, str(Path(__file__).parent))

# ──────────────────────────────────────────────────────────────────
# Config file loader (config/wscan.yaml)
# ──────────────────────────────────────────────────────────────────
_CONFIG_PATH = Path(__file__).parent / "config" / "wscan.yaml"


def _load_config(path: Path = _CONFIG_PATH) -> dict:
    """
    Load config/wscan.yaml and return a flat dict of resolved values.
    Returns defaults silently if the file is missing or unparseable.
    """
    cfg: dict = {}
    if not path.exists():
        return cfg
    try:
        import yaml
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return cfg

    # ── Flatten into a single namespace ──────────────────────────
    s   = raw.get("scan",     {})
    b   = raw.get("browser",  {})
    l   = raw.get("llm",      {})
    m   = raw.get("monitor",  {})
    pl  = raw.get("planner",  {})
    a   = raw.get("auth",     {})
    f   = raw.get("features", {})
    le  = raw.get("learning", {})
    ct  = raw.get("ctf",      {})
    o   = raw.get("output",   {})

    cfg["checks"]                  = s.get("checks",    ["sqli", "xss", "os"])
    cfg["depth"]                   = int(s.get("depth",     2))
    cfg["max_forms"]               = int(s.get("max_forms", 50))
    cfg["timeout"]                 = int(s.get("timeout",   30))
    cfg["exclude_fields"]          = list(s.get("exclude_fields", []))
    cfg["exclude_urls"]            = list(s.get("exclude_urls",   []))

    cfg["headless"]                = bool(b.get("headless", False))
    cfg["proxy"]                   = str(b.get("proxy", "") or "")

    cfg["llm_provider"]            = str(l.get("provider",     "ollama"))
    cfg["ollama_model"]            = str(l.get("ollama_model", "llama3"))
    cfg["ollama_url"]              = str(l.get("ollama_url",   "http://localhost:11434"))
    cfg["openai_model"]            = str(l.get("openai_model", "gpt-4o-mini"))
    cfg["gemini_model"]            = str(l.get("gemini_model", "gemini-2.0-flash"))

    cfg["monitor_enabled"]         = bool(m.get("enabled", True))
    cfg["port"]                    = int(m.get("port", 8765))

    cfg["use_planner"]             = bool(pl.get("enabled",     True))
    cfg["interactive_plan"]        = bool(pl.get("interactive", False))

    cfg["login_url"]               = str(a.get("login_url",               "") or "")
    cfg["login_user_field"]        = str(a.get("login_user_field",        "username"))
    cfg["login_pass_field"]        = str(a.get("login_pass_field",        "password"))
    cfg["login_success_indicator"] = str(a.get("login_success_indicator", "") or "")
    cfg["auth_user"]               = str(a.get("auth_user", "") or "")
    cfg["auth_pass"]               = str(a.get("auth_pass", "") or "")

    cfg["dom_xss"]                 = bool(f.get("dom_xss",          False))
    cfg["ai_analysis"]             = bool(f.get("ai_analysis",      True))
    cfg["waf_detection"]           = bool(f.get("waf_detection",    True))
    cfg["payload_learning"]        = bool(f.get("payload_learning", True))
    cfg["sitemap_crawl"]           = bool(f.get("sitemap_crawl",    True))
    cfg["cvss_scores"]             = bool(f.get("cvss_scores",      True))
    cfg["skip_registration"]       = bool(f.get("skip_registration", True))
    cfg["open_report"]             = bool(f.get("open_report",      True))
    cfg["auto_config"]             = bool(f.get("auto_config",      False))

    cfg["learning_file"]           = str(le.get("file", "") or "")

    cfg["ctf_mode"]                = bool(ct.get("enabled",      False))
    cfg["ctf_flag_pattern"]        = str(ct.get("flag_pattern",  "") or "")

    cfg["output_dir"]              = str(o.get("dir",           "") or "")
    cfg["payloads_file"]           = str(o.get("payloads_file", "") or "")

    return cfg


# Load once at import time so parse_args() can reference it
_CFG = _load_config()


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
        default=_CFG.get("payloads_file") or None,
        help="Custom payloads YAML file (see config/default_payloads.yaml for format)",
    )
    _ALL_CHECKS = [
        "sqli", "xss", "dom_xss", "stored_xss", "os", "path_traversal",
        "session", "csrf", "header_injection", "mail_header",
        "clickjacking", "open_redirect", "ssti", "privesc",
        "cors", "info_disclosure", "host_header", "security_headers",
        "nosql", "deserialization", "request_smuggling", "ssrf",
        "graphql", "jwt",
    ]
    _default_checks = _CFG.get("checks", ["sqli", "xss", "os"])
    scan.add_argument(
        "--checks", nargs="+",
        choices=_ALL_CHECKS,
        default=_default_checks,
        metavar="CHECK",
        help=(
            f"Security checks to run (default from config: {' '.join(_default_checks)}). "
            "Available: " + ", ".join(_ALL_CHECKS)
        ),
    )
    scan.add_argument(
        "--depth", "-d", type=int, default=_CFG.get("depth", 2), metavar="N",
        help=f"Crawl depth (default: {_CFG.get('depth', 2)})",
    )
    scan.add_argument(
        "--headless", action="store_true", default=_CFG.get("headless", False),
        help="Run browser in headless mode (no visible window)",
    )
    scan.add_argument(
        "--no-monitor", action="store_true",
        default=not _CFG.get("monitor_enabled", True),
        help="Disable the real-time monitoring dashboard",
    )
    scan.add_argument(
        "--llm",
        choices=["ollama", "claude", "openai", "gemini", "none"],
        default=_CFG.get("llm_provider", "ollama"),
        help=(
            f"LLM for payload generation (default from config: {_CFG.get('llm_provider','ollama')}). "
            "openai requires OPENAI_API_KEY. gemini requires GEMINI_API_KEY."
        ),
    )
    scan.add_argument(
        "--ollama-model", default=_CFG.get("ollama_model", "llama3"), metavar="MODEL",
        help=f"Ollama model name (default: {_CFG.get('ollama_model','llama3')})",
    )
    scan.add_argument(
        "--openai-model", default=_CFG.get("openai_model", "gpt-4o-mini"), metavar="MODEL",
        help=f"OpenAI model name (default: {_CFG.get('openai_model','gpt-4o-mini')})",
    )
    scan.add_argument(
        "--gemini-model", default=_CFG.get("gemini_model", "gemini-2.0-flash"), metavar="MODEL",
        help=f"Google Gemini model name (default: {_CFG.get('gemini_model','gemini-2.0-flash')})",
    )
    scan.add_argument(
        "--output", "-o", metavar="DIR",
        default=_CFG.get("output_dir") or None,
        help="Output directory for evidence and reports (default: output/<timestamp>)",
    )
    scan.add_argument(
        "--port", type=int, default=_CFG.get("port", 8765),
        help=f"Monitoring dashboard port (default: {_CFG.get('port', 8765)})",
    )
    scan.add_argument(
        "--timeout", type=int, default=_CFG.get("timeout", 30), metavar="SECS",
        help=f"Request timeout in seconds (default: {_CFG.get('timeout', 30)})",
    )
    scan.add_argument(
        "--max-forms", type=int, default=_CFG.get("max_forms", 50), metavar="N",
        help=f"Max forms to test per page (default: {_CFG.get('max_forms', 50)})",
    )
    scan.add_argument(
        "--exclude", "-e", nargs="+", metavar="PARAM",
        default=_CFG.get("exclude_fields", []),
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
            "(one entry per line, lines starting with # are ignored)."
        ),
    )
    scan.add_argument(
        "--ctf", action="store_true", default=_CFG.get("ctf_mode", False),
        help="CTF mode: adds SSTI scanner and halves sleep delays for faster scanning",
    )
    scan.add_argument(
        "--ctf-flag-format", metavar="REGEX", default=_CFG.get("ctf_flag_pattern", ""),
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
        "--cookie-file", metavar="FILE", default="",
        help=(
            "JSON file containing cookies from a successful login session "
            "(browser export format: list of {name, value, domain, path, …} objects)."
        ),
    )
    scan.add_argument(
        "--low-priv-cookies", metavar="COOKIES", default="",
        help=(
            "Cookie string for a low-privilege session used to test vertical "
            "privilege escalation (e.g. 'session=lowprivtoken')."
        ),
    )
    scan.add_argument(
        "--low-priv-cookie-file", metavar="FILE", default="",
        help="JSON file containing low-privilege session cookies (same format as --cookie-file).",
    )
    scan.add_argument(
        "--auth-user", metavar="USER", default=_CFG.get("auth_user", ""),
        help="Username/email for login form auto-fill",
    )
    scan.add_argument(
        "--auth-pass", metavar="PASS", default=_CFG.get("auth_pass", ""),
        help="Password for login form auto-fill",
    )
    scan.add_argument(
        "--include-registration", action="store_true",
        default=not _CFG.get("skip_registration", True),
        help=(
            "Also test registration / sign-up forms (config default: "
            f"{'include' if not _CFG.get('skip_registration', True) else 'skip'})."
        ),
    )
    scan.add_argument(
        "--no-planner", action="store_true",
        default=not _CFG.get("use_planner", True),
        help="Disable the AI attack planner.",
    )
    scan.add_argument(
        "--interactive-plan", action="store_true",
        default=_CFG.get("interactive_plan", False),
        help="Open the interactive plan editor before attacking.",
    )
    scan.add_argument(
        "--no-open-report", action="store_true",
        default=not _CFG.get("open_report", True),
        help="Do not automatically open the HTML report after scanning.",
    )
    # CI-3: Proxy support
    scan.add_argument(
        "--proxy", metavar="URL", default=_CFG.get("proxy", ""),
        help=(
            "HTTP proxy URL for all browser/HTTP requests "
            "(e.g. http://127.0.0.1:8080 for Burp Suite / mitmproxy)."
        ),
    )
    # Auth-1: Login automation
    scan.add_argument(
        "--login-url", metavar="URL", default=_CFG.get("login_url", ""),
        help="URL of the login page for automatic authentication before scanning.",
    )
    scan.add_argument(
        "--login-user-field", metavar="NAME", default=_CFG.get("login_user_field", "username"),
        help=f"Username input field name on the login form (default: {_CFG.get('login_user_field','username')}).",
    )
    scan.add_argument(
        "--login-pass-field", metavar="NAME", default=_CFG.get("login_pass_field", "password"),
        help=f"Password input field name on the login form (default: {_CFG.get('login_pass_field','password')}).",
    )
    scan.add_argument(
        "--login-success", metavar="TEXT", default=_CFG.get("login_success_indicator", ""),
        help="Substring expected in the post-login URL or page to confirm success.",
    )
    # A-3: Payload learning
    scan.add_argument(
        "--learning-file", metavar="FILE", default=_CFG.get("learning_file", ""),
        help="JSON file for payload continuous learning (default: config/payload_learning.json).",
    )
    # S-1: DOM XSS
    scan.add_argument(
        "--dom-xss", action="store_true", default=_CFG.get("dom_xss", False),
        help="Enable DOM-based XSS detection (hooks browser DOM sinks via Playwright).",
    )
    # Feature flags that can also be toggled via config
    scan.add_argument(
        "--no-ai-analysis", action="store_true",
        default=not _CFG.get("ai_analysis", True),
        help="Disable post-scan AI comprehensive analysis report.",
    )
    scan.add_argument(
        "--no-waf-detection", action="store_true",
        default=not _CFG.get("waf_detection", True),
        help="Disable WAF auto-detection probe before crawling.",
    )
    scan.add_argument(
        "--no-payload-learning", action="store_true",
        default=not _CFG.get("payload_learning", True),
        help="Disable payload continuous learning (don't load/save success rates).",
    )
    scan.add_argument(
        "--no-sitemap-crawl", action="store_true",
        default=not _CFG.get("sitemap_crawl", True),
        help="Disable sitemap.xml / robots.txt crawl seeding.",
    )
    scan.add_argument(
        "--concurrency", "-j", type=int, default=1, metavar="N",
        help=(
            "Number of parallel browser workers for Phase 3 (default: 1 = serial). "
            "Each worker gets its own Playwright page so N pages are attacked simultaneously. "
            "Recommended range: 2-4. Higher values increase speed but also server load."
        ),
    )
    scan.add_argument(
        "--fast", "-F", action="store_true", default=False,
        help=(
            "高速スキャンモード (ベストエフォート): ペイロード上限 12・深さ 1・遅延 0 で "
            "高リスク脆弱性を素早く発見する。各フラグで個別上書き可能。"
        ),
    )
    scan.add_argument(
        "--max-payloads", type=int, default=0, metavar="N",
        help=(
            "フィールド・チェックタイプ毎のペイロード上限 (0=無制限)。"
            "--fast 時のデフォルトは 12。単独でも指定可能。"
        ),
    )
    # A: Multi-account privilege escalation
    scan.add_argument(
        "--accounts", metavar="USER:PASS,...",
        default="",
        help=(
            "Comma-separated list of user:password pairs for multi-account "
            "privilege escalation testing. "
            "Example: --accounts admin:admin123,user1:pass1,user2:pass2"
        ),
    )
    scan.add_argument(
        "--accounts-file", metavar="FILE",
        default="",
        help=(
            "YAML file with account list for privilege escalation testing. "
            "Format: accounts: [{username: x, password: y, role: z}]"
        ),
    )
    scan.add_argument(
        "--auto-register", action="store_true",
        default=_CFG.get("auto_register", False),
        help=(
            "Automatically register test accounts via detected registration forms "
            "and use them for privilege escalation testing."
        ),
    )
    scan.add_argument(
        "--auto-register-count", type=int, default=_CFG.get("auto_register_count", 2), metavar="N",
        help="Number of test accounts to auto-register (default: 2).",
    )
    # ①: SPA crawl
    scan.add_argument(
        "--spa-crawl", action="store_true",
        default=_CFG.get("spa_crawl", False),
        help=(
            "Enable SPA/dynamic content crawl: click interactive elements "
            "to discover routes rendered by React/Vue/Angular."
        ),
    )

    # Auto-config wizard
    _ac_default = _CFG.get("auto_config", False)
    _ac_group = scan.add_mutually_exclusive_group()
    _ac_group.add_argument(
        "--auto-config", action="store_true", default=_ac_default,
        help=(
            "Run the LLM-powered scan configuration wizard before scanning. "
            "Interviews you about the target and auto-generates optimal settings."
        ),
    )
    _ac_group.add_argument(
        "--no-auto-config", action="store_true", default=not _ac_default,
        help="Disable the auto-config wizard (default).",
    )

    # ── agent subcommand ───────────────────────────────────────────
    agent = sub.add_parser(
        "agent",
        help=(
            "Agent Browser Mode: LLM directly controls a real browser to autonomously "
            "discover and exploit vulnerabilities (requires browser-use)"
        ),
    )
    agent.add_argument("url", help="Target URL (e.g. https://example.com)")
    agent.add_argument(
        "--llm",
        choices=["claude", "openai", "ollama"],
        default=_CFG.get("llm_provider", "claude"),
        help=(
            "LLM provider that drives the browser agent "
            "(default: claude). Requires corresponding API key."
        ),
    )
    agent.add_argument(
        "--model", metavar="MODEL", default="",
        help=(
            "Model name (default: claude-sonnet-4-5-20250929 / gpt-4o-mini / llama3). "
            "Leave blank to use provider default."
        ),
    )
    agent.add_argument(
        "--ollama-url", metavar="URL",
        default=_CFG.get("ollama_url", "http://localhost:11434"),
        help=f"Ollama endpoint (default: {_CFG.get('ollama_url','http://localhost:11434')})",
    )
    _AGENT_CHECKS = [
        "xss", "sqli", "ssti", "os", "path_traversal",
        "ssrf", "open_redirect", "csrf", "header_injection",
    ]
    agent.add_argument(
        "--checks", nargs="+",
        choices=_AGENT_CHECKS,
        default=["xss", "sqli", "ssti", "os", "path_traversal", "ssrf"],
        metavar="CHECK",
        help=(
            "Vulnerability checks for the agent to test "
            "(default: xss sqli ssti os path_traversal ssrf). "
            "Available: " + ", ".join(_AGENT_CHECKS)
        ),
    )
    agent.add_argument(
        "--max-steps", type=int, default=100, metavar="N",
        help="Maximum agent steps before stopping (default: 100)",
    )
    agent.add_argument(
        "--headless", action="store_true", default=_CFG.get("headless", True),
        help="Run browser in headless mode (default: true)",
    )
    agent.add_argument(
        "--no-headless", action="store_true", default=False,
        help="Show browser window (disables headless)",
    )
    agent.add_argument(
        "--auth-user", metavar="USER", default=_CFG.get("auth_user", ""),
        help="Username for pre-scan login",
    )
    agent.add_argument(
        "--auth-pass", metavar="PASS", default=_CFG.get("auth_pass", ""),
        help="Password for pre-scan login",
    )
    agent.add_argument(
        "--login-url", metavar="URL", default=_CFG.get("login_url", ""),
        help="Login page URL (agent will log in before testing)",
    )
    agent.add_argument(
        "--output", "-o", metavar="DIR",
        default=_CFG.get("output_dir") or None,
        help="Output directory for report and evidence (default: output/agent_<timestamp>)",
    )
    agent.add_argument(
        "--port", type=int, default=_CFG.get("port", 8765),
        help=f"Monitoring dashboard port (default: {_CFG.get('port', 8765)})",
    )
    agent.add_argument(
        "--no-monitor", action="store_true", default=False,
        help="Disable the real-time monitoring dashboard",
    )
    agent.add_argument(
        "--no-open-report", action="store_true", default=False,
        help="Do not automatically open the HTML report after scanning",
    )

    # triage subcommand
    triage = sub.add_parser(
        "triage",
        help="Fast vulnerability assessment: crawl and analyse page structure without sending payloads",
    )
    triage.add_argument("url", help="Target URL")
    triage.add_argument(
        "--depth", "-d", type=int, default=_CFG.get("depth", 2), metavar="N",
        help=f"Crawl depth (default: {_CFG.get('depth', 2)})",
    )
    triage.add_argument(
        "--headless", action="store_true", default=True,
        help="Run browser in headless mode (default: true for triage)",
    )
    triage.add_argument(
        "--proxy", metavar="URL", default=_CFG.get("proxy", ""),
        help="HTTP proxy URL",
    )
    triage.add_argument(
        "--timeout", type=int, default=_CFG.get("timeout", 20), metavar="SECS",
        help=f"Page load timeout in seconds (default: {_CFG.get('timeout', 20)})",
    )
    triage.add_argument(
        "--llm", choices=["ollama", "claude", "openai", "gemini", "none"],
        default=_CFG.get("llm_provider", "none"),
        help="LLM provider for AI attack-strategy insights (default: none)",
    )
    triage.add_argument(
        "--ollama-model", default=_CFG.get("ollama_model", "llama3"), metavar="MODEL",
    )
    triage.add_argument(
        "--openai-model", default=_CFG.get("openai_model", "gpt-4o-mini"), metavar="MODEL",
    )
    triage.add_argument(
        "--gemini-model", default=_CFG.get("gemini_model", "gemini-2.0-flash"), metavar="MODEL",
    )
    triage.add_argument(
        "--output", "-o", metavar="FILE",
        help="Save triage report as JSON to this file path",
    )

    # ── serve subcommand (GUI-first: start dashboard, configure via browser) ──
    serve = sub.add_parser(
        "serve",
        help="Start the dashboard server only — configure and launch scans from the browser",
    )
    serve.add_argument(
        "--port", type=int, default=_CFG.get("port", 8765),
        help=f"Dashboard port (default: {_CFG.get('port', 8765)})",
    )

    # A-4: Natural language setup subcommand
    setup = sub.add_parser("setup", help="Interactively configure scan options via natural language")
    setup.add_argument("description", nargs="?", default="",
                       help="Natural language description of the target")
    setup.add_argument("--llm", choices=["ollama", "claude", "openai", "gemini", "none"],
                       default=_CFG.get("llm_provider", "ollama"))
    setup.add_argument("--ollama-model", default=_CFG.get("ollama_model", "llama3"), metavar="MODEL")
    setup.add_argument("--ollama-url", default=_CFG.get("ollama_url", "http://localhost:11434"), metavar="URL")

    return parser.parse_args()


def _load_cookie_file(path: str, console) -> list:
    """Load cookies from a JSON export file. Returns a list of cookie dicts."""
    if not path:
        return []
    try:
        raw = Path(path).read_text(encoding="utf-8").strip()
        data = json.loads(raw)
        if isinstance(data, list):
            return data
        # Some exporters wrap as {"cookies": [...]}
        if isinstance(data, dict):
            for key in ("cookies", "Cookie", "cookie"):
                if isinstance(data.get(key), list):
                    return data[key]
        console.print(f"[yellow]Warning: unexpected cookie file format in {path}[/yellow]")
        return []
    except Exception as ex:
        console.print(f"[yellow]Warning: could not load cookie file '{path}': {ex}[/yellow]")
        return []


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


async def run_agent(args):
    """Agent Browser Mode — LLM autonomously controls the browser to find vulnerabilities."""
    import uvicorn
    from rich.console import Console
    from rich.panel import Panel
    from wscan.monitor import MonitorServer
    from wscan.agent_engine import AgentEngine

    console = Console()

    headless = not getattr(args, "no_headless", False)

    model_display = args.model or "(default)"
    console.print(Panel.fit(
        f"[bold magenta]WScan — Agent Browser Mode[/bold magenta]\n"
        f"Target  : [yellow]{args.url}[/yellow]\n"
        f"LLM     : [blue]{args.llm}[/blue] / {model_display}\n"
        f"Checks  : [green]{', '.join(args.checks)}[/green]\n"
        f"Steps   : [dim]max {args.max_steps}[/dim]",
        border_style="magenta",
    ))

    if getattr(args, "no_monitor", False):
        monitor = MonitorServer(port=args.port)
        engine = AgentEngine(
            url=args.url,
            llm_provider=args.llm,
            llm_model=args.model or "",
            ollama_url=getattr(args, "ollama_url", "http://localhost:11434"),
            checks=args.checks,
            headless=headless,
            auth_user=getattr(args, "auth_user", "") or "",
            auth_pass=getattr(args, "auth_pass", "") or "",
            login_url=getattr(args, "login_url", "") or "",
            max_steps=args.max_steps,
            output_dir=args.output or None,
            open_report=not getattr(args, "no_open_report", False),
            monitor=monitor,
            port=args.port,
        )
        await engine.run()
        return

    # With monitoring dashboard
    monitor = MonitorServer(port=args.port)
    config = uvicorn.Config(
        app=monitor.app,
        host="0.0.0.0",
        port=args.port,
        log_level="error",
    )
    server = uvicorn.Server(config)

    async def run_agent_task():
        await asyncio.sleep(1.5)
        console.print(
            f"\n[cyan]Monitoring dashboard:[/cyan] "
            f"[underline]http://localhost:{args.port}[/underline]"
        )
        webbrowser.open(f"http://localhost:{args.port}")

        try:
            engine = AgentEngine(
                url=args.url,
                llm_provider=args.llm,
                llm_model=args.model or "",
                ollama_url=getattr(args, "ollama_url", "http://localhost:11434"),
                checks=args.checks,
                headless=headless,
                auth_user=getattr(args, "auth_user", "") or "",
                auth_pass=getattr(args, "auth_pass", "") or "",
                login_url=getattr(args, "login_url", "") or "",
                max_steps=args.max_steps,
                output_dir=args.output or None,
                open_report=not getattr(args, "no_open_report", False),
                monitor=monitor,
                port=args.port,
            )
            await engine.run()
            console.print("[dim]Dashboard is still running — press Ctrl+C to stop.[/dim]")
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            console.print(f"\n[red]Error: {exc}[/red]")
            raise
        finally:
            server.should_exit = True

    await asyncio.gather(server.serve(), run_agent_task())


async def run_scan(args):
    from rich.console import Console
    from rich.panel import Panel

    console = Console()

    # ── Fast mode preset ──────────────────────────────────────────────
    # Apply defaults only for options the user did NOT explicitly set.
    # Explicit CLI flags always win over the preset.
    if getattr(args, "fast", False):
        _DEPTH_DEFAULT    = 2
        _FORMS_DEFAULT    = 50
        _CONC_DEFAULT     = 1
        _CHECKS_DEFAULT   = ["sqli", "xss", "os"]  # defined in add_argument default
        _LLM_DEFAULT      = "ollama"
        if args.depth       == _DEPTH_DEFAULT:  args.depth       = 1
        if args.max_forms   == _FORMS_DEFAULT:  args.max_forms   = 3
        if args.concurrency == _CONC_DEFAULT:   args.concurrency = 2
        if args.checks      == _CHECKS_DEFAULT: args.checks      = ["sqli", "xss"]
        if args.llm         == _LLM_DEFAULT:    args.llm         = "none"
        if not args.headless:                   args.headless    = True
        if not getattr(args, "no_planner",        False): args.no_planner        = True
        if not getattr(args, "no_waf_detection",  False): args.no_waf_detection  = True
        if not getattr(args, "no_sitemap_crawl",  False): args.no_sitemap_crawl  = True
        if not getattr(args, "no_ai_analysis",    False): args.no_ai_analysis    = True
        if getattr(args, "max_payloads", 0) == 0:         args.max_payloads      = 12
        console.print(
            "[bold yellow]⚡ FAST MODE[/bold yellow] — "
            f"ペイロード上限 {args.max_payloads}、遅延 0、深さ {args.depth}"
        )

    checks_display = ', '.join(args.checks) if args.checks else "all IPA checks"
    planner_display = "off" if getattr(args, "no_planner", False) else "on (AI-driven)"
    concurrency_val = getattr(args, "concurrency", 1)
    concurrency_display = (
        f"[bold green]{concurrency_val} workers[/bold green]"
        if concurrency_val > 1
        else "[dim]serial[/dim]"
    )
    console.print(Panel.fit(
        f"[bold cyan]WScan - Web Security Scanner[/bold cyan]\n"
        f"Target   : [yellow]{args.url}[/yellow]\n"
        f"Checks   : [green]{checks_display}[/green]\n"
        f"Planner  : [cyan]{planner_display}[/cyan]\n"
        f"Depth    : [blue]{args.depth}[/blue]   "
        f"LLM: [blue]{args.llm}[/blue]   "
        f"Headless: [blue]{args.headless}[/blue]   "
        f"Workers: {concurrency_display}\n"
        + _llm_model_display(args),
        border_style="cyan",
    ))

    # ── Auto-config wizard (opt-in) ────────────────────────────────
    _run_auto_config = getattr(args, "auto_config", False) and not getattr(args, "no_auto_config", False)
    if _run_auto_config:
        from wscan.payload_gen import PayloadGenerator
        from wscan.auto_config import run_wizard, apply_to_args
        _pg = PayloadGenerator(
            provider=args.llm,
            ollama_model=getattr(args, "ollama_model", "llama3"),
            ollama_url=getattr(args, "ollama_url", "http://localhost:11434"),
            openai_model=getattr(args, "openai_model", "gpt-4o-mini"),
            gemini_model=getattr(args, "gemini_model", "gemini-2.0-flash"),
        )
        _wizard_result = await run_wizard(_pg)
        if _wizard_result is not None:
            apply_to_args(_wizard_result, args)
            # Rebuild checks display after wizard
            checks_display = ', '.join(args.checks) if args.checks else "all IPA checks"
            console.print(f"[cyan]Auto-config applied:[/cyan] checks=[green]{checks_display}[/green]  "
                          f"depth=[blue]{args.depth}[/blue]")

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

    # Build cookie list from --cookie-file (JSON export format)
    cookie_list: list = _load_cookie_file(getattr(args, "cookie_file", "") or "", console)
    if cookie_list:
        console.print(f"Auth cookies    : [green]{len(cookie_list)} cookie(s) loaded from file[/green]")

    # Build low-privilege cookie list from --low-priv-cookie-file
    low_priv_cookie_list: list = _load_cookie_file(
        getattr(args, "low_priv_cookie_file", "") or "", console
    )
    low_priv_cookies: str = getattr(args, "low_priv_cookies", "") or ""
    if low_priv_cookie_list:
        console.print(
            f"Low-priv cookies: [cyan]{len(low_priv_cookie_list)} cookie(s) loaded — "
            f"vertical privilege-escalation testing enabled[/cyan]"
        )
    elif low_priv_cookies:
        console.print(
            "[cyan]Low-priv cookies provided — "
            "vertical privilege-escalation testing enabled[/cyan]"
        )

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

    # Build checks list (add dom_xss if requested, allow wizard to have updated args.checks)
    checks_list = list(args.checks)
    if getattr(args, "dom_xss", False) and "dom_xss" not in checks_list:
        checks_list.append("dom_xss")

    # A: Build accounts list from --accounts or --accounts-file
    import yaml as _yaml
    _accounts_list: list = []
    _accounts_str = getattr(args, "accounts", "") or ""
    if _accounts_str:
        for pair in _accounts_str.split(","):
            pair = pair.strip()
            if ":" in pair:
                user, pw = pair.split(":", 1)
                _accounts_list.append({"username": user.strip(), "password": pw.strip(), "role": "user"})
    _accounts_file = getattr(args, "accounts_file", "") or ""
    if _accounts_file:
        try:
            with open(_accounts_file, encoding="utf-8") as _af:
                _af_data = _yaml.safe_load(_af) or {}
            _accounts_list.extend(_af_data.get("accounts", []))
        except Exception as _ex:
            console.print(f"[yellow]Warning: Could not read accounts file: {_ex}[/yellow]")
    if _accounts_list:
        console.print(
            f"Accounts        : [cyan]{len(_accounts_list)} account(s) loaded for "
            f"privilege escalation testing[/cyan]"
        )

    def _engine_kwargs(monitor_obj):
        return dict(
            url=args.url,
            monitor=monitor_obj,
            payloads_file=args.payloads,
            depth=args.depth,
            headless=args.headless,
            llm_provider=args.llm,
            ollama_model=args.ollama_model,
            openai_model=args.openai_model,
            gemini_model=args.gemini_model,
            checks=checks_list,
            output_dir=args.output,
            timeout=args.timeout,
            max_forms=args.max_forms,
            exclude_fields=exclude_fields,
            exclude_urls=exclude_urls,
            ctf_mode=getattr(args, "ctf", False),
            ctf_flag_pattern=getattr(args, "ctf_flag_format", "") or "",
            cookies=getattr(args, "cookie", "") or "",
            cookie_list=cookie_list,
            low_priv_cookies=low_priv_cookies,
            low_priv_cookie_list=low_priv_cookie_list,
            auth_user=getattr(args, "auth_user", "") or "",
            auth_pass=getattr(args, "auth_pass", "") or "",
            use_planner=not getattr(args, "no_planner", False),
            interactive_plan=getattr(args, "interactive_plan", False) or args.llm == "none",
            skip_registration=not getattr(args, "include_registration", False),
            open_report=not getattr(args, "no_open_report", False),
            proxy=getattr(args, "proxy", "") or "",
            login_url=getattr(args, "login_url", "") or "",
            login_user_field=getattr(args, "login_user_field", "username") or "username",
            login_pass_field=getattr(args, "login_pass_field", "password") or "password",
            login_success_indicator=getattr(args, "login_success", "") or "",
            learning_file=getattr(args, "learning_file", "") or "",
            # Feature on/off flags (from config or CLI)
            enable_ai_analysis=not getattr(args, "no_ai_analysis", False),
            enable_waf_detection=not getattr(args, "no_waf_detection", False),
            enable_payload_learning=not getattr(args, "no_payload_learning", False),
            enable_sitemap_crawl=not getattr(args, "no_sitemap_crawl", False),
            enable_llm_web_browsing=getattr(args, "llm_web_browsing", False),
            concurrency=getattr(args, "concurrency", 1),
            flows=getattr(args, "flows", None) or [],
            max_payloads=getattr(args, "max_payloads", 0),
            fast_mode=getattr(args, "fast", False),
            # A: Multi-account privilege escalation
            accounts=_accounts_list,
            auto_register=getattr(args, "auto_register", False),
            auto_register_count=getattr(args, "auto_register_count", 2),
            # ①: SPA crawl
            spa_crawl=getattr(args, "spa_crawl", False),
        )

    if args.no_monitor:
        # Simple mode - no web dashboard
        from wscan.engine import ScanEngine
        from wscan.monitor import MonitorServer

        monitor = MonitorServer(port=args.port)
        engine = ScanEngine(**_engine_kwargs(monitor))
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
            engine = ScanEngine(**_engine_kwargs(monitor))
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


async def run_serve(args):
    """
    GUI-first mode: start the dashboard server, show configuration form in
    the browser, then launch the scan engine once the user submits settings.
    """
    import uvicorn
    from rich.console import Console
    from rich.panel import Panel
    from wscan.monitor import MonitorServer
    from wscan.engine import ScanEngine

    console = Console()
    port = args.port

    console.print(Panel.fit(
        f"[bold cyan]WScan — Dashboard Mode[/bold cyan]\n"
        f"  Opening [underline]http://localhost:{port}[/underline]\n"
        "  Configure and start your scan from the browser.",
        border_style="cyan",
    ))

    monitor = MonitorServer(port=port)
    # /api/auto-config エンドポイント用に LLM 設定をキャッシュ
    _llm_section = _CFG.get("llm", {}) if isinstance(_CFG.get("llm"), dict) else {}
    monitor.llm_cfg = {
        "provider":     _CFG.get("llm_provider", _llm_section.get("provider", "none")),
        "ollama_model": _CFG.get("ollama_model", _llm_section.get("ollama_model", "llama3")),
        "ollama_url":   _CFG.get("ollama_url",   _llm_section.get("ollama_url", "http://localhost:11434")),
        "openai_model": _CFG.get("openai_model", _llm_section.get("openai_model", "gpt-4o-mini")),
        "gemini_model": _CFG.get("gemini_model", _llm_section.get("gemini_model", "gemini-2.0-flash")),
        "claude_model": _CFG.get("claude_model", _llm_section.get("claude_model", "claude-haiku-4-5-20251001")),
    }
    config = uvicorn.Config(app=monitor.app, host="0.0.0.0", port=port, log_level="error")
    server = uvicorn.Server(config)

    async def serve_task():
        await asyncio.sleep(1.2)
        webbrowser.open(f"http://localhost:{port}")
        # Tell dashboard to show the config form
        await monitor.emit_awaiting_config()
        # Wait for the user to submit config from the GUI
        await monitor.scan_request_event.wait()
        cfg = monitor.scan_request_data

        url = cfg.get("url", "").strip()
        if not url:
            console.print("[red]No target URL provided — aborting.[/red]")
            server.should_exit = True
            return

        checks = cfg.get("checks", ["sqli", "xss", "os"]) or ["sqli", "xss", "os"]
        # ダッシュボードで選択された LLM 設定を auto-config エンドポイント用にも反映
        if cfg.get("llm"):
            monitor.llm_cfg.update({
                "provider":     cfg.get("llm", "none"),
                "ollama_model": cfg.get("ollama_model", "llama3"),
                "ollama_url":   cfg.get("ollama_url", "http://localhost:11434"),
                "openai_model": cfg.get("openai_model", "gpt-4o-mini"),
                "gemini_model": cfg.get("gemini_model", "gemini-2.0-flash"),
                "claude_model": cfg.get("claude_model", "claude-haiku-4-5-20251001"),
            })
        await monitor.emit_scan_started(cfg)

        # ── Agent Browser mode ─────────────────────────────────────
        if cfg.get("agent_mode"):
            from wscan.agent_engine import AgentEngine
            await monitor.emit_status(f"Agent Browser: {url} をスキャン中", "running")
            try:
                agent_engine = AgentEngine(
                    url=url,
                    llm_provider=cfg.get("llm", "claude") or "claude",
                    llm_model=cfg.get("agent_model", "") or "",
                    ollama_url=cfg.get("agent_ollama_url", "http://localhost:11434") or "http://localhost:11434",
                    checks=checks,
                    headless=bool(cfg.get("headless", True)),
                    auth_user=cfg.get("auth_user", "") or "",
                    auth_pass=cfg.get("auth_pass", "") or "",
                    login_url=cfg.get("login_url", "") or "",
                    max_steps=int(cfg.get("agent_max_steps", 50)),
                    open_report=bool(cfg.get("open_report", True)),
                    monitor=monitor,
                    port=port,
                )
                await agent_engine.run()
                console.print("[dim]Dashboard still running — press Ctrl+C to stop.[/dim]")
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                console.print(f"\n[red]Agent Error: {exc}[/red]")
                raise
            finally:
                server.should_exit = True
            return

        # ── Hybrid Mode: Agent偵察 (Phase 1) → 通常スキャン (Phase 2) ────
        seed_urls: list = []
        if cfg.get("hybrid_mode"):
            from wscan.agent_engine import AgentEngine
            await monitor.emit_status("🔀 ハイブリッド Phase 1: Agent偵察中...", "running")
            try:
                recon_engine = AgentEngine(
                    url=url,
                    llm_provider=cfg.get("hybrid_llm", "claude") or "claude",
                    llm_model=cfg.get("hybrid_model", "") or "",
                    ollama_url=cfg.get("hybrid_ollama_url", "http://localhost:11434") or "http://localhost:11434",
                    checks=[],
                    headless=bool(cfg.get("headless", True)),
                    auth_user=cfg.get("auth_user", "") or "",
                    auth_pass=cfg.get("auth_pass", "") or "",
                    login_url=cfg.get("login_url", "") or "",
                    max_steps=int(cfg.get("hybrid_max_steps", 30)),
                    open_report=False,
                    monitor=monitor,
                    port=port,
                )
                handoff = await recon_engine.run_recon()
                seed_urls = handoff.discovered_urls
                await monitor.emit_status(
                    f"🔀 Phase 2: {len(seed_urls)} URL 発見済み。通常スキャン開始...", "running"
                )
            except Exception as exc:
                console.print(
                    f"[yellow]⚠ 偵察フェーズ失敗 ({exc})。"
                    f"URL シードなしで通常スキャンを続行します。[/yellow]"
                )
                seed_urls = []

        await monitor.emit_status(f"Starting scan of {url}", "running")

        try:
            engine = ScanEngine(
                url=url,
                monitor=monitor,
                depth=int(cfg.get("depth", 2)),
                timeout=int(cfg.get("timeout", 30)),
                max_forms=int(cfg.get("max_forms", 50)),
                headless=bool(cfg.get("headless", True)),
                concurrency=int(cfg.get("concurrency", 1)),
                checks=checks,
                llm_provider=cfg.get("llm", "none") or "none",
                ollama_model=cfg.get("ollama_model", "llama3") or "llama3",
                openai_model=cfg.get("openai_model", "gpt-4o-mini") or "gpt-4o-mini",
                gemini_model=cfg.get("gemini_model", "gemini-2.0-flash") or "gemini-2.0-flash",
                claude_model=cfg.get("claude_model", "claude-haiku-4-5-20251001") or "claude-haiku-4-5-20251001",
                auth_user=cfg.get("auth_user", "") or "",
                auth_pass=cfg.get("auth_pass", "") or "",
                cookies=cfg.get("cookies", "") or "",
                proxy=cfg.get("proxy", "") or "",
                login_url=cfg.get("login_url", "") or "",
                login_user_field=cfg.get("login_user_field", "username") or "username",
                login_pass_field=cfg.get("login_pass_field", "password") or "password",
                login_success_indicator=cfg.get("login_success_indicator", "") or "",
                payloads_file=cfg.get("payloads_file") or None,
                learning_file=cfg.get("learning_file") or None,
                output_dir=cfg.get("output_dir") or None,
                cookie_list=[],
                low_priv_cookies=cfg.get("low_priv_cookies", "") or "",
                low_priv_cookie_list=[],
                use_planner=bool(cfg.get("use_planner", True)),
                interactive_plan=bool(cfg.get("interactive_plan", False)),
                skip_registration=bool(cfg.get("skip_registration", True)),
                open_report=bool(cfg.get("open_report", True)),
                enable_ai_analysis=bool(cfg.get("enable_ai_analysis", True)),
                enable_waf_detection=bool(cfg.get("enable_waf_detection", True)),
                enable_payload_learning=bool(cfg.get("enable_payload_learning", True)),
                enable_sitemap_crawl=bool(cfg.get("enable_sitemap_crawl", True)),
                enable_llm_web_browsing=bool(cfg.get("enable_llm_web_browsing", False)),
                ctf_mode=bool(cfg.get("ctf_mode", False)),
                ctf_flag_pattern=cfg.get("ctf_flag_pattern", "") or "",
                exclude_fields=cfg.get("exclude_fields", []) or [],
                exclude_urls=cfg.get("exclude_urls", []) or [],
                flows=cfg.get("flows", []) or [],
                spa_crawl=bool(cfg.get("spa_crawl", False)),
                fast_mode=bool(cfg.get("fast_mode", False)),
                max_payloads=int(cfg.get("max_payloads", 0)),
                accounts=cfg.get("accounts", []) or [],
                auto_register=bool(cfg.get("auto_register", False)),
                auto_register_count=int(cfg.get("auto_register_count", 2)),
                seed_urls=seed_urls or None,
            )
            await engine.run()
            console.print(
                f"\n[bold green]Scan complete![/bold green]  "
                f"Report: [cyan]{engine.output_dir / 'report.html'}[/cyan]"
            )
            console.print("[dim]Dashboard still running — press Ctrl+C to stop.[/dim]")
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            console.print(f"\n[red]Error: {exc}[/red]")
            raise
        finally:
            server.should_exit = True

    await asyncio.gather(server.serve(), serve_task())


async def run_triage(args):
    """Triage mode — fast structural analysis without payload injection."""
    from rich.console import Console
    from rich.panel import Panel
    console = Console()

    console.print(Panel.fit(
        f"[bold cyan]WScan Triage Mode[/bold cyan]\n"
        f"Target  : [yellow]{args.url}[/yellow]\n"
        f"Depth   : [blue]{args.depth}[/blue]   "
        f"LLM: [blue]{args.llm}[/blue]\n"
        "[dim]No payloads will be sent — structural and header analysis only[/dim]",
        border_style="cyan",
    ))

    from wscan.triage import TriageEngine, render_triage_report

    engine = TriageEngine(
        url=args.url,
        depth=args.depth,
        headless=getattr(args, "headless", True),
        proxy=getattr(args, "proxy", "") or "",
        timeout=getattr(args, "timeout", 20),
        llm_provider=getattr(args, "llm", "none"),
        ollama_model=getattr(args, "ollama_model", "llama3"),
        openai_model=getattr(args, "openai_model", "gpt-4o-mini"),
        gemini_model=getattr(args, "gemini_model", "gemini-2.0-flash"),
    )

    report = await engine.run()
    render_triage_report(report, console)

    # Optional JSON output
    output_file = getattr(args, "output", None)
    if output_file:
        Path(output_file).write_text(
            __import__("json").dumps(report.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        console.print(f"\n[green]Triage report saved:[/green] {output_file}")


async def run_setup(args):
    """A-4: Natural language scan configuration assistant."""
    from rich.console import Console
    from rich.panel import Panel
    console = Console()

    console.print(Panel.fit(
        "[bold cyan]WScan Setup Assistant[/bold cyan]\n"
        "Describe your target and I'll suggest optimal scan options.",
        border_style="cyan",
    ))

    description = args.description
    if not description:
        try:
            description = input("Describe your target (e.g. 'EC site with login, admin panel, REST API'): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(0)

    if not description:
        print("No description provided.")
        sys.exit(1)

    prompt = (
        f"You are a web security scanner configuration assistant.\n"
        f"The user wants to scan this target: {description}\n\n"
        f"Available checks: sqli, xss, dom_xss, os, ssti, path_traversal, "
        f"csrf, header_injection, mail_header, open_redirect, clickjacking, session, privesc\n\n"
        f"Based on the description, suggest the optimal scan command. "
        f"Return a JSON object with these fields:\n"
        f"  checks: list of check names to enable\n"
        f"  depth: crawl depth (1-5)\n"
        f"  reason: brief explanation\n"
        f"  flags: additional CLI flags as a list of strings (e.g. ['--dom-xss', '--depth 3'])\n\n"
        f"Return ONLY valid JSON."
    )

    from wscan.payload_gen import PayloadGenerator
    pg = PayloadGenerator(
        provider=args.llm,
        ollama_model=args.ollama_model,
        ollama_url=getattr(args, "ollama_url", "http://localhost:11434"),
    )

    suggestion = None
    if await pg._check_llm_available():
        try:
            import re as _re
            raw = await pg._call_llm(prompt) or []
            # _call_llm returns list; for setup we need text → call backends directly
            # Fallback: use text-based call
        except Exception:
            pass

    # Simple heuristic fallback
    checks = ["sqli", "xss", "os"]
    depth = 2
    flags: list[str] = []
    desc_lower = description.lower()
    if "api" in desc_lower or "rest" in desc_lower or "graphql" in desc_lower:
        checks += ["header_injection"]
    if "admin" in desc_lower or "dashboard" in desc_lower:
        checks += ["privesc"]
        depth = 3
    if "login" in desc_lower or "auth" in desc_lower:
        checks += ["session", "csrf"]
    if "redirect" in desc_lower or "link" in desc_lower:
        checks += ["open_redirect"]
    if "template" in desc_lower or "render" in desc_lower:
        checks += ["ssti"]
    if "dom" in desc_lower or "spa" in desc_lower or "react" in desc_lower or "vue" in desc_lower:
        flags.append("--dom-xss")
    checks = list(dict.fromkeys(checks))  # dedup

    cmd = f"python main.py scan <URL> --checks {' '.join(checks)} --depth {depth}"
    if flags:
        cmd += " " + " ".join(flags)

    console.print(f"\n[bold]Suggested scan command:[/bold]")
    console.print(f"  [green]{cmd}[/green]")
    console.print(f"\n[dim]Checks selected: {', '.join(checks)}[/dim]")
    console.print(f"[dim]Crawl depth: {depth}[/dim]")


def main():
    args = parse_args()
    try:
        if args.command == "setup":
            asyncio.run(run_setup(args))
        elif args.command == "triage":
            asyncio.run(run_triage(args))
        elif args.command == "serve":
            asyncio.run(run_serve(args))
        elif args.command == "agent":
            asyncio.run(run_agent(args))
        else:
            asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)


if __name__ == "__main__":
    main()
