"""
WScan Scan Engine — 4-Phase Pipeline
=====================================
Phase 1: Crawl    — BFS crawl, collect page info. No payload injection.
Phase 2: Plan     — Build per-page attack plans (LLM or heuristic).
                    Cross-page XSS/stored-injection awareness.
                    User confirms before attack begins.
Phase 3: Attack   — Execute attacks guided by the plan.
  Phase 3a:         Standard payload sweep (default list + plan extras).
                    LLM adaptively re-ranks remaining pages on new findings.
  Phase 3b:         Adaptive AI round — after each field, LLM observes the
                    application's filtering behavior in the page HTML and
                    generates creative bypass payloads (encoding tricks,
                    WAF evasion, context-aware injection, polyglots).
  Phase 3c:         Chain detection — inject distinctive probes into content
                    fields, then check ALL pages for stored/second-order
                    execution (Stored XSS, HTML injection → XSS, SSTI chain).
  Phase 3d:         Multi-parameter simultaneous injection — fill all form
                    fields with their respective payloads at once to catch
                    cross-parameter interactions and WAF bypasses.
Phase 4: Report   — Save evidence JSON and generate HTML report.
"""
import asyncio
import datetime
import json
import re
import xml.etree.ElementTree as _ET
from collections import deque
from contextvars import ContextVar
from dataclasses import dataclass, field as dc_field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urljoin

# ---------------------------------------------------------------------------
# Per-worker browser context variable
# ---------------------------------------------------------------------------
# When concurrent scanning is enabled, each asyncio Task that handles a page
# sets this variable to its dedicated WorkerBrowser instance.  The engine's
# ``browser`` property reads it so that scanners transparently use the
# worker's isolated page without any code changes.
_CURRENT_WORKER: ContextVar = ContextVar("wscan_worker", default=None)

import yaml
from rich.console import Console
from rich.rule import Rule
from rich.table import Table
from rich import box as rbox

from .attack_planner import AttackPlanner, FieldAttackPlan, PageAttackPlan
from .adaptive_payload import AdaptivePayloadEngine
from .browser import BrowserManager
from .chain_scanner import ChainScanner, ChainFinding
from .ctf_flag_finder import FlagFinder
from .intervention import ScanController, AbortScan, SkipField, SkipPage
from .monitor import MonitorServer
from .payload_gen import PayloadGenerator
from .scanners.base import Finding
from .scanners.sqli import SQLiScanner, SQL_ERROR_PATTERNS
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
from .scanners.privesc import PrivEscScanner
from .scanners.dom_xss import DOMXSSScanner
from .scanners.stored_xss import StoredXSSScanner
from .scanners.cors import CORSScanner
from .scanners.info_disclosure import InfoDisclosureScanner
from .scanners.host_header import HostHeaderScanner
from .scanners.security_headers import SecurityHeadersScanner
from .scanners.nosql_injection import NoSQLInjectionScanner
from .scanners.deserialization import DeserializationScanner
from .scanners.request_smuggling import RequestSmugglingScanner
from .scanners.ssrf import SSRFScanner
from .waf_detector import WAFDetector
from .payload_learning import PayloadLearner
from .flow_runner import ScanFlow, FlowRunner

console = Console()

CONFIG_DIR = Path(__file__).parent.parent / "config"
OUTPUT_BASE = Path(__file__).parent.parent / "output"


# ---------------------------------------------------------------------------
# Registration page / form detection
# ---------------------------------------------------------------------------

# URL path patterns that strongly suggest a new-account registration page
_REGISTRATION_URL_RE = re.compile(
    r"/(register|signup|sign[_-]up|new[_-]?account|create[_-]?account|join|enroll"
    r"|account/new|user/new|users/new|member/new|members/new"
    r"|新規登録|会員登録|ユーザー登録|アカウント登録|メンバー登録)",
    re.IGNORECASE,
)

# Field name / id patterns that only appear in registration (confirm-password) forms
_REGISTRATION_FIELD_RE = re.compile(
    r"^(confirm[_-]?pass(word)?|pass(word)?[_-]?confirm"
    r"|pass(word)?[_-]?(2|two|again|repeat|retry|check|verify|verification)"
    r"|re[_-]?pass(word)?|re[_-]?enter[_-]?pass(word)?"
    r"|password_?confirmation|passwordConfirmation"
    r"|repeat_?password|new_?password_?confirm"
    r"|パスワード確認|確認用パスワード)$",
    re.IGNORECASE,
)

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
        exclude_urls: Optional[list] = None,
        ctf_mode: bool = False,
        ctf_flag_pattern: str = "",
        cookies: str = "",
        cookie_list: Optional[list] = None,
        low_priv_cookies: str = "",
        low_priv_cookie_list: Optional[list] = None,
        auth_user: str = "",
        auth_pass: str = "",
        use_planner: bool = True,
        interactive_plan: bool = False,
        skip_registration: bool = True,
        open_report: bool = True,
        proxy: str = "",
        login_url: str = "",
        login_user_field: str = "username",
        login_pass_field: str = "password",
        login_success_indicator: str = "",
        learning_file: Optional[str] = None,
        # Feature flags (from config/wscan.yaml via main.py)
        enable_ai_analysis: bool = True,
        enable_waf_detection: bool = True,
        enable_payload_learning: bool = True,
        enable_sitemap_crawl: bool = True,
        enable_llm_web_browsing: bool = False,
        # Concurrent scanning
        concurrency: int = 1,
        # Multi-step attack flows
        flows: Optional[list] = None,
        # Fast mode
        max_payloads: int = 0,   # 0 = no limit; fast mode default: 12
        fast_mode: bool = False,  # sets sleep_factor=0
    ):
        self.target_url = url.rstrip("/")
        self.monitor = monitor
        self.depth = depth
        self.checks = list(checks or ["sqli", "xss", "os"])
        self.timeout = timeout
        self.max_forms = max_forms
        self.ctf_mode = ctf_mode
        self.max_payloads = max_payloads
        self.fast_mode = fast_mode
        # sleep_factor: fast=0.0 (no delays), ctf=0.5, normal=1.0
        if fast_mode:
            self.sleep_factor = 0.0
        elif ctf_mode:
            self.sleep_factor = 0.5
        else:
            self.sleep_factor = 1.0
        self.cookies = cookies
        self.cookie_list: list = list(cookie_list or [])
        # Normalise low-privilege cookies: prefer list form when both are given
        self.low_priv_cookies: str = low_priv_cookies
        self.low_priv_cookie_list: list = list(low_priv_cookie_list or [])
        # Convert low_priv_cookie_list → cookie-string for httpx usage
        if self.low_priv_cookie_list and not self.low_priv_cookies:
            self.low_priv_cookies = "; ".join(
                f"{c['name']}={c['value']}"
                for c in self.low_priv_cookie_list
                if c.get("name") and c.get("value") is not None
            )
        self.use_planner = use_planner
        self.interactive_plan = interactive_plan
        self.skip_registration = skip_registration
        self.open_report = open_report
        self.proxy = proxy
        self.login_url = login_url
        self.login_user_field = login_user_field
        self.login_pass_field = login_pass_field
        self.login_success_indicator = login_success_indicator
        # Feature on/off
        self.enable_ai_analysis = enable_ai_analysis
        self.enable_waf_detection = enable_waf_detection
        self.enable_payload_learning = enable_payload_learning
        self.enable_sitemap_crawl = enable_sitemap_crawl
        self.enable_llm_web_browsing = enable_llm_web_browsing
        self.concurrency = max(1, concurrency)
        # Multi-step attack flows (list[ScanFlow])
        self.flows: list[ScanFlow] = ScanFlow.list_from_dicts(flows or [])
        if ctf_mode and "ssti" not in self.checks:
            self.checks.append("ssti")

        # CTF flag finder
        self.flag_finder: Optional[FlagFinder] = FlagFinder(ctf_flag_pattern) if ctf_mode else None
        self.ctf_found_flags: list = []   # [(flag_str, source_url)]

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
        self._browser = BrowserManager(
            headless=headless, timeout=timeout, monitor=monitor,
            auth_user=auth_user, auth_pass=auth_pass,
            proxy=proxy,
            sleep_factor=self.sleep_factor,
        )
        self._flow_runner = FlowRunner(self._browser)
        self.payload_gen = PayloadGenerator(
            provider=llm_provider,
            ollama_model=ollama_model,
            openai_model=openai_model,
            gemini_model=gemini_model,
            default_payloads=payloads_data,
            prompt_templates=prompt_templates,
            enable_web_browsing=enable_llm_web_browsing,
        )

        scanner_map = {
            "sqli":             SQLiScanner,
            "xss":              XSSScanner,
            "dom_xss":          DOMXSSScanner,
            "os":               OSInjectionScanner,
            "ssti":             SSTIScanner,
            "path_traversal":   PathTraversalScanner,
            "csrf":             CSRFScanner,
            "header_injection": HeaderInjectionScanner,
            "mail_header":      MailHeaderInjectionScanner,
            "open_redirect":    OpenRedirectScanner,
            "clickjacking":       ClickjackingScanner,
            "session":            SessionScanner,
            "privesc":            PrivEscScanner,
            "stored_xss":         StoredXSSScanner,
            "cors":               CORSScanner,
            "info_disclosure":    InfoDisclosureScanner,
            "host_header":        HostHeaderScanner,
            "security_headers":   SecurityHeadersScanner,
            "nosql":              NoSQLInjectionScanner,
            "deserialization":    DeserializationScanner,
            "request_smuggling":  RequestSmugglingScanner,
            "ssrf":               SSRFScanner,
        }
        self.scanners = {n: cls(self) for n, cls in scanner_map.items() if n in self.checks}

        # Always enable privilege-escalation scanner when auth cookies are provided,
        # even if the user didn't explicitly list "privesc" in --checks.
        if "privesc" not in self.scanners and (self.cookies or self.cookie_list or self.low_priv_cookies):
            self.scanners["privesc"] = PrivEscScanner(self)

        self.attack_planner = AttackPlanner(
            payload_gen=self.payload_gen,
            enabled_checks=self.checks,
        )

        self.exclude_fields: set = {f.lower() for f in (exclude_fields or [])}
        self.exclude_urls: set = set(exclude_urls or [])

        # A-2: WAF detection
        self.waf_detector = WAFDetector(payload_gen=self.payload_gen)
        # A-3: Payload continuous learning
        self.payload_learner = PayloadLearner(learning_file=learning_file)

        # Adaptive AI payload refinement — runs a second pass per field
        # using LLM analysis of the page's filtering behavior
        self.adaptive_engine = AdaptivePayloadEngine(self.payload_gen)
        self.adaptive_enabled = llm_provider != "none"

        # Chain / stored vulnerability scanner (Phase 3c)
        self.chain_scanner = ChainScanner(
            browser=self._browser,
            sleep_factor=self.sleep_factor,
            exclude_fields=self.exclude_fields,
            enabled_checks=self.checks,
        )

        # State
        self.all_findings: list = []
        self._finding_dedup: set[tuple] = set()     # (url, field_name, check_type) — prevent duplicates
        self.attack_plans: list = []
        self.visited_urls: set = set()
        self.scanned_forms: set = set()
        self._scanned_forms_lock = asyncio.Lock()   # guards scanned_forms in concurrent mode
        self.completed_fields: int = 0
        self.total_fields: int = 0
        # page_graph: {url: {"parent": parent_url|None, "screenshot_b64": str, "depth": int}}
        self.page_graph: dict = {}
        # Scan controller (intervention system)
        self.controller = ScanController()
        # SQLi auth-bypass signal: set by signal_auth_bypass() when a scanner detects bypass
        self.auth_bypass_detected: bool = False
        self.auth_bypass_login_url: str = ""
        self.auth_bypass_post_url: str = ""

    # =========================================================================
    # browser property — transparently returns the current worker's browser
    # =========================================================================

    @property
    def browser(self):
        """
        Returns the current concurrent worker's WorkerBrowser when called from
        inside a worker task, otherwise returns the main BrowserManager.
        This makes all scanners work correctly in both serial and concurrent modes
        without any changes to scanner code.
        """
        worker = _CURRENT_WORKER.get(None)
        return worker if worker is not None else self._browser

    # =========================================================================
    # Public entry point
    # =========================================================================

    async def run(self):
        """4-phase scan pipeline."""
        if self.monitor:
            await self.monitor.emit_status(f"Starting scan of {self.target_url}", "running")
            await self.monitor.emit_scan_config(
                url=self.target_url,
                checks=self.checks,
                depth=self.depth,
                concurrency=self.concurrency,
                timeout=self.timeout,
                fast_mode=self.fast_mode,
            )

        loop = asyncio.get_event_loop()
        self.controller.start(loop, monitor=self.monitor)

        # U-3: Start manual payload listener if monitor active
        if self.monitor:
            asyncio.run_coroutine_threadsafe(self._manual_payload_listener(), loop)

        try:
            await self._browser.init()
            if self.cookies:
                await self._browser.set_cookies(self.cookies, self.target_url)
            if self.cookie_list:
                await self._browser.set_cookies_from_list(self.cookie_list, self.target_url)

            # Auth-1: Auto-login if login URL provided
            if self.login_url and self._browser.auth_user and self._browser.auth_pass:
                console.print(
                    f"  [cyan][Auth] Auto-login:[/cyan] {self.login_url}"
                )
                success = await self._browser.auto_login(
                    self.login_url,
                    user_field=self.login_user_field,
                    pass_field=self.login_pass_field,
                    success_indicator=self.login_success_indicator,
                )
                if success:
                    console.print("  [green][Auth] Login successful — session cookies captured.[/green]")
                else:
                    console.print("  [yellow][Auth] Login may have failed — continuing anyway.[/yellow]")

            # A-2: Detect WAF before crawling (if enabled)
            if self.enable_waf_detection:
                waf_name = await self.waf_detector.detect(self.target_url, timeout=float(self.timeout))
                if waf_name:
                    console.print(f"  [bold yellow][WAF][/bold yellow] Detected: {waf_name}")
                    bypass_hints = self.waf_detector.get_bypass_hints(waf_name)
                    console.print(f"  [dim yellow]Bypass hints: {'; '.join(bypass_hints[:3])}[/dim yellow]")
                    if self.monitor:
                        await self.monitor.emit("waf_detected", {"waf": waf_name, "hints": bypass_hints})
                else:
                    console.print("  [dim]No WAF detected.[/dim]")
            else:
                console.print("  [dim]WAF detection disabled.[/dim]")

            # ── Phase 1: Crawl ───────────────────────────────────────────
            if self.monitor: await self.monitor.emit_phase("crawl")
            crawled_pages = await self._phase_crawl()

            # ── Phase 2: Plan ────────────────────────────────────────────
            if self.monitor: await self.monitor.emit_phase("plan")
            plans = await self._phase_plan(crawled_pages)

            # ── Phase 3: Attack ──────────────────────────────────────────
            if self.monitor: await self.monitor.emit_phase("attack")
            try:
                await self._phase_attack(crawled_pages, plans)
            except AbortScan:
                console.print(
                    "\n[bold red][Intervention] Scan aborted by operator.[/bold red] "
                    "Generating partial report …"
                )

            # ── Phase 3c: Post-Auth Crawl + Attack (if SQLi bypass detected) ──
            if self.auth_bypass_detected:
                console.print(
                    "\n[bold red][Auth Bypass][/bold red] "
                    "SQL injection bypass confirmed — "
                    "re-crawling and attacking authenticated surface …"
                )
                new_pages = await self._phase_crawl_postauth()
                if new_pages:
                    new_plans = await self._phase_plan(new_pages)
                    console.print(
                        Rule(
                            "[bold red] Post-Auth Attack [/bold red]",
                            style="red",
                        )
                    )
                    try:
                        await self._phase_attack(new_pages, new_plans)
                    except AbortScan:
                        pass
                else:
                    console.print(
                        "  [dim]No new pages discovered in post-auth crawl.[/dim]"
                    )

        except Exception as _run_exc:
            console.print(f"\n[bold red]Scan error:[/bold red] {_run_exc}")
            if self.monitor:
                await self.monitor.emit_status(f"Scan error: {_run_exc}", "error")
            raise

        finally:
            self.controller.stop()
            await self._browser.close()

            # ── Phase 4.5: Verification ──────────────────────────────────
            await self._phase_verify()

            # ── Phase 4: Report ──────────────────────────────────────────
            if self.monitor: await self.monitor.emit_phase("report")
            await self._phase_report_async()

            if self.monitor:
                await self.monitor.emit("scan_complete", {
                    "total_findings": len(self.all_findings),
                    "report_path": str(self.output_dir / "report.html"),
                })

    # =========================================================================
    # Phase 1: Crawl
    # =========================================================================

    async def _fetch_sitemap_urls(self) -> list[str]:
        """C-3: Fetch and parse sitemap.xml and robots.txt for additional seed URLs."""
        import httpx
        discovered: list[str] = []
        base = self.target_url.rstrip("/")

        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            # robots.txt
            try:
                r = await client.get(f"{base}/robots.txt")
                if r.status_code == 200:
                    for line in r.text.splitlines():
                        line = line.strip()
                        if line.lower().startswith("sitemap:"):
                            sitemap_url = line.split(":", 1)[1].strip()
                            discovered += await self._parse_sitemap(client, sitemap_url)
                        elif line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path and path != "/":
                                full = urljoin(base + "/", path.lstrip("/"))
                                discovered.append(full)
            except Exception:
                pass

            # sitemap.xml (try directly if not found via robots)
            try:
                r = await client.get(f"{base}/sitemap.xml")
                if r.status_code == 200:
                    discovered += self._extract_sitemap_locs(r.text)
            except Exception:
                pass

        # Filter to same domain
        base_parsed = urlparse(base)
        return [
            u for u in discovered
            if urlparse(u).netloc == base_parsed.netloc and u not in self.visited_urls
        ]

    async def _parse_sitemap(self, client, sitemap_url: str) -> list[str]:
        """Fetch and parse a sitemap URL (supports sitemap index)."""
        try:
            r = await client.get(sitemap_url, timeout=10.0)
            if r.status_code == 200:
                return self._extract_sitemap_locs(r.text)
        except Exception:
            pass
        return []

    def _extract_sitemap_locs(self, xml_text: str) -> list[str]:
        """Extract <loc> URLs from a sitemap XML string."""
        urls: list[str] = []
        try:
            root = _ET.fromstring(xml_text)
            ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
            for loc in root.iter():
                if loc.tag.endswith("}loc") or loc.tag == "loc":
                    text = (loc.text or "").strip()
                    if text.startswith("http"):
                        urls.append(text)
        except Exception:
            pass
        return urls

    async def _phase_crawl(self) -> list:
        """BFS crawl — navigate every reachable page, collect forms/HTML. No payloads."""
        console.print(Rule("[bold blue] Phase 1 / 4  ·  Crawl [/bold blue]", style="blue"))
        console.print(f"  Target: [cyan]{self.target_url}[/cyan]  depth={self.depth}\n")

        pages: list = []
        queue: deque = deque([(self.target_url, 0, None)])  # (url, depth, parent_url)
        self.visited_urls.add(self.target_url)

        # C-3: Seed crawl queue from sitemap.xml / robots.txt (if enabled)
        sitemap_urls = await self._fetch_sitemap_urls() if self.enable_sitemap_crawl else []
        if sitemap_urls:
            console.print(
                f"  [dim cyan][C-3] Sitemap/robots.txt:[/dim cyan] "
                f"{len(sitemap_urls)} additional URL(s) discovered"
            )
            for su in sitemap_urls[:30]:  # cap at 30 seed URLs
                if su not in self.visited_urls:
                    self.visited_urls.add(su)
                    queue.append((su, 0, self.target_url))  # depth=0: treat as root-level

        while queue:
            url, depth, parent_url = queue.popleft()

            # Skip excluded URLs (exact match or prefix match)
            if self._is_url_excluded(url):
                console.print(f"  [dim yellow]Skip (excluded URL):[/dim yellow] {url}")
                continue

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
            screenshot_b64 = await self.browser.screenshot_b64(f"Crawl: {url}")

            # Record in page_graph for the transition diagram
            self.page_graph[url] = {
                "parent": parent_url,
                "screenshot_b64": screenshot_b64,
                "depth": depth,
            }

            # CTF: scan page HTML for flags even during crawl
            if self.flag_finder:
                self._check_page_for_flags(html, url)

            # Count and flag registration forms during crawl (informational only;
            # actual skipping happens in _attack_page)
            reg_form_count = 0
            if self.skip_registration:
                reg_form_count = sum(
                    1 for f in forms
                    if self._is_registration_form(f)
                )
                if self._is_registration_url(url):
                    reg_form_count = len(forms)  # whole page will be skipped

            input_count = sum(len(f.get("inputs", [])) for f in forms) + len(url_params)
            reg_note = (
                f"  [dim yellow]({reg_form_count} registration form(s) will be skipped)[/dim yellow]"
                if reg_form_count else ""
            )
            console.print(
                f"    [dim]forms:[/dim] {len(forms)}  "
                f"[dim]url params:[/dim] {len(url_params)}  "
                f"[dim]inputs:[/dim] {input_count}"
                + (f"\n    {reg_note}" if reg_note else "")
            )

            pages.append(CrawledPage(url=url, html=html, forms=forms,
                                     url_params=url_params, depth=depth))

            if depth < self.depth:
                links = await self.browser.collect_links(url, same_domain=True)
                url_cap = max(200, self.depth * 50)
                _cap_warned = False
                for link in links:
                    clean = link.split("#")[0].split("?")[0]
                    if len(self.visited_urls) >= url_cap:
                        if not _cap_warned:
                            console.print(
                                f"  [yellow]Crawl URL cap ({url_cap}) reached — "
                                f"some pages may have been skipped.[/yellow]"
                            )
                            _cap_warned = True
                        break
                    if (clean not in self.visited_urls
                            and not self._is_url_excluded(clean)):
                        self.visited_urls.add(clean)
                        queue.append((link, depth + 1, url))

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
            if self.interactive_plan:
                # Manual planning mode: generate heuristic base plans so the user
                # has something to start from, then open the interactive editor.
                console.print(
                    "  [bold yellow]手動プラン作成モード[/bold yellow]  "
                    "(AIプランナー無効 — ヒューリスティック分析から開始)\n"
                )
                plans = self._generate_heuristic_plans_for_pages(pages)
                if plans:
                    self.attack_plans = list(plans.values())
                    self._print_all_plans(plans)
                    console.print()
                    if self.monitor:
                        # Dashboard mode: send plans to web UI for review
                        console.print(
                            "  [bold cyan][Web Dashboard][/bold cyan] "
                            "プラン確認モーダルが開きます。ダッシュボードで確認後に攻撃を開始してください。"
                        )
                        plans_data = self._serialize_plans(plans)
                        await self.monitor.emit_plan_review(plans_data)
                        edits = await self.monitor.wait_for_plan_confirm()
                        if edits:
                            self._apply_plan_edits(plans, edits)
                            console.print("  [dim]プラン編集が適用されました。[/dim]")
                    else:
                        # Terminal fallback: interactive CUI editor
                        self._interactive_plan_editor(plans)
                        console.print(
                            "[bold]  手動プランが完成しました。[/bold] "
                            "[green]Enter[/green] で攻撃開始、[red]Ctrl+C[/red] で中断。"
                        )
                        try:
                            await asyncio.get_event_loop().run_in_executor(None, input, "  → ")
                        except (KeyboardInterrupt, EOFError):
                            raise SystemExit("\nAborted by user.")
            else:
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

        pages_with_inputs = [p for p in pages if p.forms or p.url_params]
        pages_no_inputs   = [p for p in pages if not p.forms and not p.url_params]
        for p in pages_no_inputs:
            console.print(f"  [dim]No inputs on {p.url}, skipping[/dim]")

        async def _plan_one(page):
            console.print(f"  [dim cyan]Planning:[/dim cyan] {page.url}")
            plan = await self.attack_planner.analyze_page(
                url=page.url,
                page_html=page.html,
                forms=page.forms[:self.max_forms],
                url_params=page.url_params,
                site_map=site_map,
            )
            if self.monitor:
                await self.monitor.emit_status(f"Plan: {plan.page_purpose[:60]}")
            return page.url, plan

        results = await asyncio.gather(
            *[_plan_one(p) for p in pages_with_inputs],
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, Exception):
                console.print(f"  [yellow]Planning error: {r}[/yellow]")
                continue
            page_url, plan = r
            plans[page_url] = plan
            self.attack_plans.append(plan)

        # Print all plans summary (terminal log)
        if plans:
            self._print_all_plans(plans)

        # ── Confirm / edit plans ─────────────────────────────────────
        # When the web dashboard is active, send plans there and wait for
        # the operator to click "Start Attack" (edits are applied below).
        # Without a dashboard, fall back to the terminal interactive editor.
        if self.monitor and plans:
            console.print(
                "\n  [bold cyan][Web Dashboard][/bold cyan] "
                "プラン確認モーダルが開きます。ダッシュボードで確認・修正後に攻撃を開始してください。"
            )
            plans_data = self._serialize_plans(plans)
            await self.monitor.emit_plan_review(plans_data)
            edits = await self.monitor.wait_for_plan_confirm()
            if edits:
                self._apply_plan_edits(plans, edits)
                console.print("  [dim]プラン編集が適用されました。[/dim]")
        else:
            # Terminal fallback: show interactive editor then wait for Enter
            if plans:
                self._interactive_plan_editor(plans)
            console.print()
            console.print(
                "[bold]  Plans are ready.[/bold] "
                "Press [green]Enter[/green] to start the attack, or [red]Ctrl+C[/red] to abort."
            )
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
    # Plan serialisation / deserialisation (web dashboard ↔ engine)
    # =========================================================================

    def _serialize_plans(self, plans: dict) -> list:
        """Convert plans dict → JSON-serialisable list for the web dashboard."""
        result = []
        for url, plan in plans.items():
            fields = []
            for fp in plan.fields:
                fields.append({
                    "name": fp.name,
                    "risk_score": fp.risk_score,
                    "priority_checks": fp.priority_checks,
                    "rationale": fp.rationale or "",
                    "is_url_param": fp.is_url_param,
                    "form_index": fp.form_index,
                    "custom_payloads": fp.custom_payloads or {},
                    "skip": False,
                })
            result.append({
                "url": url,
                "page_purpose": plan.page_purpose,
                "planned_by": plan.planned_by,
                "fields": fields,
            })
        return result

    def _apply_plan_edits(self, plans: dict, edits: dict) -> None:
        """
        Apply edits from the web dashboard back into the plan objects.

        edits format:
          {url: {field_name: {risk_score, priority_checks, custom_payloads, skip}}}
        """
        for url, field_edits in edits.items():
            plan = plans.get(url)
            if not plan:
                continue
            for fp in plan.fields:
                fe = field_edits.get(fp.name)
                if not fe:
                    continue
                if "risk_score" in fe:
                    fp.risk_score = int(fe["risk_score"])
                if "priority_checks" in fe:
                    fp.priority_checks = list(fe["priority_checks"])
                if "custom_payloads" in fe:
                    fp.custom_payloads = dict(fe["custom_payloads"])
                if fe.get("skip"):
                    fp.risk_score = 0   # score=0 causes field to be skipped

    # =========================================================================
    # Interactive Plan Editor (terminal fallback)
    # =========================================================================

    def _interactive_plan_editor(self, plans: dict) -> None:
        """
        Per-field interactive attack plan editor.
        Runs after LLM/heuristic planning, before the attack phase.
        Lets the user review, adjust, or override every field's plan.
        """
        console.print(Rule("[bold yellow] 手動プラン編集モード [/bold yellow]", style="yellow"))
        console.print(
            "  各フィールドのリスク・検査項目・カスタムペイロードを設定できます。\n"
            "  [dim]操作: [Enter] 確定  [番号] フィールド編集  [s] ページスキップ  [a] 全ページ確定[/dim]"
        )

        page_list = list(plans.items())
        for page_idx, (url, plan) in enumerate(page_list):
            if not plan.fields:
                continue

            while True:
                console.print(f"\n  [bold cyan]ページ {page_idx + 1}/{len(page_list)}:[/bold cyan] {url}")
                console.print(f"  [dim]目的:[/dim] {plan.page_purpose}  [dim]計画:[/dim] {plan.planned_by}")
                self._print_editable_fields(plan)

                try:
                    raw = input(
                        "\n  操作 → [Enter]=確定  [番号]=編集  [s]=スキップ  [a]=全確定: "
                    ).strip().lower()
                except (KeyboardInterrupt, EOFError):
                    raise SystemExit("\nAborted.")

                if raw == "a":
                    console.print("  [green]全ページを確定しました。[/green]")
                    return
                if raw == "s":
                    for fp in plan.fields:
                        fp.priority_checks = []
                        fp.risk_score = 0
                    console.print(f"  [yellow]  ページをスキップします。[/yellow]")
                    break
                if raw == "":
                    break
                if raw.isdigit():
                    idx = int(raw) - 1
                    sorted_fields = plan.sorted_fields()
                    if 0 <= idx < len(sorted_fields):
                        self._edit_field(sorted_fields[idx])
                    else:
                        console.print(f"  [red]  1〜{len(sorted_fields)} の番号を入力してください。[/red]")

    def _print_editable_fields(self, plan) -> None:
        """Print a numbered table of fields for interactive editing."""
        t = Table(show_header=True, header_style="bold", box=rbox.SIMPLE, padding=(0, 1))
        t.add_column("#",         justify="right", style="dim", width=3)
        t.add_column("フィールド",  style="cyan",   no_wrap=True, max_width=20)
        t.add_column("種別",       style="dim",    width=8)
        t.add_column("Risk",       justify="center", width=5)
        t.add_column("検査項目",   style="green",  max_width=30)
        t.add_column("PL",         justify="right", style="dim", width=4)

        for i, fp in enumerate(plan.sorted_fields(), 1):
            if fp.risk_score == 0:
                risk_disp = "[dim]SKIP[/dim]"
            else:
                rc = "red" if fp.risk_score >= 8 else ("yellow" if fp.risk_score >= 5 else "green")
                risk_disp = f"[{rc}]{fp.risk_score}[/{rc}]"
            kind = "URL param" if fp.is_url_param else "form"
            pl_count = sum(len(v) for v in fp.custom_payloads.values()) if fp.custom_payloads else 0
            checks_str = " · ".join(fp.priority_checks[:4]) if fp.priority_checks else "[dim]—[/dim]"
            t.add_row(str(i), fp.name, kind, risk_disp, checks_str, str(pl_count) if pl_count else "-")
        console.print(t)

    def _edit_field(self, fp) -> None:
        """Interactive editor for a single FieldAttackPlan."""
        console.print(f"\n  [bold]編集中:[/bold] [cyan]{fp.name}[/cyan]"
                      f"  [dim](現在: risk={fp.risk_score}, checks={' '.join(fp.priority_checks)})[/dim]")

        # ── Risk score ───────────────────────────────────────────────
        try:
            r = input(f"  リスクスコア (1-10) [{fp.risk_score}]: ").strip()
        except (KeyboardInterrupt, EOFError):
            return
        if r.isdigit():
            fp.risk_score = max(1, min(10, int(r)))

        # ── Checks ───────────────────────────────────────────────────
        console.print("  実施する検査:")
        for i, c in enumerate(self.checks, 1):
            mark = "[green]●[/green]" if c in fp.priority_checks else "[dim]○[/dim]"
            console.print(f"    [{i:>2}] {mark} {c}")

        try:
            c_raw = input(
                f"  番号 (スペース区切り) / 'all' / 'none'  [現在: {' '.join(fp.priority_checks) or '—'}] [Enter=変更なし]: "
            ).strip().lower()
        except (KeyboardInterrupt, EOFError):
            c_raw = ""

        if c_raw == "all":
            fp.priority_checks = list(self.checks)
        elif c_raw == "none":
            fp.priority_checks = []
            fp.risk_score = 0
            console.print("  [yellow]  スキップに設定しました。[/yellow]")
            return
        elif c_raw:
            selected = []
            for token in c_raw.split():
                if token.isdigit() and 1 <= int(token) <= len(self.checks):
                    selected.append(self.checks[int(token) - 1])
                elif token in self.checks:
                    selected.append(token)
            if selected:
                fp.priority_checks = selected

        # ── Custom payloads ──────────────────────────────────────────
        try:
            add_pl = input("  カスタムペイロードを追加しますか? (y/N): ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            add_pl = ""

        if add_pl in ("y", "yes") and fp.priority_checks:
            # Choose check type
            console.print("  どの検査用ペイロードを追加しますか?")
            for i, c in enumerate(fp.priority_checks, 1):
                console.print(f"    [{i}] {c}")
            try:
                ct_raw = input(f"  番号 [{fp.priority_checks[0]}]: ").strip()
            except (KeyboardInterrupt, EOFError):
                ct_raw = ""
            check_type = fp.priority_checks[0]
            if ct_raw.isdigit() and 1 <= int(ct_raw) <= len(fp.priority_checks):
                check_type = fp.priority_checks[int(ct_raw) - 1]
            elif ct_raw in self.checks:
                check_type = ct_raw

            console.print(f"  [dim]{check_type} 用ペイロードを1行ずつ入力 (空行で終了)[/dim]")
            new_payloads: list = []
            while True:
                try:
                    p = input("    > ").strip()
                except (KeyboardInterrupt, EOFError):
                    break
                if not p:
                    break
                new_payloads.append(p)

            if new_payloads:
                existing = fp.custom_payloads.get(check_type, [])
                fp.custom_payloads[check_type] = existing + new_payloads
                console.print(f"  [green]  ✔ {len(new_payloads)} 件のペイロードを追加しました[/green]")

        # ── Summary ──────────────────────────────────────────────────
        pl_total = sum(len(v) for v in fp.custom_payloads.values())
        console.print(
            f"  [green]  ✔ 更新:[/green] risk={fp.risk_score}  "
            f"checks={' · '.join(fp.priority_checks) or '—'}  "
            f"custom_payloads={pl_total}件"
        )

    # =========================================================================
    # Phase 3: Attack
    # =========================================================================

    async def _phase_attack(self, pages: list, plans: dict):
        """
        Execute attacks guided by the plan.

        Serial mode (concurrency=1):  same sequential flow as before.
        Concurrent mode (concurrency>1): worker pool — each worker holds its
        own Playwright page (WorkerBrowser) and processes pages in parallel.
        Within a single page, fields are still tested sequentially so that
        form state is consistent.
        """
        console.print(Rule("[bold red] Phase 3 / 4  ·  Attack [/bold red]", style="red"))

        if self.concurrency > 1:
            console.print(
                f"  [bold cyan][Concurrent][/bold cyan] "
                f"{self.concurrency} parallel worker(s)"
            )
            await self._phase_attack_concurrent(pages, plans)
        else:
            await self._phase_attack_serial(pages, plans)

        # Phase 3c: chain / stored vulnerability detection (runs after ALL pages attacked)
        chain_findings = await self.chain_scanner.run(
            source_pages=[p for p in pages if p.forms],
            observation_pages=pages,
            attack_plans=plans,
            max_forms=self.max_forms,
        )
        for cf in chain_findings:
            self._record_finding(cf.finding, source=f"chain:{cf.source_url}→{cf.trigger_url}")

    # ── Serial attack (original flow) ─────────────────────────────────────

    async def _phase_attack_serial(self, pages: list, plans: dict):
        attacked_urls: set = set()

        for page in pages:
            try:
                await self.controller.checkpoint()
            except SkipPage:
                console.print(f"  [yellow][Intervention] Skipping page: {page.url}[/yellow]")
                continue

            attacked_urls.add(page.url)
            findings_before = len(self.all_findings)
            if self.monitor:
                await self.monitor.emit_url_start(page.url, len(pages))
            await self._attack_one_page(page, plans)
            if self.monitor:
                await self.monitor.emit_url_complete(page.url)

            new_findings = self.all_findings[findings_before:]
            if new_findings and self.use_planner:
                remaining = [p for p in pages if p.url not in attacked_urls]
                if remaining:
                    self._adaptive_rerank(new_findings, remaining, plans)

    # ── Concurrent attack ─────────────────────────────────────────────────

    async def _phase_attack_concurrent(self, pages: list, plans: dict):
        """
        Distribute pages across N WorkerBrowser instances.

        Concurrency model:
        - N worker coroutines run as asyncio Tasks (N = self.concurrency).
        - Each worker picks a page from the queue, sets _CURRENT_WORKER
          in its task-local ContextVar, runs _attack_one_page(), then
          returns the worker to the pool.
        - Since asyncio is cooperative (not preemptive) and each page-attack
          is a single sequential coroutine, there are no data races on
          per-worker browser state.
        - The shared findings list and scanned_forms set are guarded by
          asyncio Locks at yield points.
        """
        # Create (concurrency-1) additional worker pages; worker[0] = main page.
        extra_workers = []
        for i in range(self.concurrency - 1):
            try:
                w = await self._browser.create_worker()
                extra_workers.append(w)
                console.print(f"  [dim]Worker {i + 2} page created[/dim]")
            except Exception as e:
                console.print(f"  [yellow]Could not create worker {i + 2}: {e}[/yellow]")

        # Worker pool queue: None = use main browser, WorkerBrowser = use worker
        worker_pool: asyncio.Queue = asyncio.Queue()
        await worker_pool.put(None)          # slot 0 → main _browser
        for w in extra_workers:
            await worker_pool.put(w)

        page_queue: asyncio.Queue = asyncio.Queue()
        for p in pages:
            await page_queue.put(p)

        # Shared abort signal — any worker that catches AbortScan sets this
        # so that other workers stop starting new pages.
        _abort_event = asyncio.Event()
        tasks: list = []  # populated below; referenced inside worker_loop

        async def worker_loop():
            while True:
                if _abort_event.is_set():
                    return
                try:
                    page = page_queue.get_nowait()
                except asyncio.QueueEmpty:
                    return

                worker_browser = await worker_pool.get()
                token = _CURRENT_WORKER.set(worker_browser)
                skip_this_page = False
                try:
                    try:
                        await self.controller.checkpoint()
                    except SkipPage:
                        console.print(
                            f"  [yellow][Intervention] Skipping page: {page.url}[/yellow]"
                        )
                        skip_this_page = True
                    if not skip_this_page:
                        if self.monitor:
                            await self.monitor.emit_url_start(page.url, page_queue.qsize() + 1)
                        await self._attack_one_page(page, plans)
                        if self.monitor:
                            await self.monitor.emit_url_complete(page.url)
                except AbortScan:
                    _abort_event.set()
                    raise
                except Exception as exc:
                    console.print(f"  [yellow][Worker] Error on {page.url}: {exc}[/yellow]")
                finally:
                    _CURRENT_WORKER.reset(token)
                    await worker_pool.put(worker_browser)
                    page_queue.task_done()

        n_slots = 1 + len(extra_workers)
        tasks[:] = [asyncio.create_task(worker_loop()) for _ in range(n_slots)]
        try:
            # return_exceptions=True so one AbortScan doesn't cancel other tasks mid-page;
            # they will exit cleanly at the top-of-loop _abort_event check.
            results = await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            for w in extra_workers:
                await w.close()

        # Propagate AbortScan to the caller (_phase_attack → run)
        if _abort_event.is_set():
            raise AbortScan()

    # ── SQLi auth-bypass signal ───────────────────────────────────────────

    def signal_auth_bypass(self, login_url: str, payload: str, post_url: str) -> None:
        """
        Called by SQLiScanner when a payload successfully bypasses authentication.
        Records the bypass event and schedules a post-authentication re-crawl
        (executed after Phase 3 completes).
        """
        if not self.auth_bypass_detected:
            self.auth_bypass_detected = True
            self.auth_bypass_login_url = login_url
            self.auth_bypass_post_url = post_url
            console.print(
                f"\n  [bold red][SQLi Auth Bypass][/bold red] "
                f"Login bypassed at [cyan]{login_url}[/cyan] "
                f"with payload [yellow]{payload!r}[/yellow]\n"
                f"  Redirected to: [green]{post_url}[/green]\n"
                f"  → Post-authentication re-crawl scheduled for after Phase 3."
            )
            # Monitor notification is done lazily at async context (see _phase_crawl_postauth)

    # ── Post-authentication re-crawl ──────────────────────────────────────

    async def _phase_crawl_postauth(self) -> list:
        """
        Re-crawl the application with the authenticated session gained via SQL
        injection auth bypass.

        Key difference from the initial crawl: we re-visit ALL pages regardless of
        whether they were visited before authentication.  Pages that previously just
        returned the login redirect may now show actual authenticated content (forms,
        data) that must be scanned.

        Deduplication is only within this crawl pass (auth_visited), NOT against
        self.visited_urls.  A page whose content changed after authentication is
        treated as new and re-added to new_pages for attack.
        """
        console.print(Rule(
            "[bold red] Phase 3c  ·  Post-Auth Crawl (SQLi Bypass) [/bold red]",
            style="red"
        ))
        console.print(
            "  [bold red]Session obtained via SQL injection authentication bypass.[/bold red]\n"
            f"  Re-crawling authenticated surface from "
            f"[cyan]{self.target_url}[/cyan]  depth={self.depth}\n"
        )
        if self.monitor:
            await self.monitor.emit_status(
                "Post-auth crawl: re-crawling authenticated surface (SQLi bypass)", "running"
            )

        # Navigate to target URL with authenticated session to find the landing page
        # (e.g., target is /login but authenticated session redirects to /dashboard)
        await self._browser.navigate(self.target_url)
        landing_url = self._browser.page.url.rstrip("/")

        # If we landed on the login page, session may have expired — try to re-login
        if self._browser.is_on_login_page(self.login_url):
            console.print("  [yellow][Post-Auth] Session appears expired — re-authenticating …[/yellow]")
            if self.login_url and self._browser.auth_user:
                ok = await self._browser.auto_login(
                    self.login_url,
                    user_field=self.login_user_field,
                    pass_field=self.login_pass_field,
                    success_indicator=self.login_success_indicator,
                )
                if not ok:
                    console.print(
                        "  [red][Post-Auth] Re-authentication failed — cannot crawl authenticated surface.[/red]"
                    )
                    return []
                landing_url = self._browser.page.url.rstrip("/")

        new_pages: list = []
        # auth_visited: only prevents re-queueing within THIS crawl (not against pre-auth crawl)
        auth_visited: set = set()
        queue: deque = deque()

        for seed in {landing_url, self.target_url}:
            if seed and seed not in auth_visited:
                auth_visited.add(seed)
                queue.append((seed, 0, None))

        while queue:
            url, depth, parent_url = queue.popleft()

            if self._is_url_excluded(url):
                continue

            console.print(
                f"  [dim][Post-Auth][/dim] Crawling ({depth}/{self.depth}): {url}"
            )
            if self.monitor:
                await self.monitor.emit_page_start(url)

            success = await self._browser.navigate(url)
            if not success:
                console.print(f"  [yellow]  ✘ could not load[/yellow]")
                continue

            # Check actual URL after navigation (may redirect)
            actual_url = self._browser.page.url.rstrip("/")

            # If redirected to login, session expired mid-crawl
            if self._browser.is_on_login_page(self.login_url):
                console.print(
                    "  [yellow][Post-Auth] Redirected to login — session expired.[/yellow]"
                )
                break

            try:
                html = await self._browser.page.content()
            except Exception:
                html = ""

            forms = await self._browser.find_forms()
            url_params = await self._browser.get_url_params()
            screenshot_b64 = await self._browser.screenshot_b64(
                f"Post-Auth Crawl: {actual_url}"
            )

            was_known = url in self.visited_urls or actual_url in self.visited_urls

            self.page_graph[actual_url] = {
                "parent": parent_url,
                "screenshot_b64": screenshot_b64,
                "depth": depth,
            }
            # Mark as visited so the main scanner doesn't double-count
            self.visited_urls.add(actual_url)

            input_count = (
                sum(len(f.get("inputs", [])) for f in forms) + len(url_params)
            )
            label = "[dim](re-crawled with auth)[/dim]" if was_known else "[green][NEW][/green]"
            console.print(
                f"    {label} "
                f"forms: {len(forms)}  "
                f"url params: {len(url_params)}  "
                f"inputs: {input_count}"
            )

            # Always add to new_pages — authenticated content may differ completely
            # from what was seen pre-auth (login form vs real page content)
            new_pages.append(
                CrawledPage(url=actual_url, html=html, forms=forms,
                            url_params=url_params, depth=depth)
            )

            # If actual_url differs from queued url (redirect), also mark in auth_visited
            if actual_url != url.rstrip("/") and actual_url not in auth_visited:
                auth_visited.add(actual_url)

            # BFS: collect links from actual page
            if depth < self.depth:
                try:
                    links = await self._browser.collect_links(actual_url, same_domain=True)
                except Exception:
                    links = []
                url_cap = max(200, self.depth * 50)
                for link in links:
                    clean = link.split("#")[0].split("?")[0]
                    if len(auth_visited) >= url_cap:
                        break
                    if clean not in auth_visited and not self._is_url_excluded(clean):
                        auth_visited.add(clean)
                        queue.append((clean, depth + 1, actual_url))

        total_inputs = sum(
            sum(len(f.get("inputs", [])) for f in p.forms) + len(p.url_params)
            for p in new_pages
        )
        console.print(
            f"\n  [bold green]Post-Auth Crawl complete[/bold green]  "
            f"[cyan]{len(new_pages)}[/cyan] page(s) · "
            f"[cyan]{total_inputs}[/cyan] input(s) discovered\n"
        )
        return new_pages

    # ── Single-page attack (shared by serial and concurrent modes) ────────

    async def _ensure_authenticated(self) -> bool:
        """
        Detect session expiry (redirect to login page) and re-authenticate.
        Called before attacking each page.  Returns True if session is valid
        (or if no auto-login is configured).
        """
        br = self.browser  # context-aware: returns worker in concurrent mode
        if not self.login_url and not br.auth_user:
            return True
        if br.is_on_login_page(self.login_url):
            console.print(
                "  [yellow][Auth] Session expired — re-authenticating...[/yellow]"
            )
            if self.monitor:
                await self.monitor.emit_status("Session expired — re-authenticating", "running")
            success = await br.auto_login(
                self.login_url,
                user_field=self.login_user_field,
                pass_field=self.login_pass_field,
                success_indicator=self.login_success_indicator,
            )
            if success:
                console.print("  [green][Auth] Re-login successful.[/green]")
            else:
                console.print("  [yellow][Auth] Re-login may have failed — continuing.[/yellow]")
            return success
        return True

    async def _attack_one_page(self, page: CrawledPage, plans: dict):
        """
        Run all checks on a single crawled page.
        Uses ``self.browser`` which transparently returns the worker's browser
        when called from inside a concurrent worker task.
        """
        # ── Page-level checks (header inspection, clickjacking, session, etc.) ──
        for check_name, scanner in self.scanners.items():
            try:
                page_findings = await scanner.scan_page(page.url)
                for f in (page_findings or []):
                    self._record_finding(f, source="page-level")
            except Exception as e:
                console.print(f"  [yellow]Page-level ({check_name}): {e}[/yellow]")

        if not page.forms and not page.url_params:
            return

        # ── Run multi-step attack flows that target this page ─────────────
        matched_flow = None
        for flow in self.flows:
            if flow.steps:
                # The last step action=navigate|attack defines the target URL
                last_nav = next(
                    (s for s in reversed(flow.steps) if s.action == "navigate"),
                    None,
                )
                if last_nav and last_nav.url.rstrip("/") == page.url.rstrip("/"):
                    matched_flow = flow
                    break
        if matched_flow:
            console.print(
                f"\n  [cyan][Flow] Pre-attack flow:[/cyan] {matched_flow.name}"
            )
            # Use context-aware browser (worker in concurrent mode)
            await FlowRunner(self.browser).run(matched_flow)
            # After flow, current browser page should already be on target URL
        else:
            # ── Re-authenticate if session expired ───────────────────────
            await self._ensure_authenticated()
            # Navigate back to page for form interaction
            success = await self.browser.navigate(page.url)
            if not success:
                return

        # CTF: re-check page after navigating (dynamic content may differ from crawl)
        if self.flag_finder:
            try:
                attack_html = await self.browser.page.content()
                self._check_page_for_flags(attack_html, page.url)
            except Exception:
                pass

        console.print(f"\n  [bold]Attacking:[/bold] {page.url}")
        plan = plans.get(page.url)

        # Phase 3a + 3b: individual field scan + adaptive AI
        await self._attack_page(page, plan)

        # Phase 3d: multi-parameter simultaneous injection
        await self._phase_multi_param(page, plan)

    async def _attack_page(self, page: CrawledPage, plan: Optional[PageAttackPlan]):
        """Run all scanners on all fields of a single page."""
        all_forms = page.forms[:self.max_forms]

        # ── Registration form exclusion ───────────────────────────────
        if self.skip_registration:
            # Also skip the whole page if its URL looks like a registration page
            if self._is_registration_url(page.url):
                console.print(
                    f"  [dim yellow]Skip (registration page):[/dim yellow] {page.url}"
                )
                return
            forms = []
            for form in all_forms:
                if self._is_registration_form(form):
                    action_hint = urlparse(form.get("action", "")).path or page.url
                    console.print(
                        f"  [dim yellow]Skip (registration form):[/dim yellow] "
                        f"action={action_hint}"
                    )
                else:
                    forms.append(form)
        else:
            forms = all_forms

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
            # Guard scanned_forms with a lock so concurrent workers don't
            # both pick up the same field simultaneously.
            async with self._scanned_forms_lock:
                if key in self.scanned_forms:
                    continue
                self.scanned_forms.add(key)

            if field_name.lower() in self.exclude_fields:
                console.print(f"  [dim]Skip excluded: {field_name}[/dim]")
                continue

            # Intervention checkpoint — allows skip-field / skip-page / abort
            try:
                await self.controller.checkpoint()
            except SkipField:
                console.print(f"  [yellow][Intervention] Skipping field: {field_name}[/yellow]")
                continue
            except SkipPage:
                console.print(f"  [yellow][Intervention] Skipping rest of page: {page.url}[/yellow]")
                return
            # AbortScan propagates up

            field_plan = plan.get_field_plan(field_name, fi, is_url_param) if plan else None
            try:
                await self._scan_field(page.url, fi, field, is_url_param, field_plan)
            except (AbortScan, SkipPage):
                raise
            except Exception as e:
                console.print(f"  [dim red]Field scan error ({field_name}): {e}[/dim red]")
                continue

            if not is_url_param:
                await self.browser.navigate(page.url)

    # =========================================================================
    # Phase 3d: Multi-parameter simultaneous injection
    # =========================================================================

    async def _phase_multi_param(self, page: CrawledPage, plan: Optional[PageAttackPlan]):
        """
        Fill ALL relevant fields in each form simultaneously with their
        respective check-type payloads and test the combined submission.

        Catches:
        - Cross-parameter WAF bypasses (each field clean alone, dangerous together)
        - Vulnerabilities that need valid companion field values to trigger
        - Concatenated rendering (multiple fields appear together on another page)
        """
        if not page.forms:
            return

        # Only run when there are forms with 2+ testable fields
        forms_to_test = [
            (fi, form) for fi, form in enumerate(page.forms[:self.max_forms])
            if len([
                inp for inp in form.get("inputs", [])
                if inp.get("name", "").lower() not in self.exclude_fields
            ]) >= 2
        ]
        if not forms_to_test:
            return

        console.print(
            f"\n  [bold magenta][MultiParam][/bold magenta] "
            f"Multi-parameter attack on {page.url}  "
            f"({len(forms_to_test)} form(s) with 2+ fields)"
        )

        xss_scanner = self.scanners.get("xss")
        sqli_scanner = self.scanners.get("sqli")

        for fi, form in forms_to_test:
            inputs = [
                inp for inp in form.get("inputs", [])
                if inp.get("name", "").lower() not in self.exclude_fields
            ]

            # Build a per-field payload map for each relevant check type
            for check_name in [c for c in ("xss", "sqli", "ssti") if c in self.scanners]:
                field_payloads: dict = {}

                for inp in inputs:
                    fname = inp.get("name", "")
                    if not fname:
                        continue

                    fp = plan.get_field_plan(fname, fi, False) if plan else None
                    # Use check if: explicitly planned OR field name heuristically relevant
                    if fp and fp.priority_checks and check_name not in fp.priority_checks:
                        continue

                    plan_payloads = (fp.custom_payloads.get(check_name) if fp else None) or []
                    defaults = self.payload_gen.default_payloads.get(check_name, [])
                    candidates = plan_payloads + [p for p in defaults if p not in plan_payloads]
                    if candidates:
                        field_payloads[fname] = candidates[0]  # pick first/best payload

                if len(field_payloads) < 2:
                    continue  # skip if only 1 field would be filled — that's already tested

                console.print(
                    f"  [dim magenta]  {check_name.upper()} × "
                    f"{len(field_payloads)} fields: "
                    f"{', '.join(field_payloads)}[/dim magenta]"
                )

                ok = await self.browser.navigate(page.url)
                if not ok:
                    continue
                self.browser.reset_dialog()

                source, pair = await self.browser.fill_and_submit_form_multi(fi, field_payloads)
                await asyncio.sleep(0.5 * self.sleep_factor)

                # CTF flag check on combined result
                if self.flag_finder and source:
                    self._check_page_for_flags(source, page.url)

                # ── XSS detection ──────────────────────────────────────
                if check_name == "xss" and xss_scanner:
                    if self.browser.dialog_fired:
                        f = await xss_scanner.record_finding(
                            url=page.url,
                            field_name=f"multi[{','.join(field_payloads)}]",
                            payload=str(field_payloads),
                            evidence=(
                                f"[MultiParam] XSS dialog triggered with simultaneous "
                                f"multi-field injection: '{self.browser.dialog_message}'"
                            ),
                            pair=pair,
                            severity="critical",
                            dialog_confirmed=True,
                            dialog_message=self.browser.dialog_message,
                        )
                        self._record_finding(f, source="multi-param")
                    elif source:
                        for fname, p in field_payloads.items():
                            reflected = xss_scanner._check_reflected(source, p)
                            if reflected:
                                f = await xss_scanner.record_finding(
                                    url=page.url,
                                    field_name=f"multi[{','.join(field_payloads)}]",
                                    payload=str(field_payloads),
                                    evidence=(
                                        f"[MultiParam] XSS reflected in combined submission "
                                        f"(field '{fname}'): '{reflected[:80]}'"
                                    ),
                                    pair=pair,
                                    severity="high",
                                )
                                self._record_finding(f, source="multi-param")
                                break

                # ── SQLi detection ─────────────────────────────────────
                elif check_name == "sqli" and sqli_scanner and source:
                    sqli_patterns = [
                        r"SQL syntax.*MySQL", r"Warning.*mysql_",
                        r"PostgreSQL.*ERROR", r"ORA-\d{5}",
                        r"SQLite.*Exception", r"ODBC.*Driver",
                        r"Microsoft.*ODBC.*SQL Server",
                        r"syntax error.*sqlite",
                        r"Unclosed quotation mark",
                    ]
                    matched = sqli_scanner.check_response_for_patterns(source, sqli_patterns)
                    if matched:
                        f = await sqli_scanner.record_finding(
                            url=page.url,
                            field_name=f"multi[{','.join(field_payloads)}]",
                            payload=str(field_payloads),
                            evidence=(
                                f"[MultiParam] SQLi error in combined submission: "
                                f"'{matched[:120]}'"
                            ),
                            pair=pair,
                            severity="high",
                        )
                        self._record_finding(f, source="multi-param")

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

            # Early exit: if a critical finding was already confirmed for this field,
            # skip remaining checks — critical is the highest severity so further
            # testing would only duplicate evidence.
            if any(
                f.severity == "critical" and f.field_name == field_name and f.url == url
                for f in self.all_findings
            ):
                break

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

        # CTF: check page source after all scanners ran on this field
        if self.flag_finder:
            try:
                post_html = await self.browser.page.content()
                self._check_page_for_flags(post_html, url)
            except Exception:
                pass

        # ── Adaptive AI round ────────────────────────────────────────────
        # Skip if LLM disabled, or a critical/high finding already confirmed
        field_findings = [f for f in self.all_findings if f.field_name == field_name and f.url == url]
        already_critical = any(f.severity in ("critical",) for f in field_findings)

        if self.adaptive_enabled and not already_critical:
            await self._adaptive_attack_field(
                url, form_index, field, is_url_param, ordered_checks, field_plan
            )

        self.completed_fields += 1
        if self.monitor and self.total_fields > 0:
            await self.monitor.emit_progress(
                current=self.completed_fields,
                total=self.total_fields,
                message=f"{field_name} ({url})",
            )

    async def _adaptive_attack_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool,
        check_names: list,
        field_plan: Optional[FieldAttackPlan],
    ):
        """
        Phase 3b: Adaptive AI round.
        For each check type, get current page HTML, ask LLM to generate
        context-aware bypass payloads, then run the scanner again with those payloads.
        """
        field_name = field.get("name", "unknown")

        # Get current page HTML as probe context
        try:
            page_html = await self.browser.page.content()
        except Exception:
            return

        for check_name in check_names:
            scanner = self.scanners.get(check_name)
            if scanner is None:
                continue

            # Don't bother adaptive pass on page-level-only scanners
            if check_name in ("csrf", "session", "clickjacking"):
                continue

            # Standard payloads that were tried in the first pass
            plan_payloads = field_plan.custom_payloads.get(check_name, []) if field_plan else []
            defaults = self.payload_gen.default_payloads.get(check_name, [])
            tried = plan_payloads + [p for p in defaults if p not in plan_payloads]

            # Ask LLM for bypass payloads (include detected WAF for targeted evasion)
            adaptive_payloads = await self.adaptive_engine.generate(
                check_type=check_name,
                field_name=field_name,
                url=url,
                payloads_tried=tried,
                page_html=page_html,
                waf_name=self.waf_detector._detected,
            )

            if not adaptive_payloads:
                continue

            # Run scanner again with adaptive payloads
            _prev = self.custom_payloads.get(check_name)
            self.custom_payloads[check_name] = adaptive_payloads

            try:
                findings = await scanner.scan_field(url, form_index, field, is_url_param)
                for f in (findings or []):
                    # Tag adaptive findings so they're identifiable
                    f.evidence = f"[AdaptiveAI] {f.evidence}"
                    self._record_finding(f, source=f"{field_name}[adaptive]")

                # Stop adaptive passes for this field if critical hit confirmed
                if any(f.severity == "critical" for f in (findings or [])):
                    self.custom_payloads[check_name] = _prev if _prev is not None else self.custom_payloads.pop(check_name, None)
                    break
            except Exception as e:
                console.print(f"    [yellow]Adaptive scanner error ({check_name}): {e}[/yellow]")
            finally:
                if _prev is None:
                    self.custom_payloads.pop(check_name, None)
                else:
                    self.custom_payloads[check_name] = _prev

            # CTF: scan page again after adaptive probe
            if self.flag_finder:
                try:
                    post_html = await self.browser.page.content()
                    self._check_page_for_flags(post_html, url)
                except Exception:
                    pass

    def _generate_heuristic_plans_for_pages(self, pages: list) -> dict:
        """
        Generate heuristic attack plans for all pages without calling the LLM.
        Used as a starting point for manual (interactive) plan editing.
        """
        plans: dict = {}
        for page in pages:
            if not page.forms and not page.url_params:
                continue
            plan = self.attack_planner._heuristic_plan(
                url=page.url,
                forms=page.forms[:self.max_forms],
                url_params=page.url_params,
            )
            plans[page.url] = plan
            console.print(
                f"  [dim cyan][HeuristicPlan][/dim cyan] {page.url}  "
                f"→ {len(plan.fields)} field(s)"
            )
        return plans

    def _is_url_excluded(self, url: str) -> bool:
        """Return True if *url* matches any entry in the exclude_urls set.
        Supports exact match or prefix match (e.g. 'http://host/admin' excludes all /admin/* URLs).
        """
        for pattern in self.exclude_urls:
            if url == pattern or url.startswith(pattern):
                return True
        return False

    def _is_registration_url(self, url: str) -> bool:
        """Return True if the URL path looks like a new-account registration page."""
        return bool(_REGISTRATION_URL_RE.search(urlparse(url).path))

    def _is_registration_form(self, form: dict) -> bool:
        """
        Return True if this form appears to be a signup / account-creation form.
        Detection signals (any one is sufficient):
          1. A field name / id matches the confirm-password pattern.
          2. The form action URL matches the registration URL pattern.
        """
        # Signal 1: confirm-password field present
        for inp in form.get("inputs", []):
            name = inp.get("name", "") or inp.get("id", "")
            if name and _REGISTRATION_FIELD_RE.match(name):
                return True
        # Signal 2: form action points to a registration endpoint
        action = form.get("action", "")
        if action and _REGISTRATION_URL_RE.search(urlparse(action).path):
            return True
        return False

    def _check_page_for_flags(self, text: str, source: str = ""):
        """Search text for CTF flags; print a banner and store any new finds."""
        if not self.flag_finder or not text:
            return
        found = self.flag_finder.find(text)
        for flag in found:
            if flag not in [f for f, _ in self.ctf_found_flags]:
                self.ctf_found_flags.append((flag, source))
                console.print()
                console.print(
                    f"  [bold white on red]  🚩 FLAG FOUND  [/bold white on red]"
                )
                console.print(
                    f"  [bold yellow]{flag}[/bold yellow]"
                    f"  [dim](source: {source})[/dim]"
                )
                console.print()

    def _record_finding(self, f: Finding, source: str = ""):
        dedup_key = (f.url, f.field_name, f.check_type)
        if dedup_key in self._finding_dedup:
            return   # duplicate — skip
        self._finding_dedup.add(dedup_key)
        self.all_findings.append(f)
        label = f.check_type.upper()
        loc = f" on [yellow]{source}[/yellow]" if source else ""
        console.print(
            f"    [bold red][FINDING][/bold red] {label}{loc} — {f.evidence[:80]}"
        )
        # A-3: record successful payload (if learning enabled)
        if f.payload and self.enable_payload_learning:
            self.payload_learner.record(f.check_type, f.payload, success=True)
        # Also scan the finding's evidence and response for flags
        if self.flag_finder:
            self._check_page_for_flags(f.evidence, f.url)
            body = (f.response or {}).get("body", "") or ""
            if body:
                self._check_page_for_flags(body, f.url)
            if f.dialog_message:
                self._check_page_for_flags(f.dialog_message, f.url)

    # =========================================================================
    # Phase 4.5: Verification — re-test each finding to catch false positives
    # =========================================================================

    _VERIFIABLE_CHECKS = frozenset({"xss", "sqli", "os", "ssti", "path_traversal"})

    async def _phase_verify(self):
        """
        Re-inject each finding's exact payload to confirm the vulnerability
        is reproducible.  Findings that cannot be reproduced are marked
        verified=False (kept in report with a ⚠ badge, not deleted).
        """
        from urllib.parse import parse_qs, urlparse

        to_verify = [
            f for f in self.all_findings
            if f.check_type in self._VERIFIABLE_CHECKS and not f.dialog_confirmed
        ]
        if not to_verify:
            return

        console.print(
            Rule(
                f"[bold blue] Phase 4.5  ·  Verification ({len(to_verify)} finding(s)) [/bold blue]",
                style="blue",
            )
        )
        if self.monitor:
            await self.monitor.emit_status(
                f"Verification: re-testing {len(to_verify)} finding(s)", "running"
            )

        for i, finding in enumerate(to_verify):
            confirmed = await self._verify_one(finding)
            if confirmed:
                console.print(
                    f"  [green][CONFIRMED][/green] {finding.check_type.upper()} "
                    f"on [yellow]{finding.field_name}[/yellow]: reproduced"
                )
            else:
                finding.verified = False
                finding.verification_note = "2回目の試行で再現できませんでした (possible false positive)"
                console.print(
                    f"  [yellow][UNCONFIRMED][/yellow] {finding.check_type.upper()} "
                    f"on [yellow]{finding.field_name}[/yellow]: not reproduced"
                )
            if self.monitor:
                await self.monitor.emit_progress(
                    current=i + 1,
                    total=len(to_verify),
                    message=f"検証 {i+1}/{len(to_verify)}: {finding.check_type}/{finding.field_name}",
                )

    async def _verify_one(self, f: Finding) -> bool:
        """
        Re-inject f.payload into f.field_name on f.url and check if the
        vulnerability is still reproducible.  Returns True if confirmed,
        True if verification could not be performed (don't penalise for nav errors).
        """
        from urllib.parse import parse_qs, urlparse
        import re as _re

        scanner = self.scanners.get(f.check_type)
        if scanner is None:
            return True  # no scanner available → assume confirmed

        # Determine URL-param vs form-field injection context
        is_url_param = f.field_name in parse_qs(
            urlparse(f.url).query, keep_blank_values=True
        )

        try:
            await self.browser.navigate(f.url)
            self.browser.reset_dialog()
            source, pair = await scanner._apply_payload(
                f.url, 0, f.field_name, f.payload, is_url_param
            )
            await asyncio.sleep(0.5 * self.sleep_factor)

            if f.check_type == "xss":
                return self.browser.dialog_fired or bool(
                    source and scanner._check_reflected(source, f.payload)
                )

            elif f.check_type == "sqli":
                body = pair.get("response", {}).get("body", "") or source or ""
                return bool(scanner.check_response_for_patterns(body, SQL_ERROR_PATTERNS))

            elif f.check_type == "os":
                OS_OUT_PATTERNS = [r"root:x:", r"uid=\d+\(", r"volume serial", r"directory of"]
                return any(
                    _re.search(p, source or "", _re.IGNORECASE)
                    for p in OS_OUT_PATTERNS
                )

            elif f.check_type == "ssti":
                return "49" in (source or "") or "7777777" in (source or "")

            else:
                return True  # path_traversal etc. — difficult to re-check, assume confirmed

        except Exception:
            return True  # navigation/injection failure → assume confirmed

    # =========================================================================
    # Phase 4: Report
    # =========================================================================

    def _phase_report(self):
        console.print(Rule("[bold green] Phase 4 / 4  ·  Report [/bold green]", style="green"))
        self._save_evidence()
        self._generate_report()
        self._print_summary()
        # A-3: Save payload learning data (if enabled)
        if self.enable_payload_learning:
            try:
                self.payload_learner.save()
            except Exception:
                pass

    async def _phase_report_async(self):
        """Async wrapper for report phase — runs A-1 AI analysis after report."""
        self._phase_report()
        # A-1: post-scan AI analysis (if enabled)
        if self.enable_ai_analysis:
            ai_text = await self._ai_analysis_report()
            if ai_text and self.monitor:
                await self.monitor.emit("ai_analysis", {"text": ai_text})

    def _save_evidence(self):
        evidence = {
            "target": self.target_url,
            "scan_date": datetime.datetime.now().isoformat(),
            "checks": self.checks,
            "visited_urls": list(self.visited_urls),
            "findings": [f.to_dict() for f in self.all_findings],
            "ctf_flags": [{"flag": flag, "source": src} for flag, src in self.ctf_found_flags],
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
        import webbrowser
        from .report import ReportGenerator
        gen = ReportGenerator(self.output_dir)
        report_path = gen.generate(
            target=self.target_url,
            findings=self.all_findings,
            visited_urls=list(self.visited_urls),
            checks=self.checks,
            attack_plans=self.attack_plans,
            ctf_flags=self.ctf_found_flags,
            page_graph=self.page_graph,
        )
        if self.open_report:
            try:
                webbrowser.open(report_path.as_uri())
            except Exception:
                pass

    async def _manual_payload_listener(self) -> None:
        """U-3: Background coroutine — executes manual payloads requested from dashboard."""
        if not self.monitor:
            return
        while self.controller._active:
            try:
                msg = await asyncio.wait_for(
                    self.monitor.manual_payload_queue.get(), timeout=0.3
                )
            except asyncio.TimeoutError:
                continue
            except Exception:
                break
            url        = msg.get("url", "")
            field_name = msg.get("field", "")
            payload    = msg.get("payload", "")
            check_type = msg.get("check_type", "xss")
            if not url or not field_name or not payload:
                continue
            console.print(
                f"  [bold cyan][U-3 Manual][/bold cyan] "
                f"{check_type.upper()} payload on {field_name} @ {url}"
            )
            try:
                scanner = self.scanners.get(check_type)
                if scanner:
                    field = {"name": field_name, "type": "text"}
                    prev = self.custom_payloads.get(check_type)
                    self.custom_payloads[check_type] = [payload]
                    findings = await scanner.scan_field(url, 0, field, is_url_param=False)
                    if prev is None:
                        self.custom_payloads.pop(check_type, None)
                    else:
                        self.custom_payloads[check_type] = prev
                    for f in (findings or []):
                        f.evidence = f"[ManualExec] {f.evidence}"
                        self._record_finding(f, source=f"manual:{field_name}")
                else:
                    # Generic: just navigate and check for payload in response
                    await self.browser.navigate(url)
                    source, pair = await self.browser.fill_and_submit_form(0, field_name, payload)
                    if payload in (source or ""):
                        console.print(
                            f"  [dim yellow][U-3 Manual] Payload reflected in response[/dim yellow]"
                        )
                    if self.monitor:
                        await self.monitor.emit("manual_result", {
                            "reflected": payload in (source or ""),
                            "field": field_name,
                            "payload": payload,
                        })
            except Exception as e:
                console.print(f"  [yellow][U-3 Manual] Error: {e}[/yellow]")

    async def _ai_analysis_report(self) -> str:
        """
        A-1: Generate a comprehensive AI analysis of all findings.
        Returns the analysis text (also saved to output_dir/ai_analysis.md).
        """
        if not self.all_findings:
            return ""
        if not await self.payload_gen._check_llm_available():
            return ""

        findings_summary = "\n".join(
            f"- [{f.severity.upper()}] {f.check_type} on {f.url} "
            f"(field: {f.field_name}): {f.evidence[:120]}"
            for f in self.all_findings[:50]
        )
        prompt = (
            f"You are a security analyst reviewing findings from an automated web security scan.\n"
            f"Target: {self.target_url}\n\n"
            f"Findings ({len(self.all_findings)} total):\n{findings_summary}\n\n"
            f"Please provide:\n"
            f"1. Overall attack scenario narrative (how these vulnerabilities could be chained)\n"
            f"2. Top 3 priority fixes with specific remediation steps\n"
            f"3. Recommended WAF rules or HTTP security headers\n"
            f"4. Risk rating for the application overall (Critical/High/Medium/Low)\n\n"
            f"Keep the response concise and actionable."
        )
        try:
            resp_text = await self._call_llm_text(prompt)
            if resp_text:
                analysis_path = self.output_dir / "ai_analysis.md"
                analysis_path.write_text(resp_text, encoding="utf-8")
                console.print(f"  [dim cyan][A-1][/dim cyan] AI analysis saved → {analysis_path}")
                return resp_text
        except Exception as e:
            console.print(f"  [yellow][A-1] AI analysis failed: {e}[/yellow]")
        return ""

    async def _call_llm_text(self, prompt: str) -> str:
        """Call the configured LLM and return raw text response."""
        provider = self.payload_gen.provider
        if provider == "claude":
            client = self.payload_gen._get_anthropic_client()
            if client:
                import asyncio as _aio
                loop = _aio.get_event_loop()
                response = await loop.run_in_executor(
                    None,
                    lambda: client.messages.create(
                        model="claude-haiku-4-5-20251001",
                        max_tokens=1500,
                        messages=[{"role": "user", "content": prompt}],
                    ),
                )
                return response.content[0].text
        elif provider == "openai":
            import httpx, os
            api_key = os.environ.get("OPENAI_API_KEY", "")
            if api_key:
                async with httpx.AsyncClient(timeout=60.0) as client:
                    resp = await client.post(
                        "https://api.openai.com/v1/chat/completions",
                        headers={"Authorization": f"Bearer {api_key}"},
                        json={"model": self.payload_gen.openai_model,
                              "messages": [{"role": "user", "content": prompt}],
                              "max_tokens": 1500},
                    )
                    if resp.status_code == 200:
                        return resp.json()["choices"][0]["message"]["content"]
        elif provider == "gemini":
            import httpx, os
            api_key = os.environ.get("GEMINI_API_KEY", "")
            if api_key:
                url = (
                    f"https://generativelanguage.googleapis.com/v1beta/models/"
                    f"{self.payload_gen.gemini_model}:generateContent?key={api_key}"
                )
                async with httpx.AsyncClient(timeout=60.0) as client:
                    resp = await client.post(url, json={"contents": [{"parts": [{"text": prompt}]}]})
                    if resp.status_code == 200:
                        return resp.json()["candidates"][0]["content"]["parts"][0]["text"]
        else:
            # Ollama
            import httpx
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    f"{self.payload_gen.ollama_url}/api/generate",
                    json={"model": self.payload_gen.ollama_model, "prompt": prompt,
                          "stream": False, "options": {"num_predict": 1500}},
                )
                if resp.status_code == 200:
                    return resp.json().get("response", "")
        return ""

    def _print_summary(self):
        console.print()
        console.print(f"  Target   : [cyan]{self.target_url}[/cyan]")
        console.print(f"  Pages    : [cyan]{len(self.visited_urls)}[/cyan]")
        console.print(f"  Plans    : [cyan]{len(self.attack_plans)}[/cyan]")
        color = "red" if self.all_findings else "green"
        console.print(f"  Findings : [{color}]{len(self.all_findings)}[/{color}]")
        adaptive_count = sum(1 for f in self.all_findings if "[AdaptiveAI]" in f.evidence)
        if adaptive_count:
            console.print(
                f"  [bold magenta]Adaptive AI[/bold magenta] : "
                f"[magenta]{adaptive_count}[/magenta] finding(s) discovered via LLM-generated bypass payloads"
            )
        chain_count = sum(1 for f in self.all_findings if "[ChainDetect]" in f.evidence)
        if chain_count:
            console.print(
                f"  [bold yellow]Chain Detect[/bold yellow] : "
                f"[yellow]{chain_count}[/yellow] finding(s) from stored/second-order vulnerability chain"
            )
        multi_count = sum(1 for f in self.all_findings if "[MultiParam]" in f.evidence)
        if multi_count:
            console.print(
                f"  [bold cyan]Multi-Param [/bold cyan] : "
                f"[cyan]{multi_count}[/cyan] finding(s) from simultaneous multi-field injection"
            )

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

        if self.ctf_found_flags:
            console.print()
            console.print(Rule("[bold white on red]  🚩  CTF FLAGS CAPTURED  🚩  [/bold white on red]", style="red"))
            for flag, src in self.ctf_found_flags:
                console.print(f"  [bold yellow]{flag}[/bold yellow]  [dim]← {src}[/dim]")
            console.print(Rule(style="red"))

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
