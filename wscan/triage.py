"""
Triage Mode — Fast Vulnerability Assessment
============================================
Crawls the target, analyzes page structure and HTTP headers WITHOUT
sending exploit payloads, then outputs:
  - Per-field risk assessment (likely vulnerability types)
  - Recommended payloads to try manually or in full scan mode
  - Page-level header / configuration issues

Usage:
  python main.py triage https://example.com
  python main.py triage https://example.com --depth 2 --llm claude
  python main.py triage https://example.com --output triage.json

The output is a Rich table in the terminal and optionally a JSON file.
"""
from __future__ import annotations

import asyncio
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field as dc_field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urljoin

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box as rbox
from rich.text import Text

# ---------------------------------------------------------------------------
# Recommended payload snippets for each check type
# ---------------------------------------------------------------------------
_RECOMMENDED_PAYLOADS: dict[str, list[str]] = {
    "sqli": [
        "' OR '1'='1'--",
        "' OR 1=1--",
        "1' AND SLEEP(3)--",
        "\" OR \"1\"=\"1",
        "'; DROP TABLE users--",
        "1 UNION SELECT NULL,NULL,NULL--",
    ],
    "xss": [
        "<script>alert(document.domain)</script>",
        "<img src=x onerror=alert(1)>",
        '"><svg onload=alert(1)>',
        "javascript:alert(1)",
        "<details open ontoggle=alert(1)>",
    ],
    "dom_xss": [
        "#<img src=x onerror=alert(1)>",
        "?x=<script>alert(1)</script>",
        "#javascript:alert(1)",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config}}",
    ],
    "os": [
        "; id",
        "| id",
        "`id`",
        "; sleep 3",
        "& whoami",
        "| dir",
    ],
    "path_traversal": [
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc/passwd",
    ],
    "open_redirect": [
        "https://evil.example.com",
        "//evil.example.com",
        "\\\\evil.example.com",
        "/%09/evil.example.com",
    ],
    "header_injection": [
        "%0d%0aX-Injected: wscan",
        "%0aSet-Cookie: wscan=1",
        "\r\nX-Injected: wscan",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost/",
        "http://127.0.0.1:22",
        "file:///etc/passwd",
        "http://[::]:80/",
    ],
    "nosql": [
        '{"$ne": ""}',
        '{"$gt": ""}',
        '{"$regex": ".*"}',
        '{"$where": "1==1"}',
    ],
    "file_upload": [
        "Upload: test.php (content: <?php system($_GET['cmd']); ?>)",
        "Upload: test.php.jpg (double extension)",
        "Upload: test.phtml (alternative PHP extension)",
    ],
    "cors": [
        "Add header: Origin: https://evil.example.com",
        "Check response for: Access-Control-Allow-Origin: https://evil.example.com",
    ],
    "csrf": [
        "Remove CSRF token from POST and re-submit",
        "Change method from POST to GET",
        "Submit from a different origin",
    ],
    "host_header": [
        "Add header: Host: evil.example.com",
        "Add header: X-Forwarded-Host: evil.example.com",
        "Check password-reset link in response",
    ],
    "clickjacking": [
        '<iframe src="TARGET_URL" width="800" height="600"></iframe>',
    ],
    "session": [
        "Inspect Set-Cookie: check for Secure, HttpOnly, SameSite",
        "Try transmitting cookie over HTTP",
    ],
    "request_smuggling": [
        "POST with Content-Length: 6 and Transfer-Encoding: chunked, body: 0\\r\\n\\r\\n",
    ],
    "deserialization": [
        "Send: O:1:\"A\":1:{s:1:\"a\";s:1:\"b\";} as a parameter value",
        "Send Java magic bytes: \\xac\\xed\\x00\\x05 as base64: rO0ABQ==",
    ],
    "stored_xss": [
        "<script>alert('STORED-'+document.domain)</script>",
        "<img src=x id='wscan_stored' onerror=alert(1)>",
    ],
    "security_headers": [
        "Check response headers for HSTS, CSP, X-Content-Type-Options",
    ],
}


# ---------------------------------------------------------------------------
# Heuristic rules: field name/type → likely vuln types (ordered by confidence)
# ---------------------------------------------------------------------------

_FIELD_RULES: list[tuple[re.Pattern, list[str]]] = [
    # SQL injection targets
    (re.compile(r"id$|user_?id$|item_?id$|order_?id$|product_?id$", re.I),
     ["sqli", "privesc", "nosql"]),
    (re.compile(r"q$|query$|search$|keyword$|filter$|term$", re.I),
     ["sqli", "xss", "ssti"]),
    (re.compile(r"username|user$|login$|email$", re.I),
     ["sqli", "xss", "nosql"]),
    (re.compile(r"pass(word)?$|passwd$|pwd$", re.I),
     ["sqli", "nosql"]),
    (re.compile(r"name$|title$|subject$|message$|comment$|description$|body$|content$", re.I),
     ["xss", "stored_xss", "ssti", "sqli"]),
    (re.compile(r"url$|link$|href$|src$|image$|avatar$", re.I),
     ["ssrf", "open_redirect", "xss"]),
    (re.compile(r"redirect$|return$|next$|goto$|back$|continue$|target$", re.I),
     ["open_redirect"]),
    (re.compile(r"file$|path$|dir$|folder$|include$|template$", re.I),
     ["path_traversal", "ssrf", "ssti"]),
    (re.compile(r"cmd$|command$|exec$|run$|shell$|ping$|host$|ip$|server$", re.I),
     ["os", "ssrf", "sqli"]),
    (re.compile(r"email$|to$|cc$|bcc$|from$|recipient$|address$", re.I),
     ["mail_header", "header_injection"]),
    (re.compile(r"template$|layout$|theme$|view$|render$", re.I),
     ["ssti", "path_traversal"]),
    (re.compile(r"token$|csrf$|nonce$|_token$", re.I),
     ["csrf"]),
    (re.compile(r"data$|payload$|json$|xml$|input$", re.I),
     ["sqli", "xss", "ssti", "nosql", "deserialization"]),
    (re.compile(r"upload$|attach$|file$|image$|photo$", re.I),
     ["file_upload", "path_traversal"]),
]

# Field types → likely vulns
_TYPE_RULES: dict[str, list[str]] = {
    "file":     ["file_upload"],
    "hidden":   ["csrf", "sqli", "deserialization"],
    "url":      ["ssrf", "open_redirect"],
    "email":    ["mail_header", "xss"],
    "text":     ["xss", "sqli"],
    "textarea": ["xss", "stored_xss", "sqli", "ssti"],
    "search":   ["xss", "sqli"],
    "number":   ["sqli"],
    "password": ["sqli"],
}

# Page-level checks (always evaluated)
_PAGE_LEVEL_CHECKS = [
    "clickjacking",
    "session",
    "csrf",
    "cors",
    "security_headers",
    "host_header",
    "info_disclosure",
    "request_smuggling",
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class FieldRisk:
    url: str
    field_name: str
    field_type: str
    form_action: str
    likely_vulns: list[str]      # ordered by confidence
    risk_level: str              # critical / high / medium / low
    payloads: dict[str, list[str]]  # check_type → payload list


@dataclass
class PageRisk:
    url: str
    page_level_risks: list[str]  # check names
    header_issues: list[str]     # human-readable descriptions
    forms_found: int
    inputs_found: int


@dataclass
class TriageReport:
    target_url: str
    field_risks: list[FieldRisk] = dc_field(default_factory=list)
    page_risks: list[PageRisk] = dc_field(default_factory=list)
    llm_insights: str = ""

    def to_dict(self) -> dict:
        return {
            "target_url": self.target_url,
            "field_risks": [
                {
                    "url": r.url,
                    "field_name": r.field_name,
                    "field_type": r.field_type,
                    "form_action": r.form_action,
                    "likely_vulns": r.likely_vulns,
                    "risk_level": r.risk_level,
                    "payloads": r.payloads,
                }
                for r in self.field_risks
            ],
            "page_risks": [
                {
                    "url": r.url,
                    "page_level_risks": r.page_level_risks,
                    "header_issues": r.header_issues,
                    "forms_found": r.forms_found,
                    "inputs_found": r.inputs_found,
                }
                for r in self.page_risks
            ],
            "llm_insights": self.llm_insights,
        }


# ---------------------------------------------------------------------------
# Risk level computation
# ---------------------------------------------------------------------------

_CRITICAL_VULNS = {"os", "sqli", "ssti", "deserialization", "stored_xss", "ssrf", "file_upload"}
_HIGH_VULNS     = {"xss", "dom_xss", "nosql", "path_traversal", "cors"}
_MEDIUM_VULNS   = {
    "open_redirect", "csrf", "header_injection", "mail_header",
    "host_header", "session", "privesc",
}


def _compute_risk(vulns: list[str]) -> str:
    if any(v in _CRITICAL_VULNS for v in vulns):
        return "critical"
    if any(v in _HIGH_VULNS for v in vulns):
        return "high"
    if any(v in _MEDIUM_VULNS for v in vulns):
        return "medium"
    return "low"


def _risk_badge(level: str) -> Text:
    colors = {"critical": "red bold", "high": "orange3 bold", "medium": "yellow", "low": "dim"}
    labels = {"critical": "●CRIT", "high": "●HIGH", "medium": "●MED", "low": "●LOW"}
    return Text(labels.get(level, level.upper()), style=colors.get(level, "white"))


# ---------------------------------------------------------------------------
# Heuristic field analyser
# ---------------------------------------------------------------------------

def analyse_field(
    url: str,
    field: dict,
    form_action: str,
) -> Optional[FieldRisk]:
    name: str = field.get("name", "")
    ftype: str = field.get("type", "text").lower()

    if ftype in ("submit", "button", "image", "reset"):
        return None
    if not name:
        return None

    vulns: list[str] = []

    # Type-based rules
    for t, vlist in _TYPE_RULES.items():
        if ftype == t:
            for v in vlist:
                if v not in vulns:
                    vulns.append(v)

    # Name-based rules
    for pattern, vlist in _FIELD_RULES:
        if pattern.search(name):
            for v in vlist:
                if v not in vulns:
                    vulns.append(v)

    # Fallback for any text-like field
    if not vulns and ftype in ("text", "textarea", "search", "tel", ""):
        vulns = ["xss", "sqli"]

    if not vulns:
        return None

    # Build payload map
    payloads = {v: _RECOMMENDED_PAYLOADS.get(v, [])[:3] for v in vulns}

    return FieldRisk(
        url=url,
        field_name=name,
        field_type=ftype,
        form_action=form_action,
        likely_vulns=vulns,
        risk_level=_compute_risk(vulns),
        payloads=payloads,
    )


def analyse_headers(headers: dict) -> list[str]:
    """Return human-readable issues found in HTTP response headers."""
    issues = []
    h = {k.lower(): v for k, v in headers.items()}

    if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
        issues.append("Clickjacking: X-Frame-Options missing")
    if "strict-transport-security" not in h:
        issues.append("HSTS missing")
    if "content-security-policy" not in h:
        issues.append("CSP missing")
    if "x-content-type-options" not in h:
        issues.append("X-Content-Type-Options missing")
    if h.get("access-control-allow-origin") == "*":
        issues.append("CORS: wildcard ACAO (Access-Control-Allow-Origin: *)")
    for th in ("server", "x-powered-by", "x-aspnet-version"):
        if th in h:
            issues.append(f"Tech disclosure: {th}: {h[th]}")

    return issues


# ---------------------------------------------------------------------------
# Triage Engine
# ---------------------------------------------------------------------------

class TriageEngine:
    """
    Lightweight crawl + heuristic analysis engine.
    No payloads are sent — only structural / header analysis.
    """

    def __init__(
        self,
        url: str,
        depth: int = 2,
        headless: bool = True,
        proxy: str = "",
        timeout: int = 20,
        llm_provider: str = "none",
        ollama_model: str = "llama3",
        openai_model: str = "gpt-4o-mini",
        gemini_model: str = "gemini-2.0-flash",
    ):
        self.target_url = url.rstrip("/")
        self.depth = depth
        self.headless = headless
        self.proxy = proxy
        self.timeout = timeout
        self.llm_provider = llm_provider
        self.ollama_model = ollama_model
        self.openai_model = openai_model
        self.gemini_model = gemini_model

        self.report = TriageReport(target_url=self.target_url)
        self._visited: set[str] = set()

    async def run(self) -> TriageReport:
        from playwright.async_api import async_playwright

        console = Console()
        console.print(f"[cyan]Triage crawling:[/cyan] {self.target_url}  depth={self.depth}")

        async with async_playwright() as pw:
            launch_kwargs: dict = {"headless": self.headless}
            if self.proxy:
                launch_kwargs["proxy"] = {"server": self.proxy}

            browser = await pw.chromium.launch(**launch_kwargs)
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent=(
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                ),
            )
            page = await context.new_page()

            # BFS crawl
            queue = [(self.target_url, 0)]
            while queue:
                url, d = queue.pop(0)
                if url in self._visited or d > self.depth:
                    continue
                self._visited.add(url)

                console.print(f"  [dim]Visiting:[/dim] {url}")

                try:
                    resp = await page.goto(url, timeout=self.timeout * 1000, wait_until="domcontentloaded")
                except Exception:
                    continue

                # Collect headers
                headers: dict = {}
                if resp:
                    try:
                        headers = await resp.all_headers()
                    except Exception:
                        pass

                # Analyse forms & fields
                forms = await page.eval_on_selector_all(
                    "form",
                    """forms => forms.map(f => ({
                        action: f.action || '',
                        method: f.method || 'get',
                        fields: Array.from(f.querySelectorAll('input,select,textarea')).map(el => ({
                            name: el.name || '',
                            type: el.type || '',
                            id: el.id || '',
                            placeholder: el.placeholder || '',
                            tagName: el.tagName.toLowerCase(),
                        }))
                    }))"""
                )

                total_inputs = sum(len(f.get("fields", [])) for f in forms)
                header_issues = analyse_headers(headers)
                page_risk = PageRisk(
                    url=url,
                    page_level_risks=_PAGE_LEVEL_CHECKS if (header_issues or forms) else [],
                    header_issues=header_issues,
                    forms_found=len(forms),
                    inputs_found=total_inputs,
                )
                self.report.page_risks.append(page_risk)

                for form in forms:
                    action = form.get("action", url) or url
                    for field_info in form.get("fields", []):
                        risk = analyse_field(url, field_info, action)
                        if risk:
                            self.report.field_risks.append(risk)

                # Collect links for next depth
                if d < self.depth:
                    links = await page.eval_on_selector_all(
                        "a[href]",
                        "els => els.map(el => el.href)",
                    )
                    origin = urlparse(self.target_url).netloc
                    for link in links:
                        parsed = urlparse(link)
                        if parsed.netloc == origin and link not in self._visited:
                            queue.append((link.split("#")[0], d + 1))

            await browser.close()

        # Optional LLM analysis
        if self.llm_provider != "none":
            self.report.llm_insights = await self._llm_analyse()

        return self.report

    async def _llm_analyse(self) -> str:
        """Ask LLM for a brief prioritized attack strategy based on triage findings."""
        try:
            from wscan.payload_gen import PayloadGenerator
            pg = PayloadGenerator(
                provider=self.llm_provider,
                ollama_model=self.ollama_model,
                openai_model=self.openai_model,
                gemini_model=self.gemini_model,
            )
            if not await pg._check_llm_available():
                return ""

            # Summarize findings for the LLM
            summary_parts = []
            for fr in self.report.field_risks[:20]:  # limit to 20
                summary_parts.append(
                    f"URL={fr.url} field={fr.field_name} type={fr.field_type} "
                    f"likely={','.join(fr.likely_vulns[:3])}"
                )
            for pr in self.report.page_risks[:10]:
                if pr.header_issues:
                    summary_parts.append(
                        f"URL={pr.url} header_issues={'; '.join(pr.header_issues[:3])}"
                    )

            prompt = (
                "You are a web security expert. I ran a triage (no payload sending) "
                "on a web application and collected this structural analysis:\n\n"
                + "\n".join(summary_parts)
                + "\n\nBased on this, give a brief (5-8 bullet points) prioritized "
                "attack strategy. Focus on the highest impact attack paths. "
                "Mention which specific fields to target first and why."
            )

            results = await pg._call_llm(prompt)
            if isinstance(results, list):
                return "\n".join(str(r) for r in results)
            return str(results)
        except Exception:
            return ""


# ---------------------------------------------------------------------------
# Rich output renderer
# ---------------------------------------------------------------------------

def render_triage_report(report: TriageReport, console: Console) -> None:
    console.print()
    console.print(Panel.fit(
        f"[bold cyan]WScan Triage Report[/bold cyan]\n"
        f"Target: [yellow]{report.target_url}[/yellow]\n"
        f"Fields analysed: [green]{len(report.field_risks)}[/green]   "
        f"Pages visited: [green]{len(report.page_risks)}[/green]",
        border_style="cyan",
    ))

    # ── Field-level risks ──────────────────────────────────────────────
    if report.field_risks:
        tbl = Table(
            title="[bold]Field-Level Risk Assessment[/bold]",
            box=rbox.ROUNDED,
            show_lines=True,
            header_style="bold cyan",
        )
        tbl.add_column("URL", max_width=35, overflow="fold")
        tbl.add_column("Field", max_width=20)
        tbl.add_column("Type", max_width=8)
        tbl.add_column("Risk", max_width=8)
        tbl.add_column("Likely Vulns", max_width=28)
        tbl.add_column("Recommended Payloads (top 2)", max_width=50, overflow="fold")

        for r in sorted(
            report.field_risks,
            key=lambda x: ["critical", "high", "medium", "low"].index(x.risk_level),
        ):
            vuln_str = ", ".join(r.likely_vulns[:4])
            payload_lines = []
            for v in r.likely_vulns[:2]:
                plist = _RECOMMENDED_PAYLOADS.get(v, [])
                if plist:
                    payload_lines.append(f"[{v}] {plist[0]}")
            payload_str = "\n".join(payload_lines)

            tbl.add_row(
                r.url,
                r.field_name,
                r.field_type,
                _risk_badge(r.risk_level),
                vuln_str,
                payload_str,
            )
        console.print(tbl)

    # ── Page-level issues ─────────────────────────────────────────────
    header_rows = [
        (pr.url, issue)
        for pr in report.page_risks
        for issue in pr.header_issues
    ]
    if header_rows:
        htbl = Table(
            title="[bold]Page-Level Header / Configuration Issues[/bold]",
            box=rbox.ROUNDED,
            show_lines=True,
            header_style="bold yellow",
        )
        htbl.add_column("URL", max_width=40, overflow="fold")
        htbl.add_column("Issue", overflow="fold")
        for url, issue in header_rows:
            htbl.add_row(url, issue)
        console.print(htbl)

    # ── LLM insights ─────────────────────────────────────────────────
    if report.llm_insights:
        console.print(Panel(
            report.llm_insights,
            title="[bold magenta]AI Attack Strategy[/bold magenta]",
            border_style="magenta",
        ))

    # ── Suggested scan command ────────────────────────────────────────
    vuln_counts: dict[str, int] = defaultdict(int)
    for r in report.field_risks:
        for v in r.likely_vulns:
            vuln_counts[v] += 1
    top_checks = sorted(vuln_counts, key=lambda k: -vuln_counts[k])[:6]
    if top_checks:
        checks_str = " ".join(top_checks)
        console.print(
            f"\n[bold green]Suggested full scan command:[/bold green]\n"
            f"  [cyan]python main.py scan {report.target_url} "
            f"--checks {checks_str}[/cyan]"
        )
