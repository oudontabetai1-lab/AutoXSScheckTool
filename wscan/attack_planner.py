"""
Attack Planner
==============
AeyeScan / VEX-style AI-driven attack-strategy planning.

Before payload injection starts, the planner:

  1. Extracts page context  — title, visible text, form purposes, field names / types.
  2. Asks the LLM to reason about the application and produce a per-field attack plan.
  3. Returns prioritised check lists and targeted payloads for every discovered field.
  4. Falls back to a fast heuristic analyser when no LLM is available.

Result is a PageAttackPlan that the ScanEngine uses to:
  - Skip irrelevant checks per field (reduce noise / scan time).
  - Run highest-risk fields first.
  - Inject purpose-built payloads instead of generic lists.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING

from rich.console import Console
from rich.rule import Rule

if TYPE_CHECKING:
    from wscan.payload_gen import PayloadGenerator

console = Console()


def _thinking_header(provider: str, model: str) -> None:
    console.print(Rule(f"[bold cyan] AI AttackPlanner ({provider}: {model}) ", style="cyan"))
    console.print()


def _thinking_footer() -> None:
    console.print()
    console.print(Rule(style="cyan"))

# ---------------------------------------------------------------------------
# All check names the planner can recommend
# ---------------------------------------------------------------------------
ALL_CHECKS = [
    "sqli", "xss", "os", "path_traversal",
    "csrf", "header_injection", "mail_header",
    "open_redirect", "clickjacking", "session", "ssti",
]

# ---------------------------------------------------------------------------
# Heuristic rules — field name substrings → likely checks
# ---------------------------------------------------------------------------
_HEURISTIC_RULES: list[tuple[set[str], list[str], int]] = [
    # (name-hint substrings, checks, risk_score)
    ({"search", "query", "q", "keyword", "term", "find", "filter", "s"},
     ["sqli", "xss"], 8),
    ({"id", "user_id", "userid", "product_id", "item", "order", "cat", "category",
      "page", "offset", "limit", "sort", "order_by"},
     ["sqli"], 8),
    ({"cmd", "exec", "command", "run", "shell", "ping", "host", "ip", "addr"},
     ["os", "sqli"], 9),
    ({"file", "path", "filepath", "dir", "directory", "filename", "include",
      "document", "doc", "download", "load", "read", "src"},
     ["path_traversal", "xss"], 9),
    ({"template", "theme", "layout", "view", "tpl"},
     ["ssti", "xss"], 8),
    ({"email", "mail", "e-mail", "e_mail"},
     ["mail_header", "xss", "sqli"], 7),
    ({"to", "from", "cc", "bcc", "subject", "reply_to", "replyto", "recipient",
      "sender"},
     ["mail_header", "xss"], 8),
    ({"next", "redirect", "redirect_to", "redirect_url", "return", "return_to",
      "returnto", "url", "forward", "goto", "target", "dest", "destination",
      "redir", "continue", "ref", "callback", "back", "link", "jump", "location"},
     ["open_redirect", "xss"], 8),
    ({"comment", "message", "content", "body", "text", "note", "feedback",
      "description", "input", "data", "value"},
     ["xss", "sqli", "ssti"], 7),
    ({"username", "user", "login", "name", "firstname", "lastname", "fullname"},
     ["sqli", "xss"], 6),
    ({"password", "passwd", "pwd", "pass"},
     ["sqli"], 4),  # Low risk score — common field, less likely to be reflected
    ({"header", "x-header", "referer", "referrer", "origin", "agent",
      "user_agent", "useragent"},
     ["header_injection", "xss"], 8),
    ({"age", "price", "qty", "quantity", "amount", "count", "num", "number"},
     ["sqli"], 6),
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FieldAttackPlan:
    """Attack plan for a single form field / URL parameter."""
    name: str
    form_index: int
    is_url_param: bool
    risk_score: int                       # 1–10, higher = scan first
    priority_checks: list[str]            # ordered, highest priority first
    rationale: str                        # LLM / heuristic reasoning
    custom_payloads: dict[str, list[str]] = field(default_factory=dict)
    # check_type → targeted payloads


@dataclass
class PageAttackPlan:
    """Full attack plan for one page URL."""
    url: str
    page_purpose: str                          # brief description of the page
    planned_by: str                            # "llm" | "heuristic"
    fields: list[FieldAttackPlan] = field(default_factory=list)

    def sorted_fields(self) -> list[FieldAttackPlan]:
        """Return fields sorted by descending risk score."""
        return sorted(self.fields, key=lambda f: f.risk_score, reverse=True)

    def get_field_plan(self, name: str, form_index: int,
                       is_url_param: bool) -> Optional[FieldAttackPlan]:
        for fp in self.fields:
            if fp.name == name and fp.form_index == form_index \
                    and fp.is_url_param == is_url_param:
                return fp
        return None


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------

class AttackPlanner:
    """
    Analyses a page and produces a PageAttackPlan.

    With LLM: deep contextual analysis → precise checks + targeted payloads.
    Without LLM: fast heuristic field-name analysis.
    """

    _LLM_PROMPT = """You are a senior web application penetration tester.
Analyse the following web page and produce a detailed attack plan.

## Site Map (all pages discovered in this crawl)
{site_map}

## Current Page
URL: {url}
Title: {title}
Page purpose (your initial guess): {purpose_hint}

## Discovered Inputs
{inputs_desc}

## Cross-page attack awareness
Consider stored / second-order attacks carefully:
- If this page ACCEPTS input that could be DISPLAYED on another page (e.g., a comment that
  appears in a feed, or a username shown on a profile page), mark XSS / SQLi risk HIGH even
  if the reflection is not immediate on this same page.
- If another page in the site map looks like it could render input from this page, note it
  in the rationale.

## Your task
1. State the page's actual purpose (login, search, file upload, admin, etc.).
2. For EACH input field / URL parameter, decide:
   - Which vulnerability checks are most relevant (pick from: {all_checks})
   - A risk score 1-10 (10 = almost certainly vulnerable given context)
   - A brief rationale (1-2 sentences, mention cross-page risk if applicable)
   - Up to 5 targeted payloads for the most likely check type (optional but preferred)

## Return ONLY valid JSON in this exact schema (no markdown, no extra text):
{{
  "page_purpose": "<one sentence>",
  "fields": [
    {{
      "name": "<field name>",
      "form_index": <int>,
      "is_url_param": <bool>,
      "risk_score": <1-10>,
      "priority_checks": ["<check1>", "<check2>"],
      "rationale": "<why, including any cross-page risk>",
      "custom_payloads": {{
        "<check_type>": ["<payload1>", "<payload2>"]
      }}
    }}
  ]
}}"""

    def __init__(
        self,
        payload_gen: "PayloadGenerator",
        enabled_checks: list[str],
    ):
        self.payload_gen = payload_gen
        self.enabled_checks: set[str] = set(enabled_checks)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def analyze_page(
        self,
        url: str,
        page_html: str,
        forms: list[dict],
        url_params: list[str],
        site_map: str = "",
    ) -> PageAttackPlan:
        """
        Build a PageAttackPlan for the given page.
        site_map: newline-separated summary of all crawled pages (for cross-page XSS awareness).
        Tries LLM first; falls back to heuristic analysis.
        """
        if self.payload_gen.provider != "none" and await self.payload_gen._check_llm_available():
            plan = await self._llm_plan(url, page_html, forms, url_params, site_map)
            if plan:
                self._print_plan_summary(plan)
                return plan

        plan = self._heuristic_plan(url, forms, url_params)
        console.print(
            f"  [dim cyan][AttackPlanner][/dim cyan] Heuristic plan — "
            f"{len(plan.fields)} fields"
        )
        return plan

    def _print_plan_summary(self, plan: "PageAttackPlan") -> None:
        """Print a rich table summarising the LLM-generated attack plan."""
        from rich.table import Table
        from rich import box as rbox

        console.print(
            f"\n  [bold cyan][AttackPlanner][/bold cyan] "
            f"LLM plan ready — purpose: [yellow]{plan.page_purpose[:80]}[/yellow]"
        )
        t = Table(
            show_header=True,
            header_style="bold magenta",
            box=rbox.SIMPLE,
            padding=(0, 1),
        )
        t.add_column("Field",          style="cyan",  no_wrap=True)
        t.add_column("Risk", justify="center", style="bold")
        t.add_column("Checks",         style="green")
        t.add_column("Rationale",      style="dim", overflow="fold")

        for fp in plan.sorted_fields():
            score = fp.risk_score
            risk_color = "red" if score >= 8 else ("yellow" if score >= 5 else "green")
            t.add_row(
                fp.name,
                f"[{risk_color}]{score}[/{risk_color}]",
                " · ".join(fp.priority_checks[:4]),
                fp.rationale[:80],
            )
        console.print(t)

    # ------------------------------------------------------------------
    # LLM-based planning
    # ------------------------------------------------------------------

    async def _llm_plan(
        self,
        url: str,
        page_html: str,
        forms: list[dict],
        url_params: list[str],
        site_map: str = "",
    ) -> Optional[PageAttackPlan]:
        """Ask the LLM to produce a structured attack plan with cross-page awareness."""
        inputs_lines: list[str] = []
        for fi, form in enumerate(forms):
            for inp in form.get("inputs", []):
                name = inp.get("name", f"field_{fi}")
                itype = inp.get("type", "text")
                inputs_lines.append(
                    f"  - Form[{fi}] field '{name}' (type={itype}, is_url_param=false)"
                )
        for param in url_params:
            inputs_lines.append(f"  - URL param '{param}' (is_url_param=true)")

        if not inputs_lines:
            return None

        title = self._extract_title(page_html)
        text_snippet = self._extract_text(page_html, max_chars=800)
        purpose_hint = self._guess_purpose(title, text_snippet, forms)

        prompt = self._LLM_PROMPT.format(
            url=url,
            title=title,
            purpose_hint=purpose_hint,
            inputs_desc="\n".join(inputs_lines),
            all_checks=", ".join(sorted(self.enabled_checks)),
            site_map=site_map or "  (only this page was crawled)",
        )

        raw: Optional[str] = None
        provider = self.payload_gen.provider
        if provider == "claude":
            raw = await self._call_claude(prompt)
        elif provider == "openai":
            raw = await self._call_openai(prompt)
        elif provider == "gemini":
            raw = await self._call_gemini(prompt)
        else:
            raw = await self._call_ollama(prompt)

        if not raw:
            return None

        return self._parse_llm_response(url, raw)

    async def _call_claude(self, prompt: str) -> Optional[str]:
        """Claude streaming attack plan — prints chunks live."""
        client = self.payload_gen._get_anthropic_client()
        if not client:
            return None
        _thinking_header("Claude", "claude-haiku-4-5-20251001")
        try:
            import asyncio
            full = ""

            def _stream_sync():
                nonlocal full
                with client.messages.stream(
                    model="claude-haiku-4-5-20251001",
                    max_tokens=2000,
                    messages=[{"role": "user", "content": prompt}],
                ) as stream:
                    for chunk in stream.text_stream:
                        sys.stdout.write(chunk)
                        sys.stdout.flush()
                        full += chunk
                return full

            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, _stream_sync)
            _thinking_footer()
            return full if full else None
        except Exception as e:
            _thinking_footer()
            console.print(f"[yellow][AttackPlanner] Claude error: {e}[/yellow]")
            return None

    async def _call_ollama(self, prompt: str) -> Optional[str]:
        """Ollama streaming attack plan — prints chunks live."""
        import httpx
        _thinking_header("Ollama", self.payload_gen.ollama_model)
        full = ""
        try:
            async with httpx.AsyncClient(timeout=90.0) as client:
                async with client.stream(
                    "POST",
                    f"{self.payload_gen.ollama_url}/api/generate",
                    json={
                        "model": self.payload_gen.ollama_model,
                        "prompt": prompt,
                        "stream": True,
                        "options": {"temperature": 0.3, "num_predict": 2000},
                    },
                ) as resp:
                    if resp.status_code != 200:
                        _thinking_footer()
                        console.print(f"[yellow][AttackPlanner] Ollama error {resp.status_code}[/yellow]")
                        return None
                    async for line in resp.aiter_lines():
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            chunk = data.get("response", "")
                            if chunk:
                                sys.stdout.write(chunk)
                                sys.stdout.flush()
                                full += chunk
                            if data.get("done"):
                                break
                        except json.JSONDecodeError:
                            pass
            _thinking_footer()
            return full if full else None
        except Exception as e:
            _thinking_footer()
            console.print(f"[yellow][AttackPlanner] Ollama error: {e}[/yellow]")
        return None

    async def _call_openai(self, prompt: str) -> Optional[str]:
        """OpenAI streaming attack plan — prints chunks live."""
        import os, httpx
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            return None
        _thinking_header("OpenAI", self.payload_gen.openai_model)
        full = ""
        try:
            async with httpx.AsyncClient(timeout=90.0) as client:
                async with client.stream(
                    "POST",
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {api_key}"},
                    json={
                        "model": self.payload_gen.openai_model,
                        "messages": [{"role": "user", "content": prompt}],
                        "max_tokens": 2000,
                        "temperature": 0.3,
                        "stream": True,
                    },
                ) as resp:
                    if resp.status_code != 200:
                        _thinking_footer()
                        console.print(f"[yellow][AttackPlanner] OpenAI error {resp.status_code}[/yellow]")
                        return None
                    async for line in resp.aiter_lines():
                        if not line.startswith("data: "):
                            continue
                        data_str = line[6:]
                        if data_str.strip() == "[DONE]":
                            break
                        try:
                            data = json.loads(data_str)
                            chunk = data["choices"][0]["delta"].get("content", "")
                            if chunk:
                                sys.stdout.write(chunk)
                                sys.stdout.flush()
                                full += chunk
                        except (json.JSONDecodeError, KeyError, IndexError):
                            pass
            _thinking_footer()
            return full if full else None
        except Exception as e:
            _thinking_footer()
            console.print(f"[yellow][AttackPlanner] OpenAI error: {e}[/yellow]")
        return None

    async def _call_gemini(self, prompt: str) -> Optional[str]:
        """Gemini attack plan — prints response after generation."""
        import os, httpx
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            return None
        _thinking_header("Gemini", self.payload_gen.gemini_model)
        try:
            model = self.payload_gen.gemini_model
            url = (
                f"https://generativelanguage.googleapis.com/v1beta/models/"
                f"{model}:generateContent?key={api_key}"
            )
            async with httpx.AsyncClient(timeout=90.0) as client:
                resp = await client.post(
                    url,
                    json={"contents": [{"parts": [{"text": prompt}]}]},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    text = data["candidates"][0]["content"]["parts"][0]["text"]
                    sys.stdout.write(text)
                    sys.stdout.flush()
                    _thinking_footer()
                    return text
                console.print(f"[yellow][AttackPlanner] Gemini error {resp.status_code}[/yellow]")
        except Exception as e:
            console.print(f"[yellow][AttackPlanner] Gemini error: {e}[/yellow]")
        _thinking_footer()
        return None

    def _parse_llm_response(self, url: str, raw: str) -> Optional[PageAttackPlan]:
        """Parse the LLM's JSON response into a PageAttackPlan."""
        # Extract the first JSON object from the response
        match = re.search(r'\{.*\}', raw, re.DOTALL)
        if not match:
            return None
        try:
            data = json.loads(match.group())
        except json.JSONDecodeError:
            return None

        page_purpose = data.get("page_purpose", "unknown")
        field_plans: list[FieldAttackPlan] = []

        for fd in data.get("fields", []):
            name = str(fd.get("name", ""))
            if not name:
                continue
            priority_checks = [
                c for c in fd.get("priority_checks", [])
                if c in self.enabled_checks
            ]
            # Fallback: if LLM gave no valid checks, use heuristic
            if not priority_checks:
                priority_checks = self._heuristic_checks_for(name)

            custom_payloads = {}
            for check_type, payloads in fd.get("custom_payloads", {}).items():
                if check_type in self.enabled_checks and isinstance(payloads, list):
                    custom_payloads[check_type] = [str(p) for p in payloads if p]

            field_plans.append(FieldAttackPlan(
                name=name,
                form_index=int(fd.get("form_index", 0)),
                is_url_param=bool(fd.get("is_url_param", False)),
                risk_score=max(1, min(10, int(fd.get("risk_score", 5)))),
                priority_checks=priority_checks,
                rationale=str(fd.get("rationale", "")),
                custom_payloads=custom_payloads,
            ))

        return PageAttackPlan(
            url=url,
            page_purpose=page_purpose,
            planned_by="llm",
            fields=field_plans,
        )

    # ------------------------------------------------------------------
    # Heuristic-based planning (LLM fallback)
    # ------------------------------------------------------------------

    def _heuristic_plan(
        self,
        url: str,
        forms: list[dict],
        url_params: list[str],
    ) -> PageAttackPlan:
        """Fast rule-based attack plan using field name heuristics."""
        field_plans: list[FieldAttackPlan] = []

        for fi, form in enumerate(forms):
            for inp in form.get("inputs", []):
                name = inp.get("name", f"field_{fi}")
                checks = self._heuristic_checks_for(name)
                score = self._heuristic_score_for(name)
                field_plans.append(FieldAttackPlan(
                    name=name,
                    form_index=fi,
                    is_url_param=False,
                    risk_score=score,
                    priority_checks=checks,
                    rationale=(
                        f"Heuristic: field name '{name}' matches rule for "
                        f"{', '.join(checks[:2]) if checks else 'generic'} testing"
                    ),
                ))

        for param in url_params:
            checks = self._heuristic_checks_for(param)
            score = self._heuristic_score_for(param)
            field_plans.append(FieldAttackPlan(
                name=param,
                form_index=0,
                is_url_param=True,
                risk_score=score,
                priority_checks=checks,
                rationale=(
                    f"Heuristic: URL param '{param}' matches rule for "
                    f"{', '.join(checks[:2]) if checks else 'generic'} testing"
                ),
            ))

        return PageAttackPlan(
            url=url,
            page_purpose="(heuristic analysis — LLM unavailable)",
            planned_by="heuristic",
            fields=field_plans,
        )

    def _heuristic_checks_for(self, field_name: str) -> list[str]:
        """Return ordered check list for a field name using heuristic rules."""
        name_lower = field_name.lower().replace("-", "_")
        for hints, checks, _ in _HEURISTIC_RULES:
            if any(hint in name_lower for hint in hints):
                return [c for c in checks if c in self.enabled_checks]
        # Generic fallback: run all enabled injection checks
        return [c for c in ["sqli", "xss", "os"] if c in self.enabled_checks]

    def _heuristic_score_for(self, field_name: str) -> int:
        """Return a risk score for a field name."""
        name_lower = field_name.lower().replace("-", "_")
        for hints, _, score in _HEURISTIC_RULES:
            if any(hint in name_lower for hint in hints):
                return score
        return 5  # default medium risk

    # ------------------------------------------------------------------
    # HTML helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_title(html: str) -> str:
        m = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return re.sub(r'\s+', ' ', m.group(1)).strip() if m else ""

    @staticmethod
    def _extract_text(html: str, max_chars: int = 800) -> str:
        text = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<[^>]+>', ' ', text)
        text = re.sub(r'\s+', ' ', text).strip()
        return text[:max_chars]

    @staticmethod
    def _guess_purpose(title: str, text: str, forms: list[dict]) -> str:
        combined = (title + " " + text).lower()
        if any(w in combined for w in ["login", "sign in", "log in", "password", "username"]):
            return "authentication / login form"
        if any(w in combined for w in ["register", "sign up", "create account"]):
            return "user registration form"
        if any(w in combined for w in ["search", "find", "query", "results"]):
            return "search / query interface"
        if any(w in combined for w in ["upload", "file", "attach", "import"]):
            return "file upload interface"
        if any(w in combined for w in ["admin", "dashboard", "manage", "panel"]):
            return "administration panel"
        if any(w in combined for w in ["contact", "message", "feedback", "support"]):
            return "contact / feedback form"
        if any(w in combined for w in ["checkout", "payment", "cart", "order", "purchase"]):
            return "e-commerce / checkout form"
        if any(w in combined for w in ["profile", "account", "settings", "preferences"]):
            return "user profile / settings"
        return "general web form"
