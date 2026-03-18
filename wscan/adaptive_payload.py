"""
Adaptive Payload Engine
=======================
After the standard payload set is fired at a field, this engine:

  1. Captures the current page HTML to observe how the application
     filtered / sanitized the input.
  2. Feeds that observation context to an LLM with a detailed bypass prompt.
  3. Streams the LLM's "reasoning" live to the terminal.
  4. Returns creative, context-aware bypass payloads that a human might
     not immediately think of.

The engine reuses the same LLM provider/model configured for the main scan.
"""
from __future__ import annotations

import html as _html_module
import json
import os
import re
import sys
from typing import Optional, TYPE_CHECKING

from rich.console import Console
from rich.rule import Rule

if TYPE_CHECKING:
    from wscan.payload_gen import PayloadGenerator

console = Console()


# ---------------------------------------------------------------------------
# Check-type descriptors — give the LLM more context about the vuln type
# ---------------------------------------------------------------------------

_CHECK_DESCRIPTIONS: dict[str, str] = {
    "xss": (
        "Cross-Site Scripting — injecting HTML/JS so it executes in a victim's browser. "
        "Techniques: event handlers, SVG/IMG tags, script tags, javascript: URIs, "
        "attribute injection, DOM sinks, encoding bypasses."
    ),
    "sqli": (
        "SQL Injection — injecting SQL syntax to manipulate backend database queries. "
        "Techniques: UNION-based, blind boolean/time-based, error-based, "
        "stacked queries, second-order injection, WAF bypasses via comments/whitespace."
    ),
    "os": (
        "OS Command Injection — injecting shell meta-characters to run OS commands. "
        "Techniques: ; | && || $() backticks, newline injection, env var expansion, "
        "encoded separators, blind OOB exfiltration via DNS/HTTP."
    ),
    "ssti": (
        "Server-Side Template Injection — injecting template engine syntax that the "
        "server evaluates. Techniques: Jinja2 {{7*7}}, Twig, Freemarker, Smarty, "
        "Velocity, Mako, Pebble, Thymeleaf. Try multiple engines' syntax."
    ),
    "path_traversal": (
        "Path/Directory Traversal — traversing the file system via ../ sequences "
        "to read arbitrary files. Techniques: double-dot variants, URL/unicode encoding, "
        "null byte termination, zip/archive path injection."
    ),
    "header_injection": (
        "HTTP Header Injection — injecting CRLF (\\r\\n) sequences to split HTTP headers. "
        "Techniques: URL-encoded CRLF, Unicode CRLF variants, response splitting."
    ),
    "open_redirect": (
        "Open Redirect — crafting a URL that redirects to an attacker-controlled host. "
        "Techniques: protocol-relative //evil.com, javascript: URI, data: URI, "
        "@-trick user:pass@host, tab/newline chars to bypass validation."
    ),
}


# ---------------------------------------------------------------------------
# Adaptive prompt template
# ---------------------------------------------------------------------------

_ADAPTIVE_PROMPT = """\
You are a world-class web application penetration tester and CTF expert.
You just ran a standard payload scan on a form field and found no confirmed vulnerability.
Now analyse the application's filtering behavior and generate advanced bypass payloads.

## Target
URL: {url}
Field name: {field_name}
Vulnerability type: {check_type}

## Vulnerability description
{check_desc}

## Standard payloads already tried (no hit found):
{payloads_tried}

## Page HTML after last probe (first 5000 chars):
```html
{page_excerpt}
```

## Your observations about the application's behavior:
{observations}

## Your task
Based on the HTML above, deduce HOW the application filters input:
- Are `<` `>` being HTML-entity-encoded?
- Are quotes `'` `"` being escaped?
- Are certain keywords (e.g. "script", "alert", "SELECT") being stripped or blocked?
- What is the injection context? (HTML body? attribute value? JavaScript string? CSS?)
- What framework/template engine might be in use?

Then generate 5-10 ADVANCED BYPASS payloads that a human might NOT immediately think of.
Focus on:
1. Encoding bypasses: unicode escapes \\uXXXX, hex \\xXX, base64, URL-encoding, HTML entities
2. Context-aware injection: if inside a JS string → break it; if in an attribute → escape the attr
3. WAF evasion: case variation, null bytes, comments /**, HTML comments, unusual whitespace
4. Polyglot payloads that work across multiple injection contexts
5. Alternative event handlers, tags, or sinks beyond the common ones
6. Template syntax for multiple engines simultaneously

Output ONLY the payloads — one per line, no numbering, no explanation, no backticks.
Each line must be a single ready-to-inject string.
"""


# ---------------------------------------------------------------------------
# Observation builder
# ---------------------------------------------------------------------------

def _build_observations(page_html: str, payloads_tried: list[str]) -> str:
    """
    Analyse the page HTML to infer sanitization behavior.
    Returns a human-readable observations string for the LLM prompt.
    """
    obs: list[str] = []
    sample = page_html[:8000].lower()

    # HTML entity encoding
    if "&lt;" in sample or "&gt;" in sample or "&amp;" in sample:
        obs.append("- HTML entity encoding detected: '<' and '>' are being encoded to &lt; &gt;")
    if "&#x" in sample or "&#" in sample:
        obs.append("- Numeric HTML entity encoding detected (&#xNN; or &#NN;)")

    # Quote escaping
    if "\\'" in page_html[:8000] or '\\"' in page_html[:8000]:
        obs.append("- Quote escaping detected: quotes appear backslash-escaped in the response")
    if "&quot;" in sample or "&#39;" in sample:
        obs.append("- HTML-encoded quotes detected (&quot; or &#39;)")

    # Common keyword stripping
    for kw in ["<script", "onerror", "onclick", "onload", "javascript:", "alert(", "eval("]:
        # Check if the keyword was tried but stripped (not in response)
        for p in payloads_tried[:10]:
            if kw.lower() in p.lower() and kw.lower() not in sample:
                obs.append(f"- Keyword '{kw}' appears to be stripped from output (not reflected)")
                break

    # Reflection check — does anything from our payloads appear in the page?
    reflected: list[str] = []
    for p in payloads_tried[:5]:
        # Check for partial reflection of distinctive fragments
        for fragment in [p[:6], p[:10]]:
            if len(fragment) > 3 and fragment.lower() in sample:
                reflected.append(fragment)
                break
    if reflected:
        obs.append(f"- Partial reflection detected — these fragments appeared in the page: {reflected[:3]}")
    else:
        obs.append("- No clear payload reflection found in the response (application may be blocking silently)")

    # Context detection
    if 'value="' in sample or "value='" in sample:
        obs.append("- Input field 'value' attribute context detected — injection may be inside an HTML attribute")
    if "<script" in sample:
        obs.append("- JavaScript context present in the page — injection into existing JS blocks may be possible")
    if "{{" in page_html[:8000] or "{%" in page_html[:8000]:
        obs.append("- Template delimiters {{ or {% found — template injection may be viable")

    # Error messages
    for err in ["sql", "mysql", "sqlite", "postgresql", "odbc", "ora-", "syntax error",
                "undefined variable", "traceback", "exception"]:
        if err in sample:
            obs.append(f"- Error/stack trace hint detected ('{err}' found in response) — application is leaking debug info")
            break

    if not obs:
        obs.append("- No obvious sanitization artifacts detected in the page HTML")

    return "\n".join(obs)


# ---------------------------------------------------------------------------
# Payload output parser
# ---------------------------------------------------------------------------

def _parse_payload_lines(text: str, already_tried: list[str]) -> list[str]:
    """
    Parse LLM output — one payload per line.
    Filter out empty lines, prose, and duplicates of already-tried payloads.
    """
    tried_set = set(p.strip() for p in already_tried)
    result: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Skip obvious prose/explanation lines
        if len(line) > 200:
            continue
        # Skip lines that look like numbered list items without a payload
        if re.match(r"^\d+\.\s*$", line):
            continue
        # Skip lines that are pure prose (no special chars typical of payloads)
        if re.match(r"^[A-Za-z][a-z ]+:?\s*$", line) and len(line) > 20:
            continue
        # Remove leading numbering like "1. " or "- "
        line = re.sub(r"^[\d]+[\.\)]\s+", "", line)
        line = re.sub(r"^[-*]\s+", "", line)
        if line and line not in tried_set:
            result.append(line)
    return list(dict.fromkeys(result))  # unique, order-preserving


# ---------------------------------------------------------------------------
# Adaptive Payload Engine
# ---------------------------------------------------------------------------

class AdaptivePayloadEngine:
    """
    Observes probe responses and asks the LLM to generate creative bypass payloads.
    Reuses the same LLM provider configured in PayloadGenerator.
    """

    def __init__(self, payload_gen: "PayloadGenerator"):
        self.pg = payload_gen

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def generate(
        self,
        check_type: str,
        field_name: str,
        url: str,
        payloads_tried: list[str],
        page_html: str,
    ) -> list[str]:
        """
        Analyse the page HTML and generate adaptive bypass payloads.
        Returns an empty list if LLM is unavailable.
        """
        if self.pg.provider == "none":
            return []
        if not await self.pg._check_llm_available():
            return []

        check_desc = _CHECK_DESCRIPTIONS.get(check_type, check_type)
        observations = _build_observations(page_html, payloads_tried)
        payloads_list = "\n".join(f"  {p}" for p in payloads_tried[:30]) or "  (none recorded)"
        page_excerpt = page_html[:5000].replace("```", "'''")

        prompt = _ADAPTIVE_PROMPT.format(
            url=url,
            field_name=field_name,
            check_type=check_type,
            check_desc=check_desc,
            payloads_tried=payloads_list,
            page_excerpt=page_excerpt,
            observations=observations,
        )

        provider = self.pg.provider
        _adaptive_header(check_type, field_name, provider)

        raw: Optional[str] = None
        if provider == "claude":
            raw = await self._stream_claude(prompt)
        elif provider == "openai":
            raw = await self._stream_openai(prompt)
        elif provider == "gemini":
            raw = await self._call_gemini(prompt)
        else:
            raw = await self._stream_ollama(prompt)

        _adaptive_footer()

        if not raw:
            return []

        payloads = _parse_payload_lines(raw, payloads_tried)
        if payloads:
            console.print(
                f"  [bold magenta][AdaptiveAI][/bold magenta] "
                f"Generated [cyan]{len(payloads)}[/cyan] bypass payload(s) for "
                f"[green]{field_name}[/green] ({check_type})"
            )
        return payloads

    # ------------------------------------------------------------------
    # Streaming backends
    # ------------------------------------------------------------------

    async def _stream_ollama(self, prompt: str) -> Optional[str]:
        import httpx
        full = ""
        try:
            async with httpx.AsyncClient(timeout=90.0) as client:
                async with client.stream(
                    "POST",
                    f"{self.pg.ollama_url}/api/generate",
                    json={
                        "model": self.pg.ollama_model,
                        "prompt": prompt,
                        "stream": True,
                        "options": {"temperature": 0.8, "num_predict": 1000},
                    },
                ) as resp:
                    if resp.status_code != 200:
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
            return full or None
        except Exception as e:
            console.print(f"[yellow][AdaptiveAI] Ollama error: {e}[/yellow]")
            return None

    async def _stream_openai(self, prompt: str) -> Optional[str]:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            return None
        import httpx
        full = ""
        try:
            async with httpx.AsyncClient(timeout=90.0) as client:
                async with client.stream(
                    "POST",
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {api_key}"},
                    json={
                        "model": self.pg.openai_model,
                        "messages": [{"role": "user", "content": prompt}],
                        "max_tokens": 1000,
                        "temperature": 0.8,
                        "stream": True,
                    },
                ) as resp:
                    if resp.status_code != 200:
                        console.print(f"[yellow][AdaptiveAI] OpenAI error {resp.status_code}[/yellow]")
                        return None
                    async for line in resp.aiter_lines():
                        if not line or not line.startswith("data:"):
                            continue
                        data_str = line[5:].strip()
                        if data_str == "[DONE]":
                            break
                        try:
                            data = json.loads(data_str)
                            chunk = (
                                data.get("choices", [{}])[0]
                                .get("delta", {})
                                .get("content", "")
                            )
                            if chunk:
                                sys.stdout.write(chunk)
                                sys.stdout.flush()
                                full += chunk
                        except (json.JSONDecodeError, IndexError, KeyError):
                            pass
            return full or None
        except Exception as e:
            console.print(f"[yellow][AdaptiveAI] OpenAI error: {e}[/yellow]")
            return None

    async def _stream_claude(self, prompt: str) -> Optional[str]:
        client = self.pg._get_anthropic_client()
        if not client:
            return None
        import asyncio
        full = ""
        try:
            def _stream_sync():
                nonlocal full
                with client.messages.stream(
                    model="claude-haiku-4-5-20251001",
                    max_tokens=1000,
                    messages=[{"role": "user", "content": prompt}],
                ) as stream:
                    for chunk in stream.text_stream:
                        sys.stdout.write(chunk)
                        sys.stdout.flush()
                        full += chunk
                return full

            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, _stream_sync)
            return full or None
        except Exception as e:
            console.print(f"[yellow][AdaptiveAI] Claude error: {e}[/yellow]")
            return None

    async def _call_gemini(self, prompt: str) -> Optional[str]:
        """Gemini (non-streaming — prints full response after completion)."""
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            return None
        import httpx
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                url = (
                    f"https://generativelanguage.googleapis.com/v1beta/models/"
                    f"{self.pg.gemini_model}:generateContent?key={api_key}"
                )
                resp = await client.post(
                    url,
                    json={"contents": [{"parts": [{"text": prompt}]}]},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    text = data["candidates"][0]["content"]["parts"][0]["text"]
                    sys.stdout.write(text)
                    sys.stdout.flush()
                    return text
                console.print(f"[yellow][AdaptiveAI] Gemini error {resp.status_code}[/yellow]")
        except Exception as e:
            console.print(f"[yellow][AdaptiveAI] Gemini error: {e}[/yellow]")
        return None


# ---------------------------------------------------------------------------
# Visual helpers
# ---------------------------------------------------------------------------

def _adaptive_header(check_type: str, field_name: str, provider: str) -> None:
    console.print()
    console.print(Rule(
        f"[bold magenta] 🧠 AdaptiveAI — {check_type.upper()} bypass for '{field_name}' "
        f"({provider}) ",
        style="magenta",
    ))
    console.print()


def _adaptive_footer() -> None:
    console.print()
    console.print(Rule(style="magenta"))
    console.print()
