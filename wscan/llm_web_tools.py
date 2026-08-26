"""
Web Search & Fetch Tools for LLM-assisted vulnerability research.

When "LLM web browsing" is enabled, these utilities let the LLM enrich its
attack planning and payload generation with live intelligence:
  - Search DuckDuckGo for known vulnerabilities in the target technology
  - Fetch CVE / exploit-db / security advisory pages
  - Discover real-world bypass payloads for specific WAFs or frameworks

No API key is required.  All requests use httpx with standard async patterns.
"""
from __future__ import annotations

import re
import httpx

_TIMEOUT = 20.0
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; wscan-llm/1.0; security-research-tool)"
    )
}

# DuckDuckGo "lite" HTML endpoint — works without JS or API key
_DDG_ENDPOINT = "https://html.duckduckgo.com/html/"


_WEB_QUERY_URL_LIKE = re.compile(r"://|@")
_WEB_QUERY_IP_LIKE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
# ドットで連結された識別子（host.tld / a.b.c）。Node.js 等の技術名も巻き込むが、host 漏洩を
# 確実に防ぐため安全側で落とす（over-strip 許容）。
_WEB_QUERY_DOTTED = re.compile(r"^[\w-]+(?:\.[\w-]+)+$")


def build_planner_web_query(tech_hints: str) -> str:
    """planner の web intel クエリを組む（純粋・匿名化）。

    LLM-007: 検査対象の host/URL/IP を外部検索へ送らない。tech_hints は untrusted な
    ページ title を含みうるため、URL/host/IP らしきトークンを token 単位で除去してから
    汎用クエリを組む（安全側で over-strip する）。
    """
    safe: list[str] = []
    for tok in (tech_hints or "").split():
        bare = tok.strip(".,;:!?()[]{}\"'")
        if not bare:
            continue
        if (
            _WEB_QUERY_URL_LIKE.search(tok)
            or _WEB_QUERY_IP_LIKE.match(bare)
            or _WEB_QUERY_DOTTED.match(bare)
        ):
            continue  # host/URL/IP/dotted-identifier は落とす
        safe.append(tok)
    return ("web application vulnerability " + " ".join(safe)).strip()


async def search_web(query: str, max_results: int = 5) -> str:
    """
    Search DuckDuckGo and return top result titles + snippets as plain text.

    Returns a formatted string ready to inject into an LLM prompt.
    Returns an error string (never raises) so callers can always proceed.
    """
    try:
        async with httpx.AsyncClient(
            headers=_HEADERS, follow_redirects=True, timeout=_TIMEOUT
        ) as client:
            resp = await client.post(_DDG_ENDPOINT, data={"q": query})
            resp.raise_for_status()
            html = resp.text
    except Exception as exc:
        return f"[Web search unavailable: {exc}]"

    # --- Parse results with regex (no BeautifulSoup dependency) ----------
    # DDG HTML result links have class "result__a"
    # Snippets follow in class "result__snippet"
    link_pat = re.compile(
        r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
        re.DOTALL,
    )
    snip_pat = re.compile(
        r'class="result__snippet"[^>]*>(.*?)</(?:span|div)>',
        re.DOTALL,
    )

    links = [(m.group(1), re.sub(r"<[^>]+>", "", m.group(2)).strip())
             for m in link_pat.finditer(html)]
    snippets = [re.sub(r"<[^>]+>", "", m.group(1)).strip()
                for m in snip_pat.finditer(html)]

    lines: list[str] = []
    for i, ((url, title), snippet) in enumerate(
        zip(links[:max_results], snippets[:max_results]), 1
    ):
        lines.append(f"{i}. {title}\n   {url}\n   {snippet}")

    if not lines:
        return "[No results found]"
    return "\n\n".join(lines)


async def fetch_url(url: str, max_chars: int = 3000) -> str:
    """
    Fetch *url* and return its text content with HTML/JS/CSS stripped.

    Returns an error string (never raises).
    """
    try:
        async with httpx.AsyncClient(
            headers=_HEADERS, follow_redirects=True, timeout=_TIMEOUT
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            html = resp.text
    except Exception as exc:
        return f"[Fetch failed: {exc}]"

    # Strip script / style blocks first, then all tags
    text = re.sub(r"<script[^>]*>.*?</script>", " ", html, flags=re.DOTALL)
    text = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_chars]


async def research_vulnerability(check_type: str, context: str) -> str:
    """
    Convenience wrapper: search for known exploits / bypass techniques
    relevant to *check_type* in the given *context* (URL, technology, etc.).

    Returns a compact "Web Intelligence" block for inclusion in LLM prompts.
    """
    _SEARCH_QUERIES: dict[str, str] = {
        "xss":              "XSS bypass payload {ctx} site:portswigger.net OR site:owasp.org",
        "sqli":             "SQL injection bypass payload {ctx} site:exploit-db.com OR site:owasp.org",
        "ssti":             "SSTI template injection {ctx} bypass",
        "os":               "OS command injection payload {ctx}",
        "path_traversal":   "path traversal bypass {ctx}",
        "ssrf":             "SSRF bypass payload {ctx} cloud metadata",
        "open_redirect":    "open redirect bypass {ctx}",
        "csrf":             "CSRF bypass techniques {ctx}",
        "header_injection": "HTTP header injection bypass {ctx}",
    }
    query_template = _SEARCH_QUERIES.get(
        check_type,
        "{ctx} vulnerability exploit payload bypass",
    )
    query = query_template.replace("{ctx}", context[:80])
    results = await search_web(query, max_results=4)
    return (
        f"--- Web Intelligence ({check_type}) ---\n"
        f"Query: {query}\n\n"
        f"{results}\n"
        f"--- End Web Intelligence ---"
    )
