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
from urllib.parse import urlparse
import httpx

_TIMEOUT = 20.0
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; wscan-llm/1.0; security-research-tool)"
    )
}

# DuckDuckGo "lite" HTML endpoint — works without JS or API key
_DDG_ENDPOINT = "https://html.duckduckgo.com/html/"


# 匿名化はブロックリスト（危険な形を列挙）ではなくアローリストで行う。URL 文法（host/path/
# port/query/fragment）は多様で列挙しきれない（Codex が同一関数で host→path/port→相対 path と
# 3度指摘）。逆に「素のプレーンな技術語トークンだけ通す」＝URL 構造文字（. : / @ ? # 等）を含む
# トークンは構造的に全て弾く、という安全側の設計にする。`C#`/`C++`/`ASP-NET` 等は許容、
# `Node.js`/`ASP.NET` はドットで巻き込まれ落ちる（over-strip 許容）。`#`/`+` は末尾のみ許可＝
# `C#`/`C++`/`F#` は通すが、SPA の複合ハッシュルート `app#tenant-42`（中間に `#`）は弾く。
_WEB_QUERY_TECH_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*[#+]*$")


def _known_target_identifiers(
    target_url: str,
) -> tuple[frozenset[str], frozenset[str]]:
    """既知の検査対象 URL から、クエリから除くべき識別子（host・host:port・IP）を抽出。

    ヒューリスティックでは捕まらない単一ラベルの内部 host（例 `intranet`）や、区切り無しで
    現れる path/query/fragment 由来の識別子（例 `tenant-42`、SPA hash route）も、対象が既知なら確実に落とせる。

    返り値は `(host_ids, exact_ids)`:
      - `host_ids`  … host・host:port。subdomain/port 付きも拾うため **部分一致**で使う。
      - `exact_ids` … path segment・query の key/値・fragment route。一般語の巻き込みを避け **完全一致**で使う。
    いずれも純粋・小文字正規化。"""
    empty: tuple[frozenset[str], frozenset[str]] = (frozenset(), frozenset())
    if not target_url:
        return empty
    host_ids: set[str] = set()
    exact_ids: set[str] = set()
    try:
        parsed = urlparse(target_url if "://" in target_url else "//" + target_url, scheme="")
        host = (parsed.hostname or "").strip().lower()
        if len(host) >= 2:
            host_ids.add(host)
            if parsed.port:
                host_ids.add(f"{host}:{parsed.port}")
        for seg in (parsed.path or "").split("/"):
            seg = seg.strip().lower()
            if len(seg) >= 2:
                exact_ids.add(seg)  # 対象固有の path segment（tenant-42 等）
        from urllib.parse import parse_qsl
        for key, val in parse_qsl(parsed.query or "", keep_blank_values=False):
            for token in (key, val):
                token = token.strip().lower()
                if len(token) >= 2:
                    exact_ids.add(token)  # 対象固有の query 識別子
        # fragment（SPA の hash-router `#/`・`#!/` 由来の route も対象固有識別子）
        frag = (parsed.fragment or "").lstrip("#!/")
        for seg in frag.replace("?", "/").replace("&", "/").split("/"):
            seg = seg.strip().lower()
            if len(seg) >= 2:
                exact_ids.add(seg)
    except Exception:
        return empty
    return (frozenset(host_ids), frozenset(exact_ids))


def build_planner_web_query(tech_hints: str, target_url: str = "") -> str:
    """planner の web intel クエリを組む（純粋・匿名化）。

    LLM-007: 検査対象の host/URL/path を外部検索へ送らない。tech_hints は untrusted な
    ページ title を含みうるため二段構えで落とす:
      (1) 既知の対象 host / path segment / query 識別子（`target_url` 由来）を明示 redact
          — 単一ラベル host も、区切り無しで現れる path/query 値（tenant-42 等）も確実に。
      (2) アローリスト: 素のプレーンな技術語トークンだけ通す。URL 構造文字（. : / @ ? # 等）を
          含むトークンは構造的に全て弾く＝host/path/port/query/fragment を一括で除去（安全側）。
    """
    host_ids, exact_ids = _known_target_identifiers(target_url)
    safe: list[str] = []
    for tok in (tech_hints or "").split():
        low = tok.lower()
        if host_ids and any(h in low for h in host_ids):
            continue  # 既知の対象 host/host:port を含むトークンは落とす（部分一致）
        if low in exact_ids:
            continue  # 既知の対象 path segment / query 識別子（区切り無しの tenant-42 等）
        if not _WEB_QUERY_TECH_TOKEN.match(tok):
            continue  # URL 構造文字を含む（host/path/port/query/fragment）トークンは弾く
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
