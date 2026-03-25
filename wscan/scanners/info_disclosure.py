"""
Information Disclosure / Sensitive File Exposure Scanner (V-3)
Checks for:
  1. Accessible sensitive files/directories (.env, .git, phpinfo, backup files, etc.)
  2. Technology stack leakage in HTTP response headers (Server, X-Powered-By, etc.)
  3. Verbose error page patterns that reveal framework/DB details
"""
import re
import httpx
from urllib.parse import urljoin, urlparse
from typing import TYPE_CHECKING

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine

# Paths that should never be publicly accessible
_SENSITIVE_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/.git/HEAD",
    "/.git/config",
    "/.svn/entries",
    "/.DS_Store",
    "/web.config",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/backup.zip",
    "/backup.tar.gz",
    "/backup.sql",
    "/db.sql",
    "/dump.sql",
    "/database.sql",
    "/wp-config.php.bak",
    "/config.php.bak",
    "/application.log",
    "/error.log",
    "/debug.log",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/mappings",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/v2/api-docs",
    "/.well-known/security.txt",
    "/crossdomain.xml",
    "/elmah.axd",
    "/trace.axd",
    "/server-status",
    "/server-info",
]

# Patterns that confirm a sensitive file was actually served (not a 404 page)
_CONTENT_PATTERNS: dict[str, str] = {
    r"DB_PASSWORD|DB_HOST|APP_KEY|SECRET_KEY|AWS_SECRET":       ".env file content",
    r"\[core\]\s*repositoryformatversion":                      ".git config content",
    r"<title>phpinfo\(\)</title>":                              "phpinfo() output",
    r"root:.*:/bin/(?:bash|sh)":                                "/etc/passwd content",
    r"(?i)fatal\s+error.*on\s+line\s+\d+":                     "PHP fatal error with stack trace",
    r"(?i)at\s+[\w\.]+\([\w\.]+\.java:\d+\)":                  "Java stack trace",
    r"(?i)Traceback \(most recent call last\)":                 "Python traceback",
    r"(?i)microsoft.*ole.*db.*provider.*error":                 "MSSQL OLE DB error",
    r"(?i)syntax error.*near.*line \d+":                        "SQL syntax error",
    r"(?i)(mysql|postgresql|sqlite|oracle)\s+error":            "Database error",
}

# Headers that reveal technology stack
_TECH_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-joomla-cache",
]


class InfoDisclosureScanner(BaseScanner):
    """Sensitive file exposure and information disclosure scanner."""

    CHECK_TYPE = "info_disclosure"
    SEVERITY = "medium"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._checked_origins: set[str] = set()

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        return []

    async def scan_page(self, url: str) -> list[Finding]:
        """Run all disclosure checks once per origin."""
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        if origin in self._checked_origins:
            return await self._check_error_page(url)
        self._checked_origins.add(origin)

        findings = []
        findings += await self._check_sensitive_files(origin)
        findings += await self._check_tech_headers(url)
        findings += await self._check_error_page(url)
        return findings

    # ------------------------------------------------------------------

    async def _check_sensitive_files(self, origin: str) -> list[Finding]:
        """Probe well-known sensitive paths on the server origin."""
        findings = []
        proxy = getattr(self.engine, "proxy", "") or None
        timeout = getattr(self.engine, "timeout", 15)

        kwargs: dict = {
            "timeout": timeout,
            "follow_redirects": False,
        }
        if proxy:
            kwargs["proxy"] = proxy

        if self.monitor:
            await self.monitor.emit_status(
                f"Info disclosure: probing sensitive files on {origin}"
            )

        async with httpx.AsyncClient(**kwargs) as client:
            for path in _SENSITIVE_PATHS:
                target = urljoin(origin, path)
                try:
                    r = await client.get(target)
                    if r.status_code not in (200, 206):
                        continue
                    body = r.text[:4000]

                    # Confirm by content pattern or small non-HTML response
                    matched_label = None
                    for pattern, label in _CONTENT_PATTERNS.items():
                        if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
                            matched_label = label
                            break

                    # Fallback: if Content-Type is not HTML and body is non-empty
                    ct = r.headers.get("content-type", "")
                    if matched_label is None and "html" not in ct and len(body.strip()) > 20:
                        matched_label = "non-HTML content (possible sensitive file)"

                    if matched_label is None:
                        continue

                    severity = "critical" if ".env" in path or ".git" in path else "high"
                    pair = {
                        "request": {"url": target},
                        "response": {
                            "status": r.status_code,
                            "headers": dict(r.headers),
                            "body": body,
                        },
                    }
                    finding = await self.record_finding(
                        url=target,
                        field_name="(sensitive file/directory)",
                        payload="(GET request — no payload)",
                        evidence=(
                            f"Sensitive resource accessible: {path} "
                            f"→ HTTP {r.status_code} — {matched_label}"
                        ),
                        pair=pair,
                        severity=severity,
                    )
                    findings.append(finding)

                except Exception:
                    continue

        return findings

    async def _check_tech_headers(self, url: str) -> list[Finding]:
        """Check response headers for technology version disclosure."""
        pair = self.browser.network.latest() or {}
        resp_headers = {
            k.lower(): v
            for k, v in pair.get("response", {}).get("headers", {}).items()
        }

        exposed = []
        for header in _TECH_HEADERS:
            value = resp_headers.get(header, "")
            if value:
                exposed.append(f"{header}: {value}")

        if not exposed:
            return []

        finding = await self.record_finding(
            url=url,
            field_name="(HTTP response headers)",
            payload="(no payload — header analysis)",
            evidence=(
                "Technology stack disclosed via HTTP headers: "
                + "; ".join(exposed)
            ),
            pair=pair,
            severity="low",
        )
        return [finding]

    async def _check_error_page(self, url: str) -> list[Finding]:
        """Check current page HTML for verbose error / stack trace patterns."""
        try:
            source = await self.browser.page.content()
        except Exception:
            return []

        for pattern, label in _CONTENT_PATTERNS.items():
            if re.search(pattern, source, re.IGNORECASE | re.DOTALL):
                pair = self.browser.network.latest() or {}
                finding = await self.record_finding(
                    url=url,
                    field_name="(page HTML)",
                    payload="(no payload — page content analysis)",
                    evidence=f"Sensitive information in page: {label}",
                    pair=pair,
                    severity="medium",
                )
                return [finding]

        return []
