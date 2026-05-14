"""
Subresource Integrity (SRI) Audit Scanner.

Flags ``<script src="https://cdn…/x.js">`` and ``<link rel="stylesheet"
href="https://cdn…/x.css">`` tags whose resource is loaded from a third-party
origin without an ``integrity`` attribute.  Without SRI a compromise of the
third-party CDN — or a network attacker on an unencrypted hop — can replace
the script with arbitrary JavaScript that then runs in the application's
origin (supply-chain XSS / RCE-in-browser).

Page-level scan: examines the parsed DOM after navigation and reports each
distinct unprotected third-party resource exactly once per page.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# Conservative list of CDNs we know serve untrusted third-party content.
# Membership is NOT required for a finding — any cross-origin script counts —
# but matching one of these raises severity from "low" to "medium".
_KNOWN_CDN_HOSTS = (
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "ajax.googleapis.com",
    "code.jquery.com",
    "maxcdn.bootstrapcdn.com",
    "stackpath.bootstrapcdn.com",
    "cdn.bootcss.com",
    "cdn.skypack.dev",
    "esm.sh",
)


_SCRIPT_TAG_RE = re.compile(
    r"<script\b([^>]*)>",
    re.IGNORECASE,
)
_LINK_TAG_RE = re.compile(
    r"<link\b([^>]*)>",
    re.IGNORECASE,
)
_ATTR_RE = re.compile(
    r"""(?P<name>[A-Za-z_:][A-Za-z0-9_.:-]*)\s*=\s*(?P<quote>['"])(?P<value>.*?)(?P=quote)""",
    re.DOTALL,
)


def _parse_attrs(attr_blob: str) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for match in _ATTR_RE.finditer(attr_blob):
        attrs[match.group("name").lower()] = match.group("value")
    return attrs


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def find_unprotected_externals(html: str, page_url: str) -> list[dict]:
    """
    Return a list of unprotected cross-origin scripts/stylesheets in ``html``.

    Each item has: ``tag`` (script/link), ``src``, ``host``, ``is_known_cdn``,
    ``has_crossorigin``.
    """
    if not html:
        return []
    page_host = _host_of(page_url)
    results: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def _process(tag: str, attrs: dict[str, str], src_attr: str) -> None:
        src = (attrs.get(src_attr) or "").strip()
        if not src:
            return
        # Skip inline / data: / javascript: / protocol-relative blanks.
        if src.startswith(("data:", "javascript:", "about:", "#")):
            return
        absolute = urljoin(page_url, src)
        host = _host_of(absolute)
        if not host or host == page_host:
            return  # same origin — SRI not required
        if "integrity" in attrs and attrs["integrity"].strip():
            return  # protected
        key = (tag, absolute)
        if key in seen:
            return
        seen.add(key)
        results.append(
            {
                "tag": tag,
                "src": absolute,
                "host": host,
                "is_known_cdn": host in _KNOWN_CDN_HOSTS,
                "has_crossorigin": "crossorigin" in attrs,
            }
        )

    for match in _SCRIPT_TAG_RE.finditer(html):
        attrs = _parse_attrs(match.group(1))
        _process("script", attrs, "src")

    for match in _LINK_TAG_RE.finditer(html):
        attrs = _parse_attrs(match.group(1))
        rel = (attrs.get("rel") or "").lower()
        # Stylesheets and preloaded scripts/styles need SRI; ignore other rels
        # (icon, dns-prefetch, preconnect, manifest, ...).
        if rel == "stylesheet" or (
            rel == "preload" and (attrs.get("as", "").lower() in {"script", "style"})
        ):
            _process("link", attrs, "href")

    return results


class SRIScanner(BaseScanner):
    """Audit third-party <script>/<link> tags missing ``integrity`` attribute."""

    CHECK_TYPE = "sri"
    SEVERITY = "medium"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._checked_urls: set[str] = set()

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        return []

    async def scan_page(self, url: str) -> list[Finding]:
        if url in self._checked_urls:
            return []
        self._checked_urls.add(url)

        if self.monitor:
            await self.monitor.emit_status(f"SRI audit on {url}")

        pair = self.current_page_pair(url)
        body = pair.get("response", {}).get("body", "") or ""
        if not body:
            try:
                body = await self.browser.page.content()
            except Exception:
                body = ""
        if not body:
            return []

        findings: list[Finding] = []
        for hit in find_unprotected_externals(body, url):
            severity = "medium" if hit["is_known_cdn"] else "low"
            finding = await self.record_finding(
                url=url,
                field_name=f"({hit['tag']} src)",
                payload="(no payload — DOM audit)",
                evidence=(
                    f"Third-party <{hit['tag']}> from {hit['host']} loaded without "
                    f"an integrity attribute: {hit['src']}"
                ),
                pair=pair,
                severity=severity,
                confidence="confirmed",
                evidence_type="sri_missing",
                evidence_details={
                    "tag": hit["tag"],
                    "src": hit["src"],
                    "host": hit["host"],
                    "is_known_cdn": hit["is_known_cdn"],
                    "has_crossorigin": hit["has_crossorigin"],
                },
                reproduction_steps=[
                    f"Open {url}",
                    "View the page source",
                    f"Find the <{hit['tag']}> element loading {hit['src']}",
                    "Confirm it has no integrity= hash, then add a SHA-384 SRI hash"
                    " (and crossorigin=\"anonymous\" for scripts).",
                ],
            )
            if finding is not None:
                findings.append(finding)
        return findings
