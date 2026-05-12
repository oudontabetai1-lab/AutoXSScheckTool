"""
File Upload Vulnerability Scanner
Detects insecure file upload endpoints that allow:
  1. Uploading web shells (PHP/JSP/ASP) disguised as images
  2. Unrestricted MIME type acceptance
  3. Double-extension bypass (shell.php.jpg)
  4. Path traversal in filename parameter
"""
import io
import re
from typing import TYPE_CHECKING

import httpx

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine

# Minimal PHP webshell as bytes (the string "<?php echo shell_exec($_GET['c']);?>"
# is clearly harmful only if served; here it functions as a probe to test whether
# the server rejects it or stores it).
_PHP_SHELL_CONTENT = b"<?php echo 'wscan-probe-' . phpversion(); ?>"
_JSP_SHELL_CONTENT = b'<% out.print("wscan-probe-jsp"); %>'

_PROBE_FILES: list[tuple[str, bytes, str]] = [
    # (filename, content, description)
    ("wscan_probe.php",         _PHP_SHELL_CONTENT, "PHP file upload"),
    ("wscan_probe.php.jpg",     _PHP_SHELL_CONTENT, "double-extension PHP"),
    ("wscan_probe.phtml",       _PHP_SHELL_CONTENT, "phtml extension bypass"),
    ("wscan_probe.jsp",         _JSP_SHELL_CONTENT, "JSP file upload"),
    ("../wscan_probe.php",      _PHP_SHELL_CONTENT, "path traversal in filename"),
    ("wscan\x00probe.php",      _PHP_SHELL_CONTENT, "null byte extension bypass"),
    ("wscan_probe.php%00.jpg",  _PHP_SHELL_CONTENT, "URL-encoded null byte bypass"),
]

_UPLOAD_FIELD_NAMES = re.compile(
    r"(?:file|upload|image|photo|avatar|attachment|document|picture|media)",
    re.IGNORECASE,
)
_SUCCESS_RE = re.compile(
    r"(?:upload(?:ed|ing)?|success|saved|stored|file\s+received)",
    re.IGNORECASE,
)
_SHELL_ECHO_RE = re.compile(r"wscan-probe-(?:jsp|\d+\.\d+)", re.IGNORECASE)


def _is_upload_field(field: dict) -> bool:
    ftype = (field.get("type") or "").lower()
    name = (field.get("name") or field.get("id") or "").lower()
    return ftype == "file" or bool(_UPLOAD_FIELD_NAMES.search(name))


class FileUploadScanner(BaseScanner):
    """Insecure file upload vulnerability scanner."""

    CHECK_TYPE = "file_upload"
    SEVERITY = "critical"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._checked_forms: set[tuple] = set()

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        if is_url_param or not _is_upload_field(field):
            return []

        key = (url, form_index)
        if key in self._checked_forms:
            return []
        self._checked_forms.add(key)

        field_name = field.get("name") or field.get("id") or "file"
        findings: list[Finding] = []

        proxy = getattr(self.engine, "proxy", "") or None
        timeout = getattr(self.engine, "timeout", 15)

        for filename, content, description in _PROBE_FILES:
            if self.monitor:
                await self.monitor.emit_payload_test(
                    url, field_name, filename, self.CHECK_TYPE
                )
            try:
                request_kwargs: dict = {
                    "files": {field_name: (filename, io.BytesIO(content), "image/jpeg")},
                }
                client_kwargs: dict = {
                    "timeout": timeout,
                    "follow_redirects": True,
                    "verify": False,
                }
                if proxy:
                    client_kwargs["proxy"] = proxy

                async with httpx.AsyncClient(**client_kwargs) as client:
                    r = await client.post(url, **request_kwargs)
                body = r.text

            except Exception as exc:
                if self.monitor:
                    await self.monitor.emit_status(
                        f"[warn] file_upload: request failed on {url}: {exc}"
                    )
                continue

            severity = "critical"
            evidence = None

            if _SHELL_ECHO_RE.search(body):
                evidence = (
                    f"File upload: uploaded file was executed as code — "
                    f"server returned probe output. Filename: {filename!r}. "
                    f"Description: {description}."
                )
                severity = "critical"
            elif r.status_code in (200, 201) and _SUCCESS_RE.search(body):
                evidence = (
                    f"File upload: server accepted {description} ({filename!r}) "
                    f"without rejection. Verify whether the file is accessible/executable."
                )
                severity = "high"

            if evidence:
                finding = await self.record_finding(
                    url=url,
                    field_name=field_name,
                    payload=filename,
                    evidence=evidence,
                    pair={
                        "request": {"url": url, "method": "POST", "filename": filename},
                        "response": {"status": r.status_code, "body": body[:1000]},
                    },
                    severity=severity,
                )
                findings.append(finding)

        return findings

    async def scan_page(self, url: str) -> list[Finding]:
        return []
