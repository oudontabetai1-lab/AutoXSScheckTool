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
from urllib.parse import urljoin

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

    def _probe_by_filename(self, filename: str) -> tuple[str, bytes, str] | None:
        for probe in _PROBE_FILES:
            if probe[0] == filename:
                return probe
        return None

    async def _form_action_url(self, page_url: str, form_index: int) -> str:
        try:
            await self.browser.navigate(page_url)
            action = await self.browser.page.evaluate(
                """
                ([formIndex]) => {
                    const form = document.querySelectorAll('form')[formIndex];
                    return form ? (form.action || window.location.href) : window.location.href;
                }
                """,
                [form_index],
            )
            return urljoin(page_url, action or page_url)
        except Exception:
            return page_url

    async def _upload_file(
        self,
        url: str,
        field_name: str,
        filename: str,
        content: bytes,
    ) -> tuple[str, int, dict]:
        timeout = getattr(self.engine, "timeout", 15)
        client_kwargs: dict = {
            "timeout": timeout,
            "follow_redirects": True,
        }
        if hasattr(self.engine, "httpx_client_kwargs"):
            client_kwargs = self.engine.httpx_client_kwargs(**client_kwargs)
        elif getattr(self.engine, "proxy", ""):
            client_kwargs["proxy"] = getattr(self.engine, "proxy", "")
            client_kwargs["verify"] = False
        if hasattr(self.engine, "auth_headers"):
            client_kwargs["headers"] = self.engine.auth_headers()

        request_kwargs = {
            "files": {field_name: (filename, io.BytesIO(content), "image/jpeg")},
        }
        async with httpx.AsyncClient(**client_kwargs) as client:
            response = await client.post(url, **request_kwargs)
        pair = {
            "request": {"url": url, "method": "POST", "filename": filename},
            "response": {"status": response.status_code, "body": response.text[:1000]},
        }
        return response.text, response.status_code, pair

    def _classify(
        self,
        body: str,
        status_code: int,
        filename: str,
        description: str,
    ) -> tuple[str, str, str, dict] | None:
        if _SHELL_ECHO_RE.search(body or ""):
            return (
                "file_upload_executable",
                "critical",
                (
                    f"File upload: uploaded file was executed as code — "
                    f"server returned probe output. Filename: {filename!r}. "
                    f"Description: {description}."
                ),
                {"filename": filename, "description": description},
            )
        if status_code in (200, 201) and _SUCCESS_RE.search(body or ""):
            return (
                "file_upload_dangerous_accept",
                "high",
                (
                    f"File upload: server accepted {description} ({filename!r}) "
                    f"without rejection. Verify whether the file is accessible/executable."
                ),
                {"filename": filename, "description": description},
            )
        return None

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
        action_url = await self._form_action_url(url, form_index)

        for filename, content, description in _PROBE_FILES:
            # log_payload_test(field_name, payload, check_type, url)
            await self.log_payload_test(
                field_name, filename, self.CHECK_TYPE, url
            )
            try:
                body, status_code, pair = await self._upload_file(
                    action_url, field_name, filename, content
                )

            except Exception as exc:
                if self.monitor:
                    await self.monitor.emit_status(
                        f"[warn] file_upload: request failed on {url}: {exc}"
                    )
                continue

            classified = self._classify(body, status_code, filename, description)

            if classified:
                evidence_type, severity, evidence, evidence_details = classified
                finding = await self.record_finding(
                    url=action_url,
                    field_name=field_name,
                    payload=filename,
                    evidence=evidence,
                    pair=pair,
                    severity=severity,
                    confidence="likely",
                    evidence_type=evidence_type,
                    evidence_details=evidence_details,
                )
                findings.append(finding)
                break

        return findings

    async def scan_page(self, url: str) -> list[Finding]:
        return []

    async def verify_finding(self, finding: Finding) -> bool | None:
        probe = self._probe_by_filename(finding.payload)
        if not probe:
            return None
        filename, content, description = probe
        try:
            body, status_code, _pair = await self._upload_file(
                finding.url,
                finding.field_name,
                filename,
                content,
            )
        except Exception:
            return None
        classified = self._classify(body, status_code, filename, description)
        return bool(classified and classified[0] == finding.evidence_type)
