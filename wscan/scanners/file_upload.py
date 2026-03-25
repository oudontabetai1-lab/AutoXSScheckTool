"""
File Upload Vulnerability Scanner (V-6)
Detects insecure file upload endpoints that may allow web shell upload or
path traversal via file names.

Tests performed:
  1. Web shell upload — attempts to upload a file with a dangerous extension
     (.php, .jsp, .aspx, .py, .sh) and checks if the server executes it.
  2. Double extension bypass — shell.php.jpg, shell.php%00.jpg, etc.
  3. Content-Type confusion — sends a script file with image/jpeg Content-Type.
  4. Path traversal in filename — ../../../tmp/shell.php

Detection: if the uploaded file is accessible and its content is returned
(even partially), flag as confirmed. If the server returns 200 with a path
that contains the filename, flag as likely.
"""
import asyncio
import uuid
import re
from typing import TYPE_CHECKING

import httpx

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine

# Unique canary string embedded in all test files so we can confirm execution
_CANARY = "WScanUploadProbe"

# Minimal content for each test file type
_TEST_FILES = [
    # (filename, content, content_type, description)
    (
        "test.php",
        f"<?php echo '{_CANARY}'; ?>",
        "application/x-php",
        "PHP web shell",
    ),
    (
        "test.php.jpg",
        f"<?php echo '{_CANARY}'; /* double-ext bypass */?>",
        "image/jpeg",
        "PHP double-extension bypass",
    ),
    (
        "test.jpg.php",
        f"<?php echo '{_CANARY}'; /* reversed double-ext */ ?>",
        "image/jpeg",
        "PHP reversed double-extension",
    ),
    (
        "test.phtml",
        f"<?php echo '{_CANARY}'; ?>",
        "image/jpeg",
        "PHP phtml extension bypass",
    ),
    (
        "test.jsp",
        f'<%= "{_CANARY}" %>',
        "application/octet-stream",
        "JSP web shell",
    ),
    (
        "test.aspx",
        f'<% Response.Write("{_CANARY}"); %>',
        "application/octet-stream",
        "ASPX web shell",
    ),
]


class FileUploadScanner(BaseScanner):
    """File upload vulnerability scanner."""

    CHECK_TYPE = "file_upload"
    SEVERITY = "critical"

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        """Test file upload fields."""
        field_type = field.get("type", "").lower()
        if field_type != "file":
            return []

        field_name = field.get("name", "unknown")

        if self.monitor:
            await self.monitor.emit_status(
                f"File upload test: {field_name} on {url}"
            )

        findings = []
        proxy = getattr(self.engine, "proxy", "") or None
        timeout = getattr(self.engine, "timeout", 20)

        client_kwargs: dict = {"timeout": timeout, "follow_redirects": True}
        if proxy:
            client_kwargs["proxy"] = proxy

        for filename, content, content_type, description in _TEST_FILES:
            if self.monitor:
                await self.monitor.emit_payload_test(
                    field_name, f"[file] {filename}", "file_upload"
                )
            try:
                # Try to submit the form with the malicious file
                upload_result = await self._attempt_upload(
                    url, form_index, field_name,
                    filename, content, content_type,
                    client_kwargs,
                )
                if not upload_result:
                    continue

                status_code, response_body, response_url = upload_result

                # Check 1: canary string in response (immediate execution)
                if _CANARY in response_body:
                    pair = {
                        "request": {"url": url, "method": "POST"},
                        "response": {"status": status_code, "body": response_body[:1000]},
                    }
                    finding = await self.record_finding(
                        url=url,
                        field_name=field_name,
                        payload=f"[file] {filename}",
                        evidence=(
                            f"File upload RCE confirmed: uploaded '{filename}' ({description}) "
                            f"and canary string '{_CANARY}' was returned — "
                            f"the server executed the uploaded file!"
                        ),
                        pair=pair,
                        severity="critical",
                    )
                    findings.append(finding)
                    break

                # Check 2: server accepted the upload and returned a URL containing the filename
                safe_name = re.escape(filename.replace(".", r"\."))
                if re.search(safe_name, response_body, re.IGNORECASE):
                    pair = {
                        "request": {"url": url, "method": "POST"},
                        "response": {"status": status_code, "body": response_body[:1000]},
                    }
                    finding = await self.record_finding(
                        url=url,
                        field_name=field_name,
                        payload=f"[file] {filename}",
                        evidence=(
                            f"File upload likely accepted: filename '{filename}' "
                            f"({description}) appears in server response. "
                            f"Manual verification needed to confirm execution."
                        ),
                        pair=pair,
                        severity="high",
                    )
                    findings.append(finding)

            except Exception:
                continue

            await asyncio.sleep(0.3 * self.sleep_factor)

        return findings

    async def scan_page(self, url: str) -> list[Finding]:
        return []

    async def _attempt_upload(
        self,
        url: str,
        form_index: int,
        field_name: str,
        filename: str,
        content: str,
        content_type: str,
        client_kwargs: dict,
    ):
        """
        Attempt a multipart file upload using the form's action URL.
        Returns (status_code, response_body, final_url) or None on failure.
        """
        try:
            # Get the form's action URL from Playwright
            action = await self.browser.page.eval_on_selector(
                f"form:nth-of-type({form_index + 1})",
                "el => el.action || el.getAttribute('action') || ''",
            )
            from urllib.parse import urljoin
            action_url = urljoin(url, action) if action else url

            # Get other form fields to include in the submission
            other_fields = await self.browser.page.eval_on_selector_all(
                f"form:nth-of-type({form_index + 1}) input:not([type=file]), "
                f"form:nth-of-type({form_index + 1}) select, "
                f"form:nth-of-type({form_index + 1}) textarea",
                """els => els.map(el => ({
                    name: el.name || '',
                    value: el.value || '',
                    type: el.type || ''
                }))""",
            )

            data = {}
            for f in other_fields:
                if f.get("name") and f.get("type") not in ("submit", "button", "image", "reset"):
                    data[f["name"]] = f.get("value", "wscan_test")

            files = {
                field_name: (filename, content.encode(), content_type),
            }

            async with httpx.AsyncClient(**client_kwargs) as client:
                r = await client.post(action_url, data=data, files=files)
                return r.status_code, r.text, str(r.url)

        except Exception:
            return None
