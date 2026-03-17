"""
CSRF (Cross-Site Request Forgery) Scanner
Detects missing CSRF token protection in POST forms (IPA: 1.6 CSRF).
"""
from typing import TYPE_CHECKING

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# Lowercase token field name patterns that indicate a CSRF protection token
CSRF_TOKEN_NAMES = {
    "csrf", "csrftoken", "csrf_token", "_csrf", "_token", "token",
    "authenticity_token", "__requestverificationtoken", "_wpnonce",
    "xsrf", "xsrftoken", "_xsrf", "anti_csrf", "verification_token",
    "form_token", "formtoken", "nonce", "security_token", "sec_token",
    "requesttoken", "request_token",
}


class CSRFScanner(BaseScanner):
    """CSRF vulnerability scanner — checks POST forms for missing CSRF tokens (IPA 1.6)."""

    CHECK_TYPE = "csrf"
    SEVERITY = "medium"

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        # CSRF is a page-level check; no per-field scan needed.
        return []

    async def scan_page(self, url: str) -> list[Finding]:
        """Check all POST forms on the page for absent CSRF token fields."""
        findings = []

        if self.monitor:
            await self.monitor.emit_status(f"CSRF check on {url}")

        try:
            forms = await self.browser.page.evaluate("""
                () => {
                    const results = [];
                    document.querySelectorAll('form').forEach((form, fi) => {
                        const method = (form.method || 'GET').toUpperCase();
                        const inputs = Array.from(
                            form.querySelectorAll('input[name], textarea[name], select[name]')
                        ).map(el => ({
                            name: (el.name || '').toLowerCase(),
                            type: (el.type || 'text').toLowerCase(),
                        }));
                        results.push({
                            index: fi,
                            method: method,
                            action: form.action || '',
                            inputs: inputs,
                        });
                    });
                    return results;
                }
            """)
        except Exception:
            return []

        for form in forms:
            if form.get("method") != "POST":
                continue  # CSRF risk is primarily on state-changing POST requests

            inputs = form.get("inputs", [])
            has_csrf_token = any(
                inp.get("name", "").replace("-", "_").replace(" ", "_") in CSRF_TOKEN_NAMES
                for inp in inputs
            )

            if not has_csrf_token:
                pair = self.browser.network.latest() or {}
                finding = await self.record_finding(
                    url=url,
                    field_name=f"form[{form['index']}]",
                    payload="(no payload — structural analysis)",
                    evidence=(
                        f"POST form (action: {form.get('action', url)}) has no CSRF token field. "
                        "State-changing requests may be forgeable from attacker-controlled pages."
                    ),
                    pair=pair,
                    severity="medium",
                )
                findings.append(finding)

        return findings
