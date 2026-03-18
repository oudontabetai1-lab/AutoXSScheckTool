"""
CTF Flag Finder
===============
Scans text (HTML, response bodies, alert messages) for flag patterns.
Used in CTF mode to automatically detect flags during scanning.
"""
import re

# Common CTF flag formats — covers most competition conventions
DEFAULT_CTF_PATTERN = (
    r'(?:'
    r'FLAG|CTF|flag|ctf|DUCTF|HTB|HTB\{|ictf|picoCTF|PICO|'
    r'pctf|KCTF|nahamcon|NahamCon|cyber|CYBER|'
    r'[A-Z0-9]{2,10}'   # arbitrary prefix like "ACSC", "DEF", etc.
    r')\{[^}]{1,300}\}'
)

# Well-known platform-specific defaults (shown as examples in the launcher)
COMMON_PATTERNS = {
    "generic":   r'(?:FLAG|flag|CTF|ctf)\{[^}]{1,200}\}',
    "HTB":       r'HTB\{[^}]{1,200}\}',
    "picoCTF":   r'picoCTF\{[^}]{1,200}\}',
    "DUCTF":     r'DUCTF\{[^}]{1,200}\}',
    "HackTheBox": r'HTB\{[^}]{1,200}\}',
    "custom":    "",   # filled by user
}


class FlagFinder:
    """Searches text content for CTF flag patterns."""

    def __init__(self, pattern: str = ""):
        raw = pattern.strip() if pattern and pattern.strip() else DEFAULT_CTF_PATTERN
        try:
            self._re = re.compile(raw, re.IGNORECASE)
            self.pattern = raw
        except re.error:
            # Fall back to default if user supplied an invalid regex
            self._re = re.compile(DEFAULT_CTF_PATTERN, re.IGNORECASE)
            self.pattern = DEFAULT_CTF_PATTERN

    def find(self, text: str) -> list:
        """Return list of unique flag strings found in *text*."""
        if not text:
            return []
        return list(dict.fromkeys(self._re.findall(text)))  # unique, order-preserving
