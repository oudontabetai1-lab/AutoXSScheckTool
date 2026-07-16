"""
XSS (Cross-Site Scripting) Scanner
Detects reflected and DOM-based XSS vulnerabilities.
"""
import asyncio
import html
import re
import uuid
from typing import TYPE_CHECKING

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# Markers used to detect reflected payloads
XSS_MARKERS = [
    "<script>",
    "onerror=",
    "onload=",
    "onfocus=",
    "ontoggle=",
    "ontouchstart=",
    "onwheel=",
    "onpointerenter=",
    "onmouseover=",
    "onanimationend=",
    "javascript:",
    "<svg",
    "<img",
    "<iframe",
    "<body",
    "<input",
    "<video",
    "<audio",
    "<details",
    "<marquee",
    "alert(",
]

# Attributes whose value is a URL — a javascript: payload here executes even
# without breaking out of the quotes, so a reflection inside them stays
# dangerous.
_URL_ATTRS = {"href", "src", "action", "formaction", "xlink:href", "data", "poster"}

# 発火トリガの baseline 用の中立値（英数字のみ・payload とも既存ハンドラ値とも一致
# しない）。この値を payload と同じ経路（URL パラメータ／フォーム action）で投入した
# 応答 DOM からダイアログハンドラを採取し、「新規に増えたハンドラ」判定の基準にする。
_HANDLER_BASELINE_VALUE = "wscanxssbaseline"

# 型付き入力（HTML5 validation）で中立値がフォームに弾かれると、baseline 送信が
# フォームページに留まり action 応答（payload が到達するページ）のハンドラを採れない。
# フィールド型ごとに *検証を通る* 中立値を用意し、payload と同じ応答ブランチへ確実に
# 到達させる（英数字トークン wscanbaseline を各型の妥当な形に埋め込む）。
_TYPED_BASELINE_VALUES = {
    "url": "https://wscanbaseline.example/x",
    "email": "wscanbaseline@example.com",
    "number": "1",
    "range": "1",
    "tel": "0000000000",
    "date": "2000-01-01",
    "datetime-local": "2000-01-01T00:00",
    "time": "12:00",
    "month": "2000-01",
    "week": "2000-W01",
    "color": "#000000",
}


# alert/confirm/prompt 呼び出し（引数は括弧の入れ子を1段許容）を捉える。
_DIALOG_CALL_RE = re.compile(r"(?:alert|confirm|prompt)\s*\((?:[^()]|\([^()]*\))*\)", re.IGNORECASE)


def _tokenize_dialog_calls(payload: str, token: str) -> str:
    """payload 内の alert/confirm/prompt 呼び出しを ``alert('<token>')`` へ置換する（純粋）。

    発火トリガ層で投入するペイロードに一意トークンを埋めることで、注入したハンドラ値が
    payload 固有になる。これにより ``trigger_injected_handlers`` の「ハンドラ値が payload に
    含まれるか」判定が、ページ本来の ``alert(1)`` 等（トークンを含まない）を確実に除外でき、
    値依存の同一パス分岐で正規ハンドラだけが現れるケースでも誤発火しない。発火の確証は
    ダイアログ文言に ``token`` が出ることで裏取りする（dom_xss と同じ一意マーカー方式）。
    ダイアログ呼び出しが無い payload はそのまま返す。
    """
    if not token:
        return payload
    return _DIALOG_CALL_RE.sub(f"alert('{token}')", payload)


def _neutral_baseline_value(field_type: str) -> str:
    """フィールド型に対して HTML5 検証を通る中立 baseline 値を返す。

    未知/テキスト系は ``_HANDLER_BASELINE_VALUE``。型付きは検証を通る妥当値を返し、
    baseline 送信が payload と同じ応答ブランチへ到達できるようにする（さもないと
    型検証で中立値だけフォームに留まり、action 応答固有の正規ハンドラを baseline に
    採れず誤発火＝誤検知の原因になる）。純粋関数。
    """
    return _TYPED_BASELINE_VALUES.get((field_type or "text").lower(), _HANDLER_BASELINE_VALUE)


class XSSScanner(BaseScanner):
    """XSS vulnerability scanner."""

    CHECK_TYPE = "xss"
    SEVERITY = "high"

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        """Scan a form field or URL parameter for XSS vulnerabilities."""
        findings = []
        field_name = field.get("name", "unknown")
        payloads = await self.get_payloads(field_name, url)

        if self.monitor:
            await self.monitor.emit_status(f"XSS testing: {field_name} on {url}")

        # Capture baseline before injecting any payload. Reflection analysis
        # runs on the raw HTTP response body (where the server's escaping is
        # visible as &lt; / &quot;), not the serialised DOM — the browser
        # re-serialises attribute values with raw < / >, which makes an escaped
        # payload inside value="…" look like a live tag and yields false
        # positives. The DOM (page.content()) is the fallback for DOM-only
        # reflections that never appear in the response body.
        baseline_source = ""
        try:
            await self.browser.navigate(url)
            baseline_source = await self.browser.page.content()
            body = self._response_body_for(url)
            if body:
                baseline_source = body
        except Exception as exc:
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] xss: baseline fetch failed on {url}: {exc}"
                )

        # baseline（ハンドラ＋リフレクション本文）は「payload と同じ経路を中立値で
        # 開いた応答」から採る。フォームは pre-submit のフォームページと action 応答で
        # 構成が異なるため、中立投入の応答本文を baseline にしないと、結果ページ固有の
        # onclick="alert(1)" 等を新規注入と誤認してリフレクション・発火の双方で誤検知する。
        baseline_handlers, baseline_path, baseline_submit_source = await self._baseline_handlers(
            url, form_index, field_name, is_url_param,
            neutral_value=_neutral_baseline_value(field.get("type", "text")),
        )
        if baseline_submit_source:
            baseline_source = baseline_submit_source

        async def _test_payload(
            payload: str,
            check_label: str = "xss",
            fire: bool = False,
            expect_token: str = "",
        ) -> bool:
            await self.log_payload_test(field_name, payload, check_label, url)

            # Reset dialog detector
            self.browser.reset_dialog()

            # Apply payload
            source, pair = await self._apply_payload(
                url, form_index, field_name, payload, is_url_param
            )

            await asyncio.sleep(0.5 * self.sleep_factor)  # Wait for any JS execution

            # Interaction-required handlers (onmouseover / onclick / onfocus) and
            # javascript: URLs do not fire on their own, so a genuine attribute-
            # breakout payload like `" onmouseover=alert('<token>') x="` reflects but
            # never triggers a dialog. Actively dispatch the matching events — only
            # for the evolution wave, whose payloads carry a unique alert token so a
            # page's own alert(1) handler is never fired or mis-confirmed. Additive
            # and exception-guarded; on failure the scan falls back to reflection.
            if fire:
                await self._fire_if_baseline_matches(
                    payload, baseline_handlers, baseline_path
                )

            # --- Check 1: Alert dialog fired (confirmed XSS) ---
            # When an expect_token is set (evolution wave), only treat the dialog as
            # ours if the token appears in its message — a pre-existing handler's
            # dialog (e.g. "1") is then never attributed to the payload.
            if self.browser.dialog_fired and (
                not expect_token or expect_token in (self.browser.dialog_message or "")
            ):
                finding = await self.record_finding(
                    url=url,
                    field_name=field_name,
                    payload=payload,
                    evidence=f"JavaScript alert() dialog triggered: '{self.browser.dialog_message}'",
                    pair=pair,
                    severity="critical",
                    dialog_confirmed=True,
                    dialog_message=self.browser.dialog_message,
                    confidence="confirmed",
                    evidence_type="xss_dialog",
                    evidence_details={
                        "execution_signal": "browser_dialog",
                        "dialog_message": self.browser.dialog_message,
                    },
                    reproduction_steps=[
                        f"Open {url}",
                        f"Submit the payload to '{field_name}'",
                        "Observe that the browser fires a JavaScript dialog.",
                    ],
                )
                # record_finding は重複 evidence_type のとき None を返す。None を
                # findings へ積むと後段の any(f.dialog_confirmed ...) が AttributeError。
                if finding:
                    findings.append(finding)
                self.browser.reset_dialog()
                return True

            # --- Check 2: Payload reflected without HTML encoding ---
            reflect_source = pair.get("response", {}).get("body") or source
            if reflect_source:
                reflection = self._analyze_reflection(reflect_source, payload, baseline_source)
                if reflection:
                    context = reflection.get("context", "unknown")
                    confidence = reflection.get("confidence", "tentative")
                    severity = "high" if confidence == "likely" else "medium"
                    finding = await self.record_finding(
                        url=url,
                        field_name=field_name,
                        payload=payload,
                        evidence=(
                            f"XSS payload reflected unencoded in {context} context: "
                            f"'{reflection.get('snippet', '')[:100]}'"
                        ),
                        pair=pair,
                        severity=severity,
                        confidence=confidence,
                        evidence_type="xss_reflection",
                        evidence_details=reflection,
                        reproduction_steps=[
                            f"Open {url}",
                            f"Submit the payload to '{field_name}'",
                            f"Confirm the payload is reflected in {context} context without complete encoding.",
                            "Escalate manually with a context-specific event or script payload if no dialog fires.",
                        ],
                    )
                    if finding:
                        findings.append(finding)
                    return True

            await asyncio.sleep(0.2 * self.sleep_factor)
            return False

        for payload in payloads:
            if await _test_payload(payload):
                break  # Found vulnerability, move to next field

        # --- Check 3: deterministic context-aware evolution wave ---
        # 走らせる条件は次のいずれか（かつ dialog 未確証のとき）:
        #   (a) 何も見つかっていない（従来どおりの探索）。
        #   (b) 既存 finding が属性系文脈の tentative 反射である。反射ヒューリスティック
        #       は「実際に発火するか」を判定できず、messy な quote-break payload で弱い
        #       tentative が立って本当に実行可能な clean breakout
        #       （例: `" onmouseover=alert(1) x="`）を試さずに終わることがあるため、
        #       clean breakout を合成→投入し発火トリガ層で confirmed 昇格を狙う。
        # html_text 等の非属性文脈の tentative では追加しない: `<` が生存するなら標準
        # 掃射の tag 系 payload で既に発火機会があり、`<` がエスケープ済みなら属性
        # breakout も成立しないため、無駄な wave を避ける（誤検知ゼロ＋実行時間の両立）。
        _ATTR_CTX = {"html_attribute", "event_handler_attribute", "url_attribute"}
        have_confirmed = any(f.dialog_confirmed for f in findings)
        attr_ctx_tentative = any(
            (not f.dialog_confirmed)
            and (f.evidence_details or {}).get("context") in _ATTR_CTX
            for f in findings
        )
        if not have_confirmed and (not findings or attr_ctx_tentative):
            extra_payloads = await self.evolved_payloads(
                url, form_index, field_name, is_url_param
            )
            # 発火トリガで投入するペイロードには一意トークンを埋め、注入ハンドラ値を
            # payload 固有にする（ページ本来の alert(1) 等を発火・確証しないため）。
            fire_token = "wsxf" + uuid.uuid4().hex[:8]
            for payload in extra_payloads:
                tok_payload = _tokenize_dialog_calls(payload, fire_token)
                await _test_payload(
                    tok_payload, "xss_evolved", fire=True, expect_token=fire_token
                )
                if any(f.dialog_confirmed for f in findings):
                    break

        # --- Check 4: String-concatenation / quote-break equivalence probe ---
        # When direct reflection checks find nothing, probe whether the input is
        # embedded in a quoted HTML attribute or JS string that can be split with
        # matching quotes (e.g. AA" "BB / 'AA'+'BB'). A collapse to the marker
        # proves the quote breaks the surrounding context — a strong XSS signal.
        if not findings:
            for ctx in ("html_attr", "js_string"):
                probe = await self.run_equivalence_probe(
                    url, form_index, field_name, is_url_param, context=ctx
                )
                if not probe:
                    continue
                verdict, pair = probe
                finding = await self.record_finding(
                    url=url,
                    field_name=field_name,
                    payload=verdict.details.get("matched_payload", ""),
                    evidence=(
                        "String-concatenation/quote-break equivalence XSS: "
                        + verdict.rationale
                    ),
                    pair=pair,
                    severity="medium",
                    confidence="likely" if verdict.confidence >= 0.85 else "tentative",
                    evidence_type="xss_concat_equivalence",
                    evidence_details={
                        "matched_dialect": verdict.matched_dialect,
                        "matched_probe": verdict.matched_probe,
                        "probe_confidence": round(verdict.confidence, 3),
                        **verdict.details,
                    },
                    reproduction_steps=[
                        f"Open {url}",
                        f"Submit the quote-splitting payload to '{field_name}': "
                        f"{verdict.details.get('matched_payload', '')}",
                        "Confirm the response collapses to the marker, proving the "
                        "injected quote breaks the surrounding attribute/JS context.",
                        "Escalate manually with a context-appropriate event/script payload.",
                    ],
                )
                if finding:
                    findings.append(finding)
                break

        return findings

    def _check_reflected(self, source: str, payload: str, baseline_source: str = "") -> str:
        """
        Check if the payload is reflected in the source without HTML encoding.
        Uses baseline comparison to avoid false positives from pre-existing page content.
        Returns the matched snippet or empty string.
        """
        reflection = self._analyze_reflection(source, payload, baseline_source)
        if reflection:
            return reflection.get("snippet", "")
        return ""

    def _analyze_reflection(
        self, source: str, payload: str, baseline_source: str = ""
    ) -> dict:
        """
        Return structured reflection evidence.

        Reflection alone is not always executable XSS.  This classifies the
        reflected location so the report can distinguish executable-looking
        contexts from weaker text-node reflections.
        """
        if payload and len(payload) > 5 and payload in source:
            if baseline_source and source.count(payload) <= baseline_source.count(payload):
                return {}
            idx = source.find(payload)
            preceding = source.lower()[max(0, idx - 300):idx]
            if not (preceding.rfind("<!--") > preceding.rfind("-->")):
                context = self._classify_reflection_context(source, idx)
                if self._reflection_executable(source, idx, payload, payload, baseline_source, context):
                    return {
                        "context": context,
                        "match": "full_payload",
                        "snippet": source[max(0, idx - 10):idx + len(payload) + 50],
                        "confidence": self._confidence_for_context(context),
                        "raw_payload_present": True,
                        "baseline_marker_delta": None,
                    }

        source_lower = source.lower()
        baseline_lower = baseline_source.lower() if baseline_source else ""
        payload_lower = payload.lower()

        for marker in XSS_MARKERS:
            marker_lower = marker.lower()
            if marker_lower not in payload_lower:
                continue
            if marker_lower not in source_lower:
                continue

            # Baseline comparison: skip if marker count did not increase after injection
            if baseline_lower:
                if source_lower.count(marker_lower) <= baseline_lower.count(marker_lower):
                    continue  # No new occurrence introduced by the payload

            # Skip if only the HTML-encoded form is present (not the raw marker)
            encoded = html.escape(marker).lower()
            if encoded != marker_lower and encoded in source_lower and marker_lower not in source_lower:
                continue

            # Inspect *every* occurrence of the marker, not just the first. The
            # first one may be an inert escaped reflection (or, on a page whose own
            # UI carries the same handler code, a pre-existing executable handler),
            # while a genuinely injected executable occurrence sits later. Report
            # the first occurrence that is (a) not in a comment, (b) executable in
            # its context, and (c) NOT pre-existing in the baseline — so a page's
            # own handler is never mis-attributed to the payload regardless of
            # where it sits relative to the reflection.
            start = 0
            while True:
                idx = source_lower.find(marker_lower, start)
                if idx == -1:
                    break
                start = idx + 1

                # Skip occurrences inside HTML comments (<!-- ... -->)
                preceding = source_lower[max(0, idx - 300):idx]
                if preceding.rfind("<!--") > preceding.rfind("-->"):
                    continue

                context = self._classify_reflection_context(source, idx)
                if not self._reflection_executable(
                    source, idx, payload, marker, baseline_source, context
                ):
                    continue

                # Per-occurrence baseline newness: skip an occurrence whose
                # surrounding text already appears verbatim in the baseline (a
                # pre-existing page handler, not something the payload introduced).
                if baseline_lower:
                    window = source_lower[max(0, idx - 40):idx + len(marker_lower) + 20]
                    if window and window in baseline_lower:
                        continue

                delta = None
                if baseline_lower:
                    delta = source_lower.count(marker_lower) - baseline_lower.count(marker_lower)
                return {
                    "context": context,
                    "match": marker,
                    "snippet": source[max(0, idx - 20):idx + len(marker) + 50],
                    "confidence": self._confidence_for_context(context),
                    "raw_payload_present": False,
                    "baseline_marker_delta": delta,
                }

        return {}

    def _reflection_executable(
        self,
        source: str,
        idx: int,
        payload: str,
        matched: str,
        baseline_source: str,
        context: str,
    ) -> bool:
        """Decide whether a reflection at ``idx`` can actually execute.

        Reflection alone is not XSS: a correctly-escaped page echoes the payload
        but neutralises the characters that would let it break out. ``matched``
        is the token confirmed present *raw* at ``idx`` (the whole payload, or a
        single marker), and ``page.content()`` is the browser's serialised DOM,
        so the trustworthy signals are:

        * ``matched`` carries a raw ``<`` — a real tag/element was formed
          (escaped output keeps ``&lt;``, and a serialised text node re-escapes
          ``<``, so a raw ``<`` in the matched token means a live tag);
        * the reflection sits in an inherently executable position — a
          ``<script>`` body, an unquoted ``on*`` handler, or a URL attribute;
        * inside a quoted attribute value, only an ``on*`` handler / URL
          attribute, or the value's delimiting quote actually being broken.

        Bare markers (``alert(``, ``onload=`` …) and quote / backtick characters
        survive ``html.escape`` and even reappear raw inside serialised attribute
        values, so they are treated as data unless one of the signals above
        holds. This is what suppresses ``value="&quot; onmouseover=alert(1)"``
        and ``Hello, &lt;script&gt;alert(1)`` false positives while still
        catching genuinely unescaped reflections.
        """
        if context == "html_comment":
            return False

        raw_tag = "<" in matched  # matched is confirmed present raw at idx

        owner, delim = self._owning_quoted_attr(source, idx)
        if owner is not None:
            # idx sits inside a quoted attribute value: the token is data unless
            # the owning attribute itself runs script, the payload broke the
            # delimiting quote, or a real tag was formed. This stops the
            # classifier from mistaking ``value="… onmouseover=alert(1)"`` text
            # for a live event handler.
            if owner.startswith("on") or owner in _URL_ATTRS:
                return True
            if raw_tag:
                return True
            base_l = baseline_source.lower() if baseline_source else ""
            return bool(
                delim
                and delim in payload
                and base_l
                and source.count(delim) > baseline_source.count(delim)
            )

        # Not inside a quoted value: trust the positional classification — an
        # unquoted on*-handler, a <script> body, or a javascript: URL attribute
        # are executable regardless of structural characters.
        if context in ("script", "event_handler_attribute", "url_attribute"):
            return True
        # html_text / bare unquoted attribute: needs a real tag-opening bracket.
        return raw_tag

    @staticmethod
    def _owning_quoted_attr(source: str, idx: int) -> tuple:
        """Resolve the quoted attribute value (if any) that contains ``idx``.

        Returns ``(attribute_name, delimiter_quote)`` when ``idx`` is inside an
        open, quoted attribute value, else ``(None, "")``. The attribute name is
        lower-cased; it is ``""`` when a delimiter is open but no name precedes
        it. Only raw quote characters are tracked, so an escaped ``&quot;`` does
        not look like a delimiter — which is exactly what distinguishes inert
        escaped output from a genuine attribute breakout.
        """
        lt = source.rfind("<", 0, idx)
        gt = source.rfind(">", 0, idx)
        if lt == -1 or (gt != -1 and gt > lt):
            return (None, "")  # not inside a tag
        seg = source[lt:idx]
        quote = None
        open_pos = -1
        for j, c in enumerate(seg):
            if quote:
                if c == quote:
                    quote = None
            elif c in ('"', "'"):
                quote = c
                open_pos = j
        if quote is None:
            return (None, "")
        head = seg[:open_pos]
        m = re.search(r'([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*$', head)
        return (m.group(1).lower() if m else "", quote)

    def _classify_reflection_context(self, source: str, idx: int) -> str:
        before = source[max(0, idx - 500):idx].lower()
        after = source[idx:idx + 500].lower()
        last_lt = before.rfind("<")
        last_gt = before.rfind(">")
        in_tag = last_lt > last_gt
        tag_fragment = before[last_lt:] if in_tag else ""

        if before.rfind("<!--") > before.rfind("-->"):
            return "html_comment"
        if "<script" in before and "</script" not in before.split("<script")[-1]:
            return "script"
        if in_tag:
            if re.search(r"\son[a-z]+\s*=\s*['\"]?$", tag_fragment):
                return "event_handler_attribute"
            if re.search(r"\s(?:href|src|action|formaction)\s*=\s*['\"]?$", tag_fragment):
                return "url_attribute"
            return "html_attribute"
        if after.startswith("</script"):
            return "script"
        return "html_text"

    def _confidence_for_context(self, context: str) -> str:
        if context in {"script", "event_handler_attribute", "url_attribute"}:
            return "likely"
        if context in {"html_attribute", "html_text"}:
            return "tentative"
        return "tentative"

    def _response_body_for(self, url: str) -> str:
        """Raw HTTP response body captured for ``url`` (empty when unavailable).

        Reflection analysis prefers this over the serialised DOM because the
        server's escaping (``&lt;`` / ``&quot;``) is visible here, whereas the
        browser re-emits attribute values with raw ``<`` / ``>``.
        """
        net = getattr(self.browser, "network", None)
        if not net:
            return ""
        try:
            pair = net.latest_for_url(url) or net.latest() or {}
        except Exception:
            return ""
        return pair.get("response", {}).get("body") or ""

    async def _baseline_handlers(
        self,
        url: str,
        form_index: int,
        field_name: str,
        is_url_param: bool,
        neutral_value: str = _HANDLER_BASELINE_VALUE,
    ) -> tuple[list, str | None, str]:
        """発火トリガ層とリフレクション判定の baseline を **中立投入の応答**から採る。

        中立値（型付きは検証を通る値）を **payload と同じ経路**で投入し、その応答から
        (1) ダイアログハンドラ一覧、(2) 着地パス、(3) 応答本文（リフレクション baseline）
        を返す。フォームは pre-submit のフォームページと action 応答でハンドラ/本文が
        異なるため、応答本文を baseline にしないと action 応答固有の正規 onclick=alert(1)
        等を「payload が入れた新規」と誤認して発火・リフレクション双方で誤検知する。

        着地パスは payload の着地と一致するときだけ発火するために使う（型検証で中立値が
        フォームに留まり payload だけ別ページへ到達した場合の誤発火防止）。戻り値は
        ``(handlers, landing_path, source)``。失敗時は ``([], None, "")``。中立投入で
        立ったダイアログは後続 payload に持ち越さないよう reset する。
        """
        from urllib.parse import urlparse

        try:
            await self.log_payload_test(
                field_name, neutral_value, "xss_handler_baseline", url
            )
            self.browser.reset_dialog()
            src, pair = await self._apply_payload(
                url, form_index, field_name, neutral_value, is_url_param
            )
            await asyncio.sleep(0.2 * self.sleep_factor)
            handlers = await self.browser.snapshot_dialog_handlers()
            landing_path = urlparse(self.browser.page.url).path
            body = (pair.get("response", {}) or {}).get("body") or src or ""
            return handlers, landing_path, body
        except Exception:
            return [], None, ""
        finally:
            self.browser.reset_dialog()

    def _current_path(self) -> str | None:
        """発火判定用に、いま browser がいるページの URL パスを返す（失敗時 None）。"""
        from urllib.parse import urlparse

        try:
            return urlparse(self.browser.page.url).path
        except Exception:
            return None

    async def _fire_if_baseline_matches(
        self, payload: str, baseline_handlers: list, baseline_path: str | None
    ) -> None:
        """baseline を採れた着地ページと同じ場所にいるときだけ発火トリガを撃つ。

        着地パスが一致しない（＝中立 baseline が payload と別ページに落ちた）場合や
        baseline 不確実（``baseline_path is None``）の場合は、既存ハンドラの誤発火を
        避けるため発火を見送り、従来の反射ヒューリスティックに委ねる。加算的・例外保護。
        """
        if self.browser.dialog_fired:
            return
        try:
            if baseline_path is None:
                return
            if self._current_path() != baseline_path:
                return
            if await self.browser.trigger_injected_handlers(payload, baseline_handlers):
                await asyncio.sleep(0.3 * self.sleep_factor)
        except Exception:
            pass

    async def verify_finding(self, finding: Finding) -> bool | None:
        from urllib.parse import parse_qs, urlparse
        is_url_param = finding.field_name in parse_qs(
            urlparse(finding.url).query, keep_blank_values=True
        )
        baseline_source = ""
        try:
            self.browser.reset_dialog()
            await self.browser.navigate(finding.url)
            baseline_source = await self.browser.page.content()
            body = self._response_body_for(finding.url)
            if body:
                baseline_source = body
        except Exception:
            baseline_source = ""
        # baseline（ハンドラ＋リフレクション本文）は payload と同じ経路を中立値で開いた
        # 応答から採る（フォーム action 応答固有の正規ハンドラを誤発火/誤検知しないため）。
        baseline_handlers, baseline_path, baseline_submit_source = await self._baseline_handlers(
            finding.url, 0, finding.field_name, is_url_param
        )
        if baseline_submit_source:
            baseline_source = baseline_submit_source
        self.browser.reset_dialog()
        await self.log_payload_test(
            finding.field_name, finding.payload, "xss_verify", finding.url
        )
        source, pair = await self._apply_payload(
            finding.url,
            0,
            finding.field_name,
            finding.payload,
            is_url_param,
        )
        await asyncio.sleep(0.5 * self.sleep_factor)
        # 発火は dialog 由来の finding のみ再現（その payload は一意トークン付きなので
        # ページ本来の alert(1) 等を発火・誤確証しない）。reflection 由来は下で反射を
        # 再判定するため、能動発火はしない（無関係な既存ハンドラを撃たないため）。
        token = ""
        if getattr(finding, "evidence_type", "") == "xss_dialog":
            m = re.search(r"wsxf[0-9a-f]{8}", finding.payload or "")
            token = m.group(0) if m else ""
            await self._fire_if_baseline_matches(
                finding.payload, baseline_handlers, baseline_path
            )
        if self.browser.dialog_fired and (
            not token or token in (self.browser.dialog_message or "")
        ):
            return True
        if getattr(finding, "evidence_type", "") == "xss_dialog":
            return False
        reflect_source = pair.get("response", {}).get("body") or source
        return bool(reflect_source and self._analyze_reflection(reflect_source, finding.payload, baseline_source))

    async def _apply_payload(
        self,
        url: str,
        form_index: int,
        field_name: str,
        payload: str,
        is_url_param: bool,
    ) -> tuple[str, dict]:
        try:
            if is_url_param:
                return await self.browser.test_url_param(url, field_name, payload)
            else:
                await self.browser.navigate(url)
                return await self.browser.fill_and_submit_form(
                    form_index, field_name, payload
                )
        except Exception as exc:
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] xss: _apply_payload failed on {field_name} @ {url}: {exc}"
                )
            return "", {}
