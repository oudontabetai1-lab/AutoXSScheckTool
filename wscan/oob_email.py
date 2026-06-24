"""OOB（帯域外）メール受信シンク。

Blind XSS / SSRF、メールヘッダインジェクション、second-order など
「対象アプリがメールを送って初めて確証できる」脆弱性のために、専用の
受信メールボックス（IMAP / POP3）を監視し、ペイロードに埋め込んだ一意
トークンと突合する。

設計方針:
- 送信した payload に ``<token>@<catch-all-domain>`` 形式の一意アドレス／
  トークンを埋め込む（``make_oob_token`` / ``oob_address``）。
- 脆弱性が発火すると catch-all メールボックスへメールが届く。
- ``EmailSink.search(token)`` / ``wait_for(token, timeout)`` で受信箱を検索し、
  To ヘッダ・件名・本文のいずれかにトークンを含むメールを返す。

トランスポート（imaplib / poplib）と解析・突合ロジックを分離してあり、
解析系（``parse_email`` / ``email_matches_token`` / ``filter_messages``）は
ネットワーク非依存で単体テストできる。設定は環境変数から読む
（``OOBEmailConfig.from_env``）ため、認証情報をコードに埋め込まない。
"""
from __future__ import annotations

import email
import os
import secrets
import time
from dataclasses import dataclass, field
from email.message import Message
from email.utils import getaddresses
from typing import Optional


# ── トークン / アドレス生成 ────────────────────────────────────────────────
_TOKEN_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"


def make_oob_token(scan_id: str = "") -> str:
    """ペイロードに埋め込む一意トークンを生成する。

    ``wscan-oob-<scan_id>-<nonce>`` 形式。英数字とハイフンのみで、メール
    アドレスのローカルパートやヘッダ値に安全に使える。
    """
    nonce = "".join(secrets.choice(_TOKEN_ALPHABET) for _ in range(12))
    sid = "".join(c for c in scan_id.lower() if c in _TOKEN_ALPHABET)[:16]
    return f"wscan-oob-{sid}-{nonce}" if sid else f"wscan-oob-{nonce}"


def oob_address(token: str, domain: str) -> str:
    """catch-all ドメイン上の OOB 受信アドレスを返す。"""
    return f"{token}@{domain}"


# ── 設定 ──────────────────────────────────────────────────────────────────
@dataclass
class OOBEmailConfig:
    protocol: str = "imap"          # "imap" | "pop3"
    host: str = ""
    port: int = 0                    # 0 → プロトコル既定 (IMAPS 993 / POP3S 995)
    username: str = ""
    password: str = ""
    use_ssl: bool = True
    mailbox: str = "INBOX"          # IMAP のみ
    domain: str = ""                 # OOB アドレスの catch-all ドメイン

    @property
    def effective_port(self) -> int:
        if self.port:
            return self.port
        if self.protocol == "pop3":
            return 995 if self.use_ssl else 110
        return 993 if self.use_ssl else 143

    @property
    def configured(self) -> bool:
        return bool(self.host and self.username and self.password)

    @classmethod
    def from_env(cls, env: Optional[dict] = None) -> "OOBEmailConfig":
        e = env if env is not None else os.environ

        def _bool(key: str, default: bool) -> bool:
            v = e.get(key)
            if v is None:
                return default
            return v.strip().lower() in ("1", "true", "yes", "on")

        def _int(key: str, default: int) -> int:
            try:
                return int(e.get(key, default))
            except (TypeError, ValueError):
                return default

        protocol = (e.get("WSCAN_OOB_PROTOCOL", "imap") or "imap").strip().lower()
        return cls(
            protocol="pop3" if protocol == "pop3" else "imap",
            host=(e.get("WSCAN_OOB_HOST", "") or "").strip(),
            port=_int("WSCAN_OOB_PORT", 0),
            username=(e.get("WSCAN_OOB_USERNAME", "") or "").strip(),
            password=e.get("WSCAN_OOB_PASSWORD", "") or "",
            use_ssl=_bool("WSCAN_OOB_SSL", True),
            mailbox=(e.get("WSCAN_OOB_MAILBOX", "INBOX") or "INBOX").strip(),
            domain=(e.get("WSCAN_OOB_DOMAIN", "") or "").strip(),
        )


# ── 受信メール表現 ────────────────────────────────────────────────────────
@dataclass
class ReceivedEmail:
    uid: str = ""
    from_addr: str = ""
    to_addrs: list = field(default_factory=list)
    subject: str = ""
    date: str = ""
    body: str = ""
    size: int = 0

    def to_dict(self) -> dict:
        return {
            "uid": self.uid,
            "from": self.from_addr,
            "to": self.to_addrs,
            "subject": self.subject,
            "date": self.date,
            "body": self.body[:4000],
            "size": self.size,
        }


# ── 解析・突合（ネットワーク非依存・テスト対象） ──────────────────────────
def _extract_body(msg: Message) -> str:
    """メールから text/plain（無ければ text/html）本文を抽出する。"""
    if msg.is_multipart():
        plain, html = "", ""
        for part in msg.walk():
            ctype = part.get_content_type()
            if part.get_content_disposition() == "attachment":
                continue
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None
            if not payload:
                continue
            text = payload.decode(part.get_content_charset() or "utf-8", "replace")
            if ctype == "text/plain" and not plain:
                plain = text
            elif ctype == "text/html" and not html:
                html = text
        return plain or html
    try:
        payload = msg.get_payload(decode=True)
    except Exception:
        payload = None
    if payload:
        return payload.decode(msg.get_content_charset() or "utf-8", "replace")
    return msg.get_payload() or ""


def parse_email(raw: bytes, uid: str = "") -> ReceivedEmail:
    """生のメールバイト列を ``ReceivedEmail`` に解析する（純粋関数）。"""
    msg = email.message_from_bytes(raw)
    to_pairs = getaddresses(msg.get_all("to", []) + msg.get_all("cc", []) + msg.get_all("delivered-to", []))
    to_addrs = [addr for _, addr in to_pairs if addr]
    return ReceivedEmail(
        uid=uid,
        from_addr=(msg.get("from", "") or "").strip(),
        to_addrs=to_addrs,
        subject=(msg.get("subject", "") or "").strip(),
        date=(msg.get("date", "") or "").strip(),
        body=_extract_body(msg),
        size=len(raw),
    )


def email_matches_token(received: ReceivedEmail, token: str) -> bool:
    """受信メールがトークンを含む（To / 件名 / 本文）か判定する。"""
    if not token:
        return False
    t = token.lower()
    if any(t in (addr or "").lower() for addr in received.to_addrs):
        return True
    if t in (received.subject or "").lower():
        return True
    if t in (received.body or "").lower():
        return True
    if t in (received.from_addr or "").lower():
        return True
    return False


def filter_messages(raw_messages, token: str) -> list:
    """``[(uid, raw_bytes), ...]`` からトークン一致メールを抽出する（純粋関数）。"""
    out = []
    for uid, raw in raw_messages:
        try:
            received = parse_email(raw, uid=str(uid))
        except Exception:
            continue
        if email_matches_token(received, token):
            out.append(received)
    return out


# ── トランスポート（IMAP / POP3） ─────────────────────────────────────────
class EmailSink:
    """設定済みメールボックスからトークン一致メールを取得する。"""

    def __init__(self, config: OOBEmailConfig):
        self.config = config
        self._conn = None

    # -- IMAP --
    def _connect_imap(self):
        import imaplib

        cfg = self.config
        if cfg.use_ssl:
            conn = imaplib.IMAP4_SSL(cfg.host, cfg.effective_port)
        else:
            conn = imaplib.IMAP4(cfg.host, cfg.effective_port)
        conn.login(cfg.username, cfg.password)
        conn.select(cfg.mailbox)
        return conn

    def _search_imap(self, token: str) -> list:
        conn = self._connect_imap()
        try:
            uids: list[bytes] = []
            # サーバ側検索（To / Cc / Subject / Body / Delivered-To）。catch-all 宛
            # なので To/Delivered-To が主だが、メールヘッダ注入で追加された Cc に
            # トークンが現れるケースも拾えるよう CC と HEADER も検索する。
            for crit in (
                ["TO", token],
                ["CC", token],
                ["SUBJECT", token],
                ["BODY", token],
                ["HEADER", "Delivered-To", token],
            ):
                try:
                    typ, data = conn.uid("search", None, *crit)
                except Exception:
                    continue
                if typ == "OK" and data and data[0]:
                    uids.extend(data[0].split())
            seen: set[bytes] = set()
            raws: list = []
            for uid in uids:
                if uid in seen:
                    continue
                seen.add(uid)
                typ, msg_data = conn.uid("fetch", uid, "(RFC822)")
                if typ != "OK" or not msg_data or not msg_data[0]:
                    continue
                raws.append((uid.decode(), msg_data[0][1]))
            return filter_messages(raws, token)
        finally:
            try:
                conn.logout()
            except Exception:
                pass

    # -- POP3 (サーバ側検索が無いので全件取得してフィルタ) --
    def _search_pop3(self, token: str) -> list:
        import poplib

        cfg = self.config
        if cfg.use_ssl:
            conn = poplib.POP3_SSL(cfg.host, cfg.effective_port)
        else:
            conn = poplib.POP3(cfg.host, cfg.effective_port)
        try:
            conn.user(cfg.username)
            conn.pass_(cfg.password)
            count = len(conn.list()[1])
            raws = []
            # 直近メールを優先（最大100件）して負荷を抑える。
            start = max(1, count - 100 + 1)
            for i in range(start, count + 1):
                resp, lines, octets = conn.retr(i)
                raws.append((str(i), b"\r\n".join(lines)))
            return filter_messages(raws, token)
        finally:
            try:
                conn.quit()
            except Exception:
                pass

    def search(self, token: str) -> list:
        """トークンに一致する受信メールのリストを返す。"""
        if not self.config.configured:
            raise RuntimeError(
                "OOB email is not configured (set WSCAN_OOB_HOST / "
                "WSCAN_OOB_USERNAME / WSCAN_OOB_PASSWORD)."
            )
        if self.config.protocol == "pop3":
            return self._search_pop3(token)
        return self._search_imap(token)

    # -- 直近メールの一括取得（複数トークンをメモリ内で突合するため） --
    def _fetch_recent_imap(self, limit: int) -> list:
        conn = self._connect_imap()
        try:
            typ, data = conn.uid("search", None, "ALL")
            if typ != "OK" or not data or not data[0]:
                return []
            uids = data[0].split()[-max(1, limit):]
            out = []
            for uid in uids:
                typ, msg_data = conn.uid("fetch", uid, "(RFC822)")
                if typ != "OK" or not msg_data or not msg_data[0]:
                    continue
                try:
                    out.append(parse_email(msg_data[0][1], uid=uid.decode()))
                except Exception:
                    continue
            return out
        finally:
            try:
                conn.logout()
            except Exception:
                pass

    def _fetch_recent_pop3(self, limit: int) -> list:
        import poplib

        cfg = self.config
        if cfg.use_ssl:
            conn = poplib.POP3_SSL(cfg.host, cfg.effective_port)
        else:
            conn = poplib.POP3(cfg.host, cfg.effective_port)
        try:
            conn.user(cfg.username)
            conn.pass_(cfg.password)
            count = len(conn.list()[1])
            out = []
            start = max(1, count - max(1, limit) + 1)
            for i in range(start, count + 1):
                resp, lines, octets = conn.retr(i)
                try:
                    out.append(parse_email(b"\r\n".join(lines), uid=str(i)))
                except Exception:
                    continue
            return out
        finally:
            try:
                conn.quit()
            except Exception:
                pass

    def fetch_recent(self, limit: int = 50) -> list:
        """直近 ``limit`` 件の受信メールを **1 回のログイン**で取得・解析して返す。

        複数トークンを 1 ポーリングで突合したいときに使う。トークン毎に
        :meth:`search` を呼ぶとログインが多発しメールボックスを絞られ得るため、
        ここで一括取得し、突合は ``email_matches_token`` でメモリ内に行う。
        """
        if not self.config.configured:
            raise RuntimeError(
                "OOB email is not configured (set WSCAN_OOB_HOST / "
                "WSCAN_OOB_USERNAME / WSCAN_OOB_PASSWORD)."
            )
        if self.config.protocol == "pop3":
            return self._fetch_recent_pop3(limit)
        return self._fetch_recent_imap(limit)

    def wait_for(
        self, token: str, timeout: float = 60.0, interval: float = 5.0
    ) -> Optional[ReceivedEmail]:
        """トークン一致メールが届くまで最大 ``timeout`` 秒ポーリングする。"""
        deadline = time.time() + max(0.0, timeout)
        while True:
            try:
                hits = self.search(token)
            except Exception:
                hits = []
            if hits:
                return hits[0]
            if time.time() >= deadline:
                return None
            time.sleep(max(0.5, interval))
