"""HTTP リクエスト / ペイロードのログを JSONL 形式で保存するユーティリティ。

スキャン中に送信したすべての HTTP リクエスト（メソッド・URL・ヘッダ・
``post_data``）とレスポンスのステータス、および各フィールドへ投入した
ペイロードを ``output_dir`` 配下のファイルへ追記する。スキャン後の監査・
再現・デバッグ用途に利用する。

- ``http_requests.jsonl`` … ブラウザが送信した全リクエスト/レスポンス
- ``payloads.jsonl``       … 各フィールドへ投入したペイロード

いずれも 1 行 1 レコードの JSON Lines 形式。ログ書き込みはスキャン本体を
妨げないよう、失敗しても例外を握りつぶす（ベストエフォート）。
"""
import json
import re
import threading
import time
from pathlib import Path
from typing import Optional

# 巨大な post_data でログが肥大化するのを防ぐための上限（文字数）
_MAX_POST_DATA = 20000

# 監査ログは output/ 配下に保存され、ダッシュボードが（既定では認証なしで）
# 配信しうる。認証情報がそのまま残ると閲覧者に漏れるため、書き込み前に
# 機微なヘッダ値・ボディフィールドをマスクする。
_REDACTED = "<redacted>"

# 値をマスクするヘッダ名（小文字・完全一致）
_SENSITIVE_HEADERS = frozenset({
    "authorization", "proxy-authorization", "authentication",
    "cookie", "set-cookie", "x-api-key", "api-key", "apikey",
    "x-auth-token", "x-amz-security-token", "x-csrf-token", "x-xsrf-token",
})

# urlencoded / JSON ボディや URL クエリでマスクするキーのトークン（部分一致）
_SENSITIVE_BODY_KEYS = (
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "apitoken", "access_token", "refresh_token", "client_secret",
    "sessionid", "session_id", "csrf", "xsrf", "authenticity_token",
)
_KEYS_ALT = "|".join(re.escape(k) for k in _SENSITIVE_BODY_KEYS)
# urlencoded: <key>=<value>  （key が機微トークンを含むとき value をマスク）
_RE_URLENCODED = re.compile(rf"(?i)([^&=?\s]*(?:{_KEYS_ALT})[^&=]*)=[^&]*")
# JSON: "<key>": "<value>"
_RE_JSON = re.compile(rf'(?i)("(?:[^"\\]*(?:{_KEYS_ALT})[^"\\]*)"\s*:\s*)"[^"]*"')


def _redact_headers(headers: dict) -> dict:
    if not isinstance(headers, dict):
        return headers
    return {
        k: (_REDACTED if str(k).lower() in _SENSITIVE_HEADERS else v)
        for k, v in headers.items()
    }


def _redact_text(text):
    """urlencoded ボディ / JSON ボディ中の機微フィールド値をマスクする。"""
    if not isinstance(text, str) or not text:
        return text
    text = _RE_URLENCODED.sub(lambda m: f"{m.group(1)}={_REDACTED}", text)
    text = _RE_JSON.sub(lambda m: f'{m.group(1)}"{_REDACTED}"', text)
    return text


def _redact_url(url):
    """URL のクエリ文字列に含まれる機微パラメータ値をマスクする。"""
    if not isinstance(url, str) or "?" not in url:
        return url
    base, _, query = url.partition("?")
    return f"{base}?{_redact_text(query)}"


class RequestLogger:
    """リクエスト/ペイロードを JSONL ファイルへ追記するロガー。"""

    def __init__(self, output_dir, *, enabled: bool = True):
        self.output_dir = Path(output_dir)
        self.enabled = enabled
        self.http_path = self.output_dir / "http_requests.jsonl"
        self.payload_path = self.output_dir / "payloads.jsonl"
        # NetworkCapture（同期）と Monitor（async）双方から呼ばれうるので
        # ファイル追記をロックで直列化する。
        self._lock = threading.Lock()
        self.http_count = 0
        self.payload_count = 0

    def _append(self, path: Path, record: dict) -> None:
        if not self.enabled:
            return
        try:
            line = json.dumps(record, ensure_ascii=False)
        except Exception:
            return
        with self._lock:
            try:
                with open(path, "a", encoding="utf-8") as fp:
                    fp.write(line + "\n")
            except Exception:
                # ログ保存はベストエフォート。失敗してもスキャンは継続する。
                pass

    def log_http(self, pair: Optional[dict]) -> None:
        """NetworkCapture が組み立てた request/response ペアを記録する。"""
        if not self.enabled or not pair:
            return
        req = pair.get("request", {}) or {}
        resp = pair.get("response", {}) or {}
        post_data = req.get("post_data")
        if isinstance(post_data, str) and len(post_data) > _MAX_POST_DATA:
            post_data = post_data[:_MAX_POST_DATA] + "...<truncated>"
        # 認証情報（Cookie/Authorization ヘッダ・パスワード等のボディ/クエリ）を
        # マスクしてから保存する。output/ は閲覧者へ配信されうるため。
        record = {
            "ts": req.get("timestamp") or time.time(),
            "method": req.get("method", ""),
            "url": _redact_url(req.get("url", "")),
            "request_headers": _redact_headers(req.get("headers", {})),
            "post_data": _redact_text(post_data),
            "status": resp.get("status"),
            "response_headers": _redact_headers(resp.get("headers", {})),
        }
        self._append(self.http_path, record)
        self.http_count += 1

    def log_payload(self, field: str, payload: str, check_type: str, url: str = "") -> None:
        """フィールドへ投入したペイロードを記録する。"""
        if not self.enabled:
            return
        record = {
            "ts": time.time(),
            "url": _redact_url(url),
            "field": field,
            "check_type": check_type,
            "payload": payload,
        }
        self._append(self.payload_path, record)
        self.payload_count += 1
