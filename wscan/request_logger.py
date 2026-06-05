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
import threading
import time
from pathlib import Path
from typing import Optional

# 巨大な post_data でログが肥大化するのを防ぐための上限（文字数）
_MAX_POST_DATA = 20000


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
        record = {
            "ts": req.get("timestamp") or time.time(),
            "method": req.get("method", ""),
            "url": req.get("url", ""),
            "request_headers": req.get("headers", {}),
            "post_data": post_data,
            "status": resp.get("status"),
            "response_headers": resp.get("headers", {}),
        }
        self._append(self.http_path, record)
        self.http_count += 1

    def log_payload(self, field: str, payload: str, check_type: str, url: str = "") -> None:
        """フィールドへ投入したペイロードを記録する。"""
        if not self.enabled:
            return
        record = {
            "ts": time.time(),
            "url": url,
            "field": field,
            "check_type": check_type,
            "payload": payload,
        }
        self._append(self.payload_path, record)
        self.payload_count += 1
