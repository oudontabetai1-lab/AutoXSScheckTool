"""
WebSocket Injection Scanner
============================
Playwright の WebSocket イベントフックを使い、WS エンドポイントへの
メッセージにペイロードを注入してインジェクション脆弱性を検査する。

検査パターン:
  - XSS ペイロード (反射型 / 蓄積型)
  - SQLi ペイロード (エラー応答)
  - OSコマンドインジェクション (タイムディレイ)
  - JSONフィールドへのネスト注入

動作:
  1. scan_page() でページをナビゲートし、WS 接続を観測する
  2. 接続されたメッセージの JSON 構造を解析
  3. 各フィールドにペイロードを注入したメッセージを送信
  4. WS レスポンスをパターンマッチで検査
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from typing import TYPE_CHECKING

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine

# 検査ペイロード — (underlying_type, payload, detection_pattern, evidence_type)
_WS_PAYLOADS: list[tuple[str, str, str, str]] = [
    # XSS
    ("xss", "<script>alert('wsxss')</script>",    r"<script>alert\('wsxss'\)</script>", "websocket_xss_reflection"),
    ("xss", "<img src=x onerror=alert('wsxss')>", r"onerror=alert\('wsxss'\)", "websocket_xss_reflection"),
    # SQLi (エラーベース)
    ("sqli", "' OR '1'='1",                       r"(?i)(sql|syntax|mysql|sqlite|postgres|ora-[0-9]+)", "websocket_sqli_error"),
    ("sqli", "1 UNION SELECT NULL--",             r"(?i)(sql|syntax|union|select)", "websocket_sqli_error"),
    # OS インジェクション (エコーベース)
    ("os",   "; echo wsostest123;",               r"wsostest123", "websocket_os_echo"),
    ("os",   "| echo wsostest123",                r"wsostest123", "websocket_os_echo"),
    # SSTI
    ("ssti", "{{7*7}}",                           r"49", "websocket_ssti_eval"),
    ("ssti", "${7*7}",                            r"49", "websocket_ssti_eval"),
]

# JSON フィールド注入対象 (よく使われる WS メッセージキー)
_INJECT_KEYS = {
    "message", "msg", "text", "content", "data", "input",
    "query", "q", "search", "cmd", "command", "action",
    "id", "user", "username", "name", "value",
}


class WebSocketScanner(BaseScanner):
    """WebSocket エンドポイントへのインジェクション脆弱性を検査するスキャナー。"""

    CHECK_TYPE = "websocket"
    SEVERITY = "high"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._ws_urls: set[str] = set()
        self._observed_messages: list[str] = []

    # ──────────────────────────────────────────────────────────────────────────
    # BaseScanner interface
    # ──────────────────────────────────────────────────────────────────────────

    async def scan_field(self, url: str, form_index: int, field: dict,
                         is_url_param: bool = False) -> list[Finding]:
        return []  # WebSocket はフィールドスキャンではなくページスキャンで動作

    async def scan_page(self, url: str) -> list[Finding]:
        """
        WS 接続を観測し、ペイロードを注入して脆弱性を検査する。
        WS エンドポイントが検出されなかった場合は空リストを返す。
        """
        findings: list[Finding] = []

        ws_messages: list[dict] = []  # {"ws": WS object, "data": str}
        ws_endpoints: list = []

        page = self.browser.page

        def on_websocket(ws):
            ws_endpoints.append(ws)
            self._ws_urls.add(ws.url)

            def on_message(data):
                payload = data.get("payload", "") if isinstance(data, dict) else str(data)
                ws_messages.append({"ws": ws, "data": payload, "ts": time.time()})

            ws.on("framereceived", on_message)

        page.on("websocket", on_websocket)

        try:
            await self.browser.navigate(url)
            # WS 接続が確立されるまで最大 3 秒待機
            await asyncio.sleep(3.0 * self.sleep_factor)
        finally:
            page.remove_listener("websocket", on_websocket)

        if not ws_endpoints:
            return []  # WS 接続なし

        # 観測されたメッセージから JSON 構造を推定
        sample_json: dict | None = None
        for m in ws_messages[:5]:
            try:
                parsed = json.loads(m.get("data", ""))
                if isinstance(parsed, dict):
                    sample_json = parsed
                    break
            except (json.JSONDecodeError, TypeError):
                pass

        # 各 WS エンドポイントに対してペイロードを注入
        for ws in ws_endpoints[:3]:  # 最大 3 エンドポイントを検査
            ws_findings = await self._test_websocket(ws, url, sample_json, ws_messages)
            findings.extend(ws_findings)

        return findings

    # ──────────────────────────────────────────────────────────────────────────
    # Internal
    # ──────────────────────────────────────────────────────────────────────────

    async def _test_websocket(
        self,
        ws,
        page_url: str,
        sample_json: dict | None,
        baseline_messages: list[dict],
    ) -> list[Finding]:
        """1つの WebSocket エンドポイントに対してペイロードを注入する。"""
        findings: list[Finding] = []
        ws_url = ws.url

        for underlying_type, payload, detection_pattern, evidence_type in self._active_payloads():
            if any(
                f.evidence_type == evidence_type
                and f.evidence_details.get("underlying_type") == underlying_type
                for f in findings
            ):
                continue

            # 注入メッセージを構築
            inject_messages = self._build_inject_messages(payload, sample_json)

            for inject_msg, inject_key in inject_messages:
                responses = await self._send_ws_message(ws_url, inject_msg)

                # レスポンスをパターンマッチ
                for resp in responses:
                    if self._response_matches(resp, detection_pattern):
                        finding = Finding(
                            check_type=self.CHECK_TYPE,
                            severity=self.SEVERITY,
                            url=page_url,
                            field_name=f"ws:{inject_key or 'message'}",
                            payload=inject_msg[:200],
                            evidence=(
                                f"WebSocket ({ws_url}) がペイロードに応答: "
                                f"{resp[:200]}"
                            ),
                            request={"ws_url": ws_url, "sent": inject_msg[:500]},
                            response={"ws_url": ws_url, "received": resp[:500]},
                            confidence="likely",
                            evidence_type=evidence_type,
                            evidence_details={
                                "ws_url": ws_url,
                                "underlying_type": underlying_type,
                                "inject_key": inject_key,
                                "pattern": detection_pattern,
                                "sent": inject_msg,
                            },
                        )
                        findings.append(finding)
                        break  # このペイロードは確認済み、次へ

                if any(f.evidence_type == evidence_type for f in findings):
                    # 1件でも検出されたら次のペイロードへ
                    break

        return findings

    def _active_payloads(self) -> list[tuple[str, str, str, str]]:
        checks = set(getattr(self.engine, "checks", []) or [])
        if self.CHECK_TYPE in checks:
            return list(_WS_PAYLOADS)
        return [entry for entry in _WS_PAYLOADS if entry[0] in checks]

    def _response_matches(self, response: str, pattern: str) -> bool:
        return bool(re.search(pattern, response or ""))

    async def _send_ws_message(self, ws_url: str, message: str) -> list[str]:
        wait_ms = max(250, int(1000 * self.sleep_factor))
        try:
            result = await self.browser.page.evaluate(
                """
                ({ wsUrl, message, waitMs }) => new Promise((resolve) => {
                  const responses = [];
                  let done = false;
                  const finish = () => {
                    if (done) return;
                    done = true;
                    try { socket.close(); } catch (_) {}
                    resolve(responses);
                  };
                  let socket;
                  try {
                    socket = new WebSocket(wsUrl);
                  } catch (_) {
                    resolve([]);
                    return;
                  }
                  socket.onmessage = (event) => responses.push(String(event.data));
                  socket.onerror = finish;
                  socket.onopen = () => {
                    try { socket.send(message); } catch (_) { finish(); return; }
                    setTimeout(finish, waitMs);
                  };
                  setTimeout(finish, waitMs + 1000);
                })
                """,
                {"wsUrl": ws_url, "message": message, "waitMs": wait_ms},
            )
            return [str(item) for item in (result or [])]
        except Exception:
            return []

    async def verify_finding(self, finding: Finding) -> bool | None:
        details = getattr(finding, "evidence_details", {}) or {}
        ws_url = details.get("ws_url") or (finding.request or {}).get("ws_url")
        pattern = details.get("pattern")
        sent = details.get("sent") or finding.payload
        if not ws_url or not pattern or not sent:
            return None
        responses = await self._send_ws_message(ws_url, sent)
        return any(self._response_matches(resp, pattern) for resp in responses)

    def _build_inject_messages(
        self,
        payload: str,
        sample_json: dict | None,
    ) -> list[tuple[str, str]]:
        """
        注入メッセージのリストを生成する。
        JSON の場合は各フィールドを個別に注入した変種も生成する。
        """
        messages: list[tuple[str, str]] = []

        if sample_json is not None:
            # JSON フォーマット: 注入対象キーを1つずつ置換
            for key in sample_json:
                if key.lower() in _INJECT_KEYS or len(messages) < 3:
                    injected = dict(sample_json)
                    injected[key] = payload
                    messages.append((json.dumps(injected), key))
                    if len(messages) >= 3:
                        break
        else:
            # プレーンテキスト: ペイロードをそのまま送信
            messages.append((payload, ""))
            # JSON フォーマットも試みる
            for key in list(_INJECT_KEYS)[:3]:
                messages.append((json.dumps({key: payload}), key))

        return messages[:5]  # 最大 5 パターン
