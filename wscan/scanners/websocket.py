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

# 検査ペイロード — (check_type, payload, detection_pattern)
_WS_PAYLOADS: list[tuple[str, str, str]] = [
    # XSS
    ("xss", "<script>alert('wsxss')</script>",    r"<script>alert\('wsxss'\)</script>"),
    ("xss", "<img src=x onerror=alert('wsxss')>", r"onerror=alert\('wsxss'\)"),
    # SQLi (エラーベース)
    ("sqli", "' OR '1'='1",                       r"(?i)(sql|syntax|mysql|sqlite|postgres|ora-[0-9]+)"),
    ("sqli", "1 UNION SELECT NULL--",             r"(?i)(sql|syntax|union|select)"),
    # OS インジェクション (エコーベース)
    ("os",   "; echo wsostest123;",               r"wsostest123"),
    ("os",   "| echo wsostest123",                r"wsostest123"),
    # SSTI
    ("ssti", "{{7*7}}",                           r"49"),
    ("ssti", "${7*7}",                            r"49"),
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
                ws_messages.append({"ws": ws, "data": data, "ts": time.time()})

            ws.on("framereceived", lambda payload: on_message(payload.get("payload", "")))

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

        for check_type, payload, detection_pattern in _WS_PAYLOADS:
            if check_type not in self.engine.checks:
                continue

            # 注入メッセージを構築
            inject_messages = self._build_inject_messages(payload, sample_json)

            for inject_msg, inject_key in inject_messages:
                responses: list[str] = []

                def capture(data):
                    responses.append(data.get("payload", "") if isinstance(data, dict) else str(data))

                ws.on("framereceived", capture)
                try:
                    # ペイロードを WS に送信
                    await ws.send(inject_msg)
                    await asyncio.sleep(1.0 * self.sleep_factor)
                except Exception:
                    pass
                finally:
                    ws.remove_listener("framereceived", capture)

                # レスポンスをパターンマッチ
                for resp in responses:
                    if re.search(detection_pattern, resp):
                        finding = Finding(
                            check_type=check_type,
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
                        )
                        findings.append(finding)
                        break  # このペイロードは確認済み、次へ

                if findings:
                    # 1件でも検出されたら次のペイロードへ
                    break

        return findings

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
