"""
Notification Manager
====================
重大な脆弱性検出時に Slack / 汎用 Webhook へ通知を送信する。

対応エンドポイント:
  - Slack Incoming Webhook (Block Kit 形式)
  - 汎用 JSON Webhook (POST application/json)

使い方:
    from wscan.notification import NotificationManager
    nm = NotificationManager(
        webhook_url="https://hooks.slack.com/...",
        min_severity="high",
    )
    await nm.notify_finding(finding, "https://target.example.com")
    await nm.notify_scan_complete(summary_dict, "https://target.example.com")
"""
from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from wscan.scanners.base import Finding

# 重大度の順序 (低い値 = より高い重大度)
_SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high":     1,
    "medium":   2,
    "low":      3,
    "info":     4,
}

_SEVERITY_COLOR: dict[str, str] = {
    "critical": "#742a2a",
    "high":     "#e53e3e",
    "medium":   "#dd6b20",
    "low":      "#d69e2e",
    "info":     "#4299e1",
}

_SEVERITY_EMOJI: dict[str, str] = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "🔵",
}


class NotificationManager:
    """
    脆弱性検出通知を Slack / 汎用 Webhook に送信する。

    Parameters
    ----------
    webhook_url   : 通知先 URL (Slack または汎用 POST エンドポイント)
    min_severity  : この重大度以上の検出のみ通知 (デフォルト: "high")
    notify_complete: スキャン完了時にサマリーを送信するか
    """

    def __init__(
        self,
        webhook_url: str = "",
        min_severity: str = "high",
        notify_complete: bool = True,
    ):
        self.webhook_url = webhook_url.strip()
        self.min_severity = min_severity
        self.notify_complete = notify_complete
        self._min_rank = _SEVERITY_RANK.get(min_severity, 1)
        self._notified: set[tuple] = set()  # dedup: (url, field_name, check_type)

    @property
    def enabled(self) -> bool:
        return bool(self.webhook_url)

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    async def notify_finding(self, finding: "Finding", target_url: str = "") -> None:
        """確証済みかつ重大度閾値以上の Finding を通知する。"""
        if not self.enabled:
            return
        if not finding.verified:
            return
        rank = _SEVERITY_RANK.get(finding.severity, 99)
        if rank > self._min_rank:
            return

        key = (finding.url, finding.field_name, finding.check_type)
        if key in self._notified:
            return
        self._notified.add(key)

        payload = self._build_finding_payload(finding, target_url)
        await self._send(payload)

    async def notify_scan_complete(
        self,
        summary: dict,
        target_url: str = "",
        report_path: str = "",
        sarif_path: str = "",
    ) -> None:
        """スキャン完了通知を送信する。"""
        if not self.enabled or not self.notify_complete:
            return
        payload = self._build_complete_payload(summary, target_url, report_path, sarif_path)
        await self._send(payload)

    # ──────────────────────────────────────────────────────────────────────────
    # Payload builders
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _build_finding_payload(finding: "Finding", target_url: str) -> dict:
        """Slack Block Kit + 汎用 JSON ペイロードを生成する。"""
        severity = finding.severity
        emoji = _SEVERITY_EMOJI.get(severity, "⚠️")
        color = _SEVERITY_COLOR.get(severity, "#718096")
        check = finding.check_type.upper()
        short_url = finding.url[:80] + ("..." if len(finding.url) > 80 else "")
        evidence = (finding.evidence or "")[:200]
        payload_str = (finding.payload or "")[:120]
        cvss = getattr(finding, "cvss_score", 0.0)

        text = f"{emoji} *{severity.upper()} — {check}* on `{short_url}`"
        details = []
        if finding.field_name:
            details.append(f"*フィールド*: `{finding.field_name}`")
        if evidence:
            details.append(f"*証拠*: {evidence}")
        if payload_str:
            details.append(f"*ペイロード*: `{payload_str}`")
        if cvss:
            details.append(f"*CVSS*: {cvss:.1f}")
        if target_url:
            details.append(f"*対象*: {target_url}")

        return {
            # Slack Block Kit
            "text": text,
            "attachments": [
                {
                    "color": color,
                    "title": f"{emoji} {severity.upper()}: {check}",
                    "title_link": finding.url,
                    "text": "\n".join(details),
                    "footer": "AutoXSScheckTool",
                    "ts": int(time.time()),
                }
            ],
            # 汎用フィールド (Slack 以外のエンドポイント向け)
            "severity":   severity,
            "check_type": finding.check_type,
            "url":        finding.url,
            "field_name": finding.field_name,
            "evidence":   evidence,
            "payload":    payload_str,
            "cvss_score": cvss,
            "target":     target_url,
        }

    @staticmethod
    def _build_complete_payload(
        summary: dict,
        target_url: str,
        report_path: str,
        sarif_path: str,
    ) -> dict:
        """スキャン完了サマリーペイロードを生成する。"""
        total = summary.get("total", 0)
        critical = summary.get("critical", 0)
        high = summary.get("high", 0)
        medium = summary.get("medium", 0)
        low = summary.get("low", 0)

        status_emoji = "🔴" if critical > 0 else ("🟠" if high > 0 else "🟡" if medium > 0 else "🟢")
        text = f"{status_emoji} *スキャン完了*: {target_url}"
        details = [
            f"🔴 Critical: {critical}　🟠 High: {high}　🟡 Medium: {medium}　🟢 Low: {low}",
            f"合計: {total} 件",
        ]
        if report_path:
            details.append(f"レポート: `{report_path}`")
        if sarif_path:
            details.append(f"SARIF: `{sarif_path}`")

        color = "#742a2a" if critical > 0 else ("#e53e3e" if high > 0 else "#d69e2e")

        return {
            "text": text,
            "attachments": [
                {
                    "color": color,
                    "title": f"スキャン完了 — {target_url}",
                    "text": "\n".join(details),
                    "footer": "AutoXSScheckTool",
                    "ts": int(time.time()),
                }
            ],
            "event":    "scan_complete",
            "target":   target_url,
            "summary":  summary,
        }

    # ──────────────────────────────────────────────────────────────────────────
    # HTTP transport
    # ──────────────────────────────────────────────────────────────────────────

    async def _send(self, payload: dict) -> None:
        """webhook_url に JSON を POST する。エラーは握り潰してログ出力。"""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    self.webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code not in (200, 201, 202, 204):
                    _log(f"Webhook POST failed: HTTP {resp.status_code}")
        except Exception as exc:
            _log(f"Webhook 送信エラー: {exc}")


def _log(msg: str) -> None:
    try:
        from rich.console import Console
        Console().print(f"  [yellow][Notification] {msg}[/yellow]")
    except Exception:
        print(f"[Notification] {msg}")
