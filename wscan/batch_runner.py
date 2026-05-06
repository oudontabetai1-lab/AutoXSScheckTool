"""
Batch Runner
============
複数の URL を順次（または並列）スキャンし、統合サマリーレポートを生成する。

CI/CD で複数のマイクロサービスやステージング環境を一括検査する用途を想定。

バッチ定義ファイル (YAML):
    global:
      depth: 2
      checks: [sqli, xss, os]
      llm: none
      headless: true

    targets:
      - url: https://app1.example.com
        label: "App1 Production"
        checks: [sqli, xss, os, csrf]
        auth_user: admin
        auth_pass: secret
      - url: https://app2.example.com
        label: "App2 Staging"
        depth: 3

使い方:
    from wscan.batch_runner import BatchRunner
    runner = BatchRunner.load_from_yaml("batch.yaml")
    results = await runner.run()
    print(runner.summary_text())
"""
from __future__ import annotations

import asyncio
import datetime
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class BatchTarget:
    """バッチスキャンの1ターゲット定義。"""
    url: str
    label: str = ""
    checks: list[str] = field(default_factory=list)
    depth: int = 2
    max_forms: int = 50
    timeout: int = 30
    headless: bool = True
    auth_user: str = ""
    auth_pass: str = ""
    login_url: str = ""
    cookies: str = ""
    output_dir: str = ""       # 空欄 = 自動生成


@dataclass
class BatchResult:
    """1ターゲットのスキャン結果サマリー。"""
    target: BatchTarget
    findings_count: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    output_dir: str = ""
    duration_secs: float = 0.0
    error: str = ""

    @property
    def success(self) -> bool:
        return not self.error

    def severity_summary(self) -> str:
        return (
            f"Critical={self.critical} High={self.high} "
            f"Medium={self.medium} Low={self.low}"
        )


class BatchRunner:
    """
    複数ターゲットを順次スキャンし、統合サマリーを生成するランナー。

    Parameters
    ----------
    targets      : BatchTarget のリスト
    global_kwargs: ScanEngine に渡す共通キーワード引数
    output_base  : 各ターゲット出力を格納するベースディレクトリ
    """

    def __init__(
        self,
        targets: list[BatchTarget],
        global_kwargs: Optional[dict] = None,
        output_base: Optional[Path] = None,
    ):
        self.targets = targets
        self.global_kwargs: dict = global_kwargs or {}
        self.output_base = output_base or (
            Path("output") / f"batch_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        self.results: list[BatchResult] = []

    # ──────────────────────────────────────────────────────────────────────────
    # Factory
    # ──────────────────────────────────────────────────────────────────────────

    @classmethod
    def load_from_yaml(cls, yaml_path: str) -> "BatchRunner":
        """
        YAML バッチ定義ファイルから BatchRunner を生成する。
        """
        import yaml  # PyYAML (requirements.txt に含まれる)
        p = Path(yaml_path)
        if not p.exists():
            raise FileNotFoundError(f"バッチファイルが見つかりません: {yaml_path}")
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        global_cfg: dict = data.get("global", {})
        targets: list[BatchTarget] = []
        for t in data.get("targets", []):
            target = BatchTarget(
                url=t["url"],
                label=t.get("label", t["url"]),
                checks=t.get("checks", global_cfg.get("checks", ["sqli", "xss"])),
                depth=int(t.get("depth", global_cfg.get("depth", 2))),
                max_forms=int(t.get("max_forms", global_cfg.get("max_forms", 50))),
                timeout=int(t.get("timeout", global_cfg.get("timeout", 30))),
                headless=bool(t.get("headless", global_cfg.get("headless", True))),
                auth_user=t.get("auth_user", global_cfg.get("auth_user", "")),
                auth_pass=t.get("auth_pass", global_cfg.get("auth_pass", "")),
                login_url=t.get("login_url", global_cfg.get("login_url", "")),
                cookies=t.get("cookies", global_cfg.get("cookies", "")),
                output_dir=t.get("output_dir", ""),
            )
            targets.append(target)

        # global_cfg から ScanEngine 共通オプションを構築
        global_kwargs = {}
        for key in ("llm", "sarif", "webhook_url", "notify_min_severity",
                    "request_delay", "fast_mode"):
            if key in global_cfg:
                global_kwargs[key] = global_cfg[key]

        return cls(targets=targets, global_kwargs=global_kwargs)

    # ──────────────────────────────────────────────────────────────────────────
    # Execution
    # ──────────────────────────────────────────────────────────────────────────

    async def run(self) -> list[BatchResult]:
        """全ターゲットを順次スキャンし、BatchResult のリストを返す。"""
        self.output_base.mkdir(parents=True, exist_ok=True)
        self.results = []
        for target in self.targets:
            result = await self._run_one(target)
            self.results.append(result)
        return self.results

    async def _run_one(self, target: BatchTarget) -> BatchResult:
        """1ターゲットをスキャンして BatchResult を返す。"""
        from wscan.engine import ScanEngine

        label = target.label or target.url
        _print(f"\n[Batch] スキャン開始: [cyan]{label}[/cyan]")

        # 出力ディレクトリを決定
        if target.output_dir:
            out_dir = str(target.output_dir)
        else:
            safe_host = re.sub(r"[^a-zA-Z0-9._-]", "_", target.url.split("://")[-1])[:60]
            out_dir = str(self.output_base / safe_host)

        start = time.time()
        try:
            kwargs = dict(self.global_kwargs)
            kwargs.update({
                "url":            target.url,
                "depth":          target.depth,
                "checks":         target.checks or ["sqli", "xss"],
                "max_forms":      target.max_forms,
                "timeout":        target.timeout,
                "headless":       target.headless,
                "auth_user":      target.auth_user,
                "auth_pass":      target.auth_pass,
                "login_url":      target.login_url,
                "cookies":        target.cookies,
                "output_dir":     out_dir,
                "open_report":    False,  # バッチモードでは自動オープン無効
            })
            # monitor は無効化 (バッチモードではポート競合を防ぐ)
            kwargs.pop("monitor", None)

            engine = ScanEngine(**kwargs)
            await engine.run()

            counts: dict[str, int] = {}
            for f in engine.all_findings:
                counts[f.severity] = counts.get(f.severity, 0) + 1

            result = BatchResult(
                target=target,
                findings_count=len(engine.all_findings),
                critical=counts.get("critical", 0),
                high=counts.get("high", 0),
                medium=counts.get("medium", 0),
                low=counts.get("low", 0),
                output_dir=out_dir,
                duration_secs=time.time() - start,
            )
        except Exception as exc:
            result = BatchResult(
                target=target,
                output_dir=out_dir,
                duration_secs=time.time() - start,
                error=str(exc),
            )
            _print(f"[Batch] エラー: {label} — {exc}")

        status = "✅" if result.success else "❌"
        _print(
            f"[Batch] {status} {label} — "
            f"{result.findings_count} 件 ({result.severity_summary()}) "
            f"[{result.duration_secs:.1f}s]"
        )
        return result

    # ──────────────────────────────────────────────────────────────────────────
    # Reporting
    # ──────────────────────────────────────────────────────────────────────────

    def summary_text(self) -> str:
        """リッチテキスト形式のバッチサマリーを返す。"""
        lines = [
            "=" * 60,
            f"  Batch Scan Summary — {len(self.results)} targets",
            "=" * 60,
        ]
        total_findings = 0
        for r in self.results:
            label = r.target.label or r.target.url
            status = "✅" if r.success else f"❌ ({r.error[:50]})"
            lines.append(
                f"  {status} {label[:40]:<40} "
                f"Total={r.findings_count:3d}  "
                f"C={r.critical} H={r.high} M={r.medium} L={r.low}  "
                f"[{r.duration_secs:.1f}s]"
            )
            total_findings += r.findings_count
        lines.append("-" * 60)
        lines.append(f"  合計: {total_findings} 件の脆弱性が検出されました")
        lines.append(f"  出力: {self.output_base}")
        return "\n".join(lines)

    def save_batch_summary_json(self) -> Path:
        """バッチサマリーを JSON ファイルとして保存する。"""
        import json
        summary = {
            "scan_date": datetime.datetime.now().isoformat(),
            "output_base": str(self.output_base),
            "targets": [
                {
                    "url":            r.target.url,
                    "label":          r.target.label,
                    "findings_count": r.findings_count,
                    "critical":       r.critical,
                    "high":           r.high,
                    "medium":         r.medium,
                    "low":            r.low,
                    "output_dir":     r.output_dir,
                    "duration_secs":  round(r.duration_secs, 2),
                    "error":          r.error,
                    "success":        r.success,
                }
                for r in self.results
            ],
            "total_findings": sum(r.findings_count for r in self.results),
            "total_critical": sum(r.critical for r in self.results),
            "total_high":     sum(r.high for r in self.results),
        }
        out = self.output_base / "batch_summary.json"
        out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        return out


def _print(msg: str) -> None:
    try:
        from rich.console import Console
        Console().print(msg)
    except Exception:
        print(msg)
