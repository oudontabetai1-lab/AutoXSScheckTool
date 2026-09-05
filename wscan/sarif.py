"""
SARIF Exporter
==============
SARIF 2.1.0 (Static Analysis Results Interchange Format) 形式で
スキャン結果を出力する。

GitHub Advanced Security / VS Code / Azure DevOps などの CI ツールと
ネイティブ統合するための標準フォーマット。

使い方:
    from wscan.sarif import SarifExporter
    exporter = SarifExporter()
    sarif_doc = exporter.export(findings_dicts, target_url="https://example.com")
    with open("report.sarif", "w") as f:
        json.dump(sarif_doc, f, ensure_ascii=False, indent=2)
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

# ── SARIF severity mapping ────────────────────────────────────────────────────
_SEVERITY_TO_LEVEL: dict[str, str] = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "note",
}

# ── Rule descriptions per check type ─────────────────────────────────────────
_RULE_DESCS: dict[str, str] = {
    "sqli":                "SQLインジェクション — ユーザー入力がSQLクエリに注入される",
    "sqli_auth_bypass":    "SQLインジェクション (認証回避) — ログインをバイパスできる",
    "xss":                 "クロスサイト・スクリプティング (反射型) — スクリプトが反射実行される",
    "dom_xss":             "DOM-based XSS — クライアントサイドの DOM 操作による XSS",
    "stored_xss":          "蓄積型 XSS — 悪意あるスクリプトが保存され他ユーザーに影響する",
    "os":                  "OSコマンド・インジェクション — サーバー上のOSコマンドが実行される",
    "ssti":                "サーバーサイド・テンプレート・インジェクション",
    "path_traversal":      "パス・トラバーサル — ディレクトリを越えた任意ファイルの読み取り",
    "open_redirect":       "オープンリダイレクト — 任意URLへのリダイレクトが可能",
    "csrf":                "CSRF — 正規ユーザーに意図しないリクエストを送信させられる",
    "cors":                "CORSの誤設定 — 任意オリジンからのクロスオリジンリクエストが可能",
    "header_injection":    "HTTPヘッダ・インジェクション / レスポンス分割",
    "mail_header":         "メールヘッダ・インジェクション",
    "clickjacking":        "クリックジャッキング — X-Frame-Options が未設定",
    "session":             "セッション管理の問題 — Cookie 属性の不備など",
    "privesc":             "権限昇格 — 低権限ユーザーが高権限リソースにアクセス可能",
    "ssrf":                "SSRF — サーバーを経由した内部リソースへのリクエスト送信",
    "xxe":                 "XXE — XML外部エンティティ参照による情報漏洩",
    "deserialization":     "安全でないデシリアライゼーション",
    "request_smuggling":   "HTTPリクエスト・スマグリング",
    "host_header":         "Hostヘッダ・インジェクション",
    "security_headers":    "セキュリティヘッダーの欠如",
    "info_disclosure":     "情報漏洩 — エラーメッセージ・バージョン情報など",
    "nosql":               "NoSQLインジェクション",
    "graphql":             "GraphQL の脆弱性 (イントロスペクション有効・インジェクションなど)",
    "jwt":                 "JWT の脆弱性 (alg=none・弱い秘密鍵など)",
    "ldap":                "LDAPインジェクション",
    "file_upload":         "安全でないファイルアップロード",
    "race_condition":      "競合状態 (TOCTOU) の脆弱性",
    "cms":                 "CMS 固有の脆弱性",
    "websocket":           "WebSocket インジェクション",
}

_TOOL_NAME = "AutoXSScheckTool"
_TOOL_URI  = "https://github.com/oudontabetai1-lab/AutoXSScheckTool"
_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "master/Schemata/sarif-schema-2.1.0.json"
)


from wscan.scanners.base import finding_dict_confirmed


class SarifExporter:
    """SARIF 2.1.0 ドキュメントを生成するエクスポーター。"""

    def export(
        self,
        findings: list[dict],
        target_url: str = "",
        tool_version: str = "1.0.0",
        coverage: dict | None = None,
    ) -> dict:
        """
        findings_dicts (Finding.to_dict() の出力リスト) から
        SARIF 2.1.0 ドキュメントを生成して返す。

        ``coverage``（engine.coverage_summary() の出力）を渡すと、run properties へ
        検査カバレッジ補助情報（registered/selected/not_selected/前提不足/state profile skip）
        を出す。SARIF 消費側が「0 findings＝安全ではない・未実行の検査がある」を判別できる
        （0016 観測性）。未指定なら従来どおり（後方互換）。
        """
        rules = self._build_rules(findings)
        results = [self._finding_to_result(f) for f in findings]
        confirmed_total = sum(1 for f in findings if finding_dict_confirmed(f))

        properties: dict = {
            "target": target_url,
            "total_findings": confirmed_total,
            "hypothesis_findings": len(findings) - confirmed_total,
            "total_results": len(findings),
        }
        coverage_props = self._build_coverage_properties(coverage)
        if coverage_props:
            properties["coverage"] = coverage_props

        return {
            "$schema": _SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": _TOOL_NAME,
                            "version": tool_version,
                            "informationUri": _TOOL_URI,
                            "rules": rules,
                        }
                    },
                    "originalUriBaseIds": {
                        "WEBROOT": {"uri": target_url or "https://unknown/"}
                    },
                    "results": results,
                    "properties": properties,
                }
            ],
        }

    @staticmethod
    def _build_coverage_properties(coverage: dict | None) -> dict:
        """coverage_summary から SARIF run properties 用の補助情報を組む（純粋）。

        registered/selected/not_selected（check_coverage）と、前提不足・state profile skip
        （prerequisite_coverage）を SARIF 消費側向けに平坦化する。coverage 無し/空なら空 dict。
        """
        if not coverage:
            return {}
        cc = coverage.get("check_coverage") or {}
        pc = coverage.get("prerequisite_coverage") or {}
        props: dict = {}
        if cc:
            props["check_coverage"] = {
                "registry_total": cc.get("registry_total", 0),
                "selected": cc.get("selected", []),
                "selected_count": cc.get("selected_count", 0),
                "not_selected": cc.get("not_selected", []),
                "coverage_status": cc.get("coverage_status", ""),
                "unknown_selected": cc.get("unknown_selected", []),
            }
        if pc:
            props["prerequisite_missing"] = [
                (m or {}).get("check", "")
                for m in (pc.get("prerequisite_missing") or [])
                if isinstance(m, dict)
            ]
            props["state_profile_skipped"] = [
                (s or {}).get("check", "")
                for s in (pc.get("state_profile_skipped") or [])
                if isinstance(s, dict)
            ]
        return props

    # ── helpers ───────────────────────────────────────────────────────────────

    def _build_rules(self, findings: list[dict]) -> list[dict]:
        """check_type の一意セットからルール定義リストを生成する。"""
        seen: set[str] = set()
        rules: list[dict] = []
        for f in findings:
            ct = f.get("check_type", "unknown")
            if ct in seen:
                continue
            seen.add(ct)
            severity = f.get("severity", "medium")
            level = _SEVERITY_TO_LEVEL.get(severity, "warning")
            desc = _RULE_DESCS.get(ct, ct)

            # 修正ガイダンス (remediation._STATIC_FIX から流用)
            help_text = self._get_remediation(ct)

            rules.append({
                "id": ct,
                "name": ct.replace("_", " ").title(),
                "shortDescription": {"text": desc},
                "fullDescription": {"text": desc},
                "help": {"text": help_text, "markdown": help_text},
                "defaultConfiguration": {"level": level},
                "properties": {
                    "tags": ["security", "web", ct],
                    "precision": "medium",
                    "problem.severity": severity,
                },
            })
        return rules

    @staticmethod
    def _finding_to_result(f: dict) -> dict:
        """Finding dict を SARIF result エントリに変換する。"""
        ct = f.get("check_type", "unknown")
        severity = f.get("severity", "medium")
        verified = finding_dict_confirmed(f)
        # 未確証 result は残すが、CI の脆弱性ゲート対象にはしない。
        level = _SEVERITY_TO_LEVEL.get(severity, "warning") if verified else "note"
        url = f.get("url", "")
        evidence = f.get("evidence", "")
        field_name = f.get("field_name", "")
        payload = f.get("payload", "")
        cvss = f.get("cvss_score", 0.0)
        confidence = f.get("confidence", "tentative")
        source = f.get("source", "scanner")

        message = evidence
        if field_name:
            message = f"[{field_name}] {message}"
        if payload:
            message = f"{message} (payload: {payload[:120]})"

        result: dict = {
            "ruleId": ct,
            "level": level,
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": url,
                            "uriBaseId": "WEBROOT",
                        },
                        "region": {"startLine": 1},
                    },
                    "logicalLocations": [
                        {"name": field_name or url, "kind": "parameter"}
                    ] if field_name else [],
                }
            ],
            "properties": {
                "cvss_score":       cvss,
                "cvss_vector":      f.get("cvss_vector", ""),
                "confidence":       confidence,
                "field_name":       field_name,
                "payload":          payload,
                "verified":         verified,
                # verified=False でも「実際に再現できず」と「例外で検証未実行(要手動確認)」を
                # SARIF 消費側が区別できるよう、理由を持つ note も出力する。
                "verification_note": f.get("verification_note", ""),
                # assumed は verified=False となるが、未再検証と再現失敗を区別するため
                # verification_state も明示する。空文字は旧 Finding（不明）の予約値として保つ。
                "verification_state": f.get("verification_state", ""),
                "source":           source,
                "agent_verified":   f.get("agent_verified", False),
                "compliance_refs":  f.get("compliance_refs", {}),
            },
        }

        # scanner は従来 fingerprint を維持し、Agent 由来だけ名前空間を分ける。
        fingerprint = f"{ct}:{url}:{field_name}"
        if source == "agent":
            fingerprint = f"agent:{fingerprint}"
        result["partialFingerprints"] = {
            "primaryLocationLineHash": fingerprint
        }

        return result

    @staticmethod
    def _get_remediation(check_type: str) -> str:
        """remediation モジュールの静的テンプレートから修正ガイダンスを取得する。"""
        try:
            from wscan.remediation import _STATIC_FIX
            return _STATIC_FIX.get(check_type, f"{check_type} の適切な入力検証と出力エスケープを実施してください。")
        except Exception:
            return f"{check_type} の適切な入力検証と出力エスケープを実施してください。"


def write_sarif(
    findings: list,
    target_url: str,
    output_path: "Path | str",
    tool_version: str = "1.0.0",
    coverage: dict | None = None,
) -> Path:
    """
    Finding オブジェクトのリスト (または to_dict() 済み dict のリスト) を
    SARIF ファイルとして output_path に書き出す。
    書き出したパスを返す。``coverage`` を渡すと run properties へ検査カバレッジを出す（0016）。
    """
    # Finding オブジェクト (to_dict メソッド持ち) → dict に変換
    findings_dicts: list[dict] = []
    for f in findings:
        if hasattr(f, "to_dict"):
            findings_dicts.append(f.to_dict())
        elif isinstance(f, dict):
            findings_dicts.append(f)

    exporter = SarifExporter()
    sarif_doc = exporter.export(
        findings_dicts, target_url=target_url, tool_version=tool_version, coverage=coverage
    )

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(sarif_doc, ensure_ascii=False, indent=2), encoding="utf-8")
    return out
