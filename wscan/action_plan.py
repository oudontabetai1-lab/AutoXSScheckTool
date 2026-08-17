"""Remediation action plan exporter.

Turns findings into ticket-friendly remediation artifacts.
"""
from __future__ import annotations

import json
from pathlib import Path

from .remediation import _get_static
from .scanners.base import Finding


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def write_action_plan(findings: list[Finding], output_dir: Path) -> dict:
    plan = build_action_plan(findings)
    tasks = plan["tasks"]
    review_items = plan["review_items"]

    json_path = output_dir / "remediation_tasks.json"
    md_path = output_dir / "remediation_plan.md"

    json_path.write_text(
        json.dumps(plan, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    md_path.write_text(_build_markdown(tasks, review_items), encoding="utf-8")

    return {
        "json": str(json_path),
        "markdown": str(md_path),
        "count": len(tasks),
        "review_count": len(review_items),
    }


def build_action_plan(findings: list[Finding]) -> dict:
    sorted_findings = _sort_findings(findings)
    actionable = [f for f in sorted_findings if _is_actionable(f)]
    review_only = [f for f in sorted_findings if not _is_actionable(f)]
    task_groups = _group_actionable_findings(actionable)
    tasks = [
        _task_from_finding(group[0], i + 1, related=group[1:])
        for i, group in enumerate(task_groups)
    ]
    review_groups = _group_actionable_findings(review_only)
    review_items = [
        _review_item_from_finding(group[0], i + 1, related=group[1:])
        for i, group in enumerate(review_groups)
    ]
    return {"tasks": tasks, "review_items": review_items}


def _is_actionable(f: Finding) -> bool:
    if f.verified is False:
        return False
    if f.confidence == "tentative":
        return False
    return True


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            _SEVERITY_RANK.get(f.severity, 99),
            0 if f.confidence == "confirmed" else 1 if f.confidence == "likely" else 2,
            f.url,
            f.field_name,
        ),
    )


def _group_actionable_findings(findings: list[Finding]) -> list[list[Finding]]:
    groups: dict[tuple, list[Finding]] = {}
    for finding in findings:
        groups.setdefault(_group_key(finding), []).append(finding)
    return list(groups.values())


def _group_key(f: Finding) -> tuple:
    details = f.evidence_details or {}
    if f.evidence_type == "sqli_auth_bypass":
        return (
            f.check_type,
            f.evidence_type,
            details.get("original_url", f.url),
            details.get("post_login_url", ""),
        )
    return (
        f.check_type,
        f.field_name,
        f.evidence_type,
        details.get("context", ""),
        details.get("sink", ""),
    )


def _task_from_finding(f: Finding, idx: int, related: list[Finding] | None = None) -> dict:
    related = related or []
    title = _task_title(f, related)
    url = _task_url(f)
    field_name = _task_field_name(f, related)
    priority = _priority_for(f)
    return {
        "id": f"WS-{idx:03d}",
        "title": title,
        "priority": priority,
        "severity": f.severity,
        "confidence": f.confidence,
        "verified": f.verified,
        # verified=True でも「実際に再現できた(reproduced)」と「検証を再実行できず維持
        # (assumed)」を消費側が区別できるよう state を出力。assumed は修正前に手動確証が
        # 必要な旨を needs_confirmation で明示する（タスク自体は落とさない＝過検知を消さない）。
        "verification_state": getattr(f, "verification_state", ""),
        "needs_confirmation": getattr(f, "verification_state", "") == "assumed",
        "check_type": f.check_type,
        "url": url,
        "field_name": field_name,
        "evidence_type": f.evidence_type,
        "evidence": f.evidence,
        "payload": f.payload,
        "reproduction_steps": f.reproduction_steps,
        "related_findings": [_related_finding_dict(r) for r in related],
        "recommended_fix": _get_static(f.check_type),
        "acceptance_criteria": _acceptance_criteria(f),
    }


def _task_title(f: Finding, related: list[Finding]) -> str:
    if f.evidence_type == "sqli_auth_bypass":
        return f"[{f.severity.upper()}] Fix SQLi authentication bypass on login form"
    return f"[{f.severity.upper()}] Fix {f.check_type} on {f.field_name}"


def _task_url(f: Finding) -> str:
    if f.evidence_type == "sqli_auth_bypass":
        return (f.evidence_details or {}).get("original_url", f.url)
    return f.url


def _task_field_name(f: Finding, related: list[Finding]) -> str:
    if f.evidence_type == "sqli_auth_bypass":
        names = sorted({f.field_name, *(r.field_name for r in related)})
        return ", ".join(names)
    return f.field_name


def _related_finding_dict(f: Finding) -> dict:
    return {
        "severity": f.severity,
        "confidence": f.confidence,
        "verified": f.verified,
        "verification_state": getattr(f, "verification_state", ""),
        "url": f.url,
        "field_name": f.field_name,
        "evidence_type": f.evidence_type,
        "evidence": f.evidence,
    }


def _review_item_from_finding(f: Finding, idx: int, related: list[Finding] | None = None) -> dict:
    related = related or []
    return {
        "id": f"WR-{idx:03d}",
        "title": f"Review {f.check_type} signal on {f.field_name}",
        "severity": f.severity,
        "confidence": f.confidence,
        "verified": f.verified,
        "verification_state": getattr(f, "verification_state", ""),
        "check_type": f.check_type,
        "url": f.url,
        "field_name": f.field_name,
        "evidence_type": f.evidence_type,
        "evidence": f.evidence,
        "related_signals": [_related_finding_dict(r) for r in related],
        "reason": "Not promoted to a remediation task because the finding is unverified or tentative.",
        "next_steps": [
            "Manually replay the captured payload and request context.",
            "Promote to a remediation task only if execution or exploitability is confirmed.",
        ],
    }


def _priority_for(f: Finding) -> str:
    if f.severity == "critical":
        return "P0" if f.confidence == "confirmed" else "P1"
    if f.severity == "high":
        return "P1"
    if f.severity == "medium":
        return "P2"
    return "P3"


def _acceptance_criteria(f: Finding) -> list[str]:
    criteria = [
        "The captured reproduction steps no longer trigger the finding.",
        "The affected endpoint has regression coverage for this input path.",
        "The remediation does not break expected valid input behavior.",
    ]
    if f.check_type in {"xss", "dom_xss", "stored_xss"}:
        criteria.append("User-controlled output is contextually encoded or safely sanitized.")
    elif f.check_type.startswith("sqli") or f.check_type == "nosql":
        criteria.append("Database access uses parameter binding or a safe ORM query API.")
    elif f.check_type in {
        "privesc",
        "privesc_unauth",
        "privesc_vertical",
        "privesc_horizontal",
        "privesc_param_idor",
        "privesc_cross_acct",
        "privesc_action",
        "privesc_bypass",
    }:
        criteria.append("Authorization checks are enforced server-side for the affected resource.")
    return criteria


def _build_markdown(tasks: list[dict], review_items: list[dict]) -> str:
    lines = [
        "# WScan Remediation Plan",
        "",
        f"Total tasks: {len(tasks)}",
        f"Review-only signals: {len(review_items)}",
        "",
    ]
    for task in tasks:
        lines.extend([
            f"## {task['id']} {task['title']}",
            "",
            f"- Priority: {task['priority']}",
            f"- Severity: {task['severity']}",
            f"- Confidence: {task['confidence']}",
            f"- Verification: {task['verification_state'] or 'reproduced/assumed'}"
            + ("（要手動確認：修正前に再現を確認）" if task["needs_confirmation"] else ""),
            f"- URL: `{task['url']}`",
            f"- Field: `{task['field_name']}`",
            f"- Evidence type: `{task['evidence_type']}`",
            f"- Related findings: {len(task['related_findings'])}",
            "",
            "Evidence:",
            "",
            f"> {task['evidence']}",
            "",
            "Reproduction:",
        ])
        for step in task["reproduction_steps"]:
            lines.append(f"- {step}")
        lines.extend(["", "Acceptance criteria:"])
        for criterion in task["acceptance_criteria"]:
            lines.append(f"- [ ] {criterion}")
        if task["related_findings"]:
            lines.extend(["", "Related findings:"])
            for related in task["related_findings"]:
                lines.append(
                    f"- `{related['url']}` field `{related['field_name']}` "
                    f"({related['evidence_type']}, {related['confidence']})"
                )
        lines.extend(["", "Recommended fix:", "", task["recommended_fix"], ""])
    if review_items:
        lines.extend(["", "# Review-only Signals", ""])
        for item in review_items:
            lines.extend([
                f"## {item['id']} {item['title']}",
                "",
                f"- Severity: {item['severity']}",
                f"- Confidence: {item['confidence']}",
                f"- Verified: {item['verified']}",
                # unreproduced（再現失敗）と skipped（検証未実行）は verified=False で潰れるため
                # operator の判断が変わる state を明示する（task 側と同様）。
                f"- Verification: {item['verification_state'] or 'unknown'}",
                f"- URL: `{item['url']}`",
                f"- Field: `{item['field_name']}`",
                f"- Evidence type: `{item['evidence_type']}`",
                f"- Related signals: {len(item['related_signals'])}",
                "",
                "Evidence:",
                "",
                f"> {item['evidence']}",
                "",
                "Next steps:",
            ])
            for step in item["next_steps"]:
                lines.append(f"- {step}")
            lines.append("")
    return "\n".join(lines)
