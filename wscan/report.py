"""
WScan Report Generator
Generates a self-contained HTML security assessment report.
"""
import datetime
import json
from pathlib import Path
from typing import Optional, TYPE_CHECKING

from .scanners.base import Finding

if TYPE_CHECKING:
    from .attack_planner import PageAttackPlan

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {
    "critical": "#e53e3e",
    "high": "#dd6b20",
    "medium": "#d69e2e",
    "low": "#38a169",
    "info": "#4299e1",
}

# Risk score → colour
def _risk_color(score: int) -> str:
    if score >= 8:
        return "#e53e3e"
    if score >= 6:
        return "#dd6b20"
    if score >= 4:
        return "#d69e2e"
    return "#38a169"


class ReportGenerator:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    def generate(
        self,
        target: str,
        findings: list[Finding],
        visited_urls: list[str],
        checks: list[str],
        attack_plans: "Optional[list[PageAttackPlan]]" = None,
        ctf_flags: "Optional[list]" = None,
        page_graph: "Optional[dict]" = None,
        template: str = "audit",
        diff_result=None,
    ):
        """
        Generate HTML report and save to output directory.

        Parameters
        ----------
        template  : "audit" (default/full detail) | "executive" | "developer"
        diff_result : DiffResult or None
        """
        sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

        if template == "executive":
            html = self._build_executive_html(target, sorted_findings, visited_urls, checks,
                                               attack_plans or [], ctf_flags or [], page_graph or {},
                                               diff_result)
            report_path = self.output_dir / "report_executive.html"
        elif template == "developer":
            html = self._build_developer_html(target, sorted_findings, visited_urls, checks,
                                               attack_plans or [], ctf_flags or [], page_graph or {},
                                               diff_result)
            report_path = self.output_dir / "report_developer.html"
        else:
            html = self._build_html(target, sorted_findings, visited_urls, checks,
                                    attack_plans or [], ctf_flags or [], page_graph or {},
                                    diff_result)
            report_path = self.output_dir / "report.html"

        report_path.write_text(html, encoding="utf-8")
        return report_path

    def _build_html(
        self,
        target: str,
        findings: list[Finding],
        visited_urls: list[str],
        checks: list[str],
        attack_plans: "list[PageAttackPlan]" = None,
        ctf_flags: list = None,
        page_graph: dict = None,
        diff_result=None,
    ) -> str:
        attack_plans = attack_plans or []
        ctf_flags = ctf_flags or []
        page_graph = page_graph or {}
        scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total = len(findings)
        counts = {}
        for sev in ["critical", "high", "medium", "low"]:
            counts[sev] = sum(1 for f in findings if f.severity == sev)

        findings_html = ""
        for i, f in enumerate(findings):
            color = SEVERITY_COLORS.get(f.severity, "#718096")
            screenshot_html = ""
            if f.screenshot_b64:
                screenshot_html = f"""
                <div class="screenshot-container">
                    <h4>Screenshot</h4>
                    <img src="data:image/jpeg;base64,{f.screenshot_b64}" alt="Evidence screenshot" class="evidence-screenshot">
                </div>"""

            req = f.request or {}
            resp = f.response or {}
            req_html = self._format_request(req)
            resp_html = self._format_response(resp, f)

            extra_badges = ""
            if "[ChainDetect]" in f.evidence:
                extra_badges += '<span class="badge-chain">🔗 Chain</span>'
            if "[MultiParam]" in f.evidence:
                extra_badges += '<span class="badge-multi">⚡ MultiParam</span>'
            if "[AdaptiveAI]" in f.evidence:
                extra_badges += '<span class="badge-ai">🧠 AdaptiveAI</span>'
            if not getattr(f, "verified", True):
                note = self._escape(getattr(f, "verification_note", ""))
                extra_badges += f'<span class="badge-unconfirmed" title="{note}">⚠ 要確認</span>'
            # E: 信頼度バッジ
            conf = getattr(f, "confidence", "tentative")
            conf_labels = {"confirmed": ("✔ 確認済", "#276749"), "likely": ("〜 可能性高", "#744210"), "tentative": ("? 暫定", "#4a5568")}
            conf_label, conf_color = conf_labels.get(conf, conf_labels["tentative"])
            extra_badges += f'<span class="badge-confidence" style="background:{conf_color}">{conf_label}</span>'
            # I: 差分バッジ
            diff_status = getattr(f, "_diff_status", "") or f.__dict__.get("_diff_status", "")
            if diff_status == "new":
                extra_badges += '<span class="badge-diff-new">🆕 新規</span>'
            elif diff_status == "persistent":
                extra_badges += '<span class="badge-diff-persist">🔄 継続</span>'

            cvss_score = getattr(f, "cvss_score", 0.0)
            cvss_vector = getattr(f, "cvss_vector", "")
            cvss_html = ""
            if cvss_score > 0:
                sc = cvss_score
                sc_color = "#e53e3e" if sc >= 9 else ("#dd6b20" if sc >= 7 else ("#d69e2e" if sc >= 4 else "#38a169"))
                cvss_html = (
                    f'<span class="cvss-badge" style="background:{sc_color}" '
                    f'title="{self._escape(cvss_vector)}">CVSS {sc:.1f}</span>'
                )

            # ⑨ AI fix suggestion (attached to Finding by engine._ai_analysis_report)
            ai_fix_text = f.__dict__.get("ai_fix", "")
            ai_fix_html = ""
            if ai_fix_text:
                ai_fix_safe = self._escape(ai_fix_text).replace("\n", "<br>")
                ai_fix_html = f"""
                    <div class="finding-detail ai-fix-section">
                        <h4>🤖 AI 推奨修正 (AI Fix Suggestion)</h4>
                        <div class="ai-fix-body">{ai_fix_safe}</div>
                    </div>"""

            findings_html += f"""
            <div class="finding-card" id="finding-{i}"
                 data-severity="{f.severity}" data-check="{f.check_type}"
                 data-url="{self._escape(f.url)}" data-field="{self._escape(f.field_name)}">
                <div class="finding-header" style="border-left: 4px solid {color}">
                    <div class="finding-title">
                        <span class="badge" style="background:{color}">{f.severity.upper()}</span>
                        <span class="check-type">{f.check_type.upper()}</span>
                        <span class="field-name">Field: {self._escape(f.field_name)}</span>
                        {cvss_html}
                        {extra_badges}
                    </div>
                    <div class="finding-url">{self._escape(f.url)}</div>
                </div>
                <div class="finding-body">
                    <div class="finding-detail">
                        <h4>Evidence</h4>
                        <p class="evidence-text">{self._escape(f.evidence)}</p>
                    </div>
                    <div class="finding-detail">
                        <h4>Payload Used</h4>
                        <code class="payload-code">{self._escape(f.payload)}</code>
                    </div>
                    {screenshot_html}
                    <div class="network-grid">
                        {req_html}
                        {resp_html}
                    </div>
                    {ai_fix_html}
                </div>
            </div>"""

        urls_html = "".join(
            f'<li class="url-item">{self._escape(u)}</li>' for u in visited_urls
        )

        no_findings_html = ""
        if not findings:
            no_findings_html = """
            <div class="no-findings">
                <div class="no-findings-icon">✓</div>
                <p>No vulnerabilities detected in scanned scope.</p>
                <p class="note">This does not guarantee security. The tool tests known patterns only.</p>
            </div>"""

        # ── Attack Plan section ──────────────────────────────────────────
        attack_plan_html = self._build_attack_plan_html(attack_plans)

        # ── CTF Flags section ────────────────────────────────────────────
        ctf_flags_html = self._build_ctf_flags_html(ctf_flags)

        # ── Page flow diagram section ─────────────────────────────────────
        page_flow_html = self._build_page_flow_html(page_graph)

        # ⑧ Attack chain / AI analysis section (reads ai_analysis.md if present)
        ai_analysis_html = self._build_ai_analysis_html()

        return f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WScan Security Report — {self._escape(target)}</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #f7f8fa; color: #1a202c; line-height: 1.6; }}
.header {{ background: linear-gradient(135deg, #1a202c 0%, #2d3748 100%); color: white; padding: 40px; }}
.header h1 {{ font-size: 2rem; font-weight: 700; margin-bottom: 8px; }}
.header .subtitle {{ color: #a0aec0; font-size: 0.95rem; }}
.header .target {{ color: #63b3ed; font-size: 1.1rem; margin-top: 12px; word-break: break-all; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 32px 24px; }}
.summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 32px; }}
.summary-card {{ background: white; border-radius: 12px; padding: 20px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
.summary-card .count {{ font-size: 2.5rem; font-weight: 800; }}
.summary-card .label {{ font-size: 0.85rem; color: #718096; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.05em; }}
.critical-count {{ color: #e53e3e; }}
.high-count {{ color: #dd6b20; }}
.medium-count {{ color: #d69e2e; }}
.low-count {{ color: #38a169; }}
.total-count {{ color: #4299e1; }}
.section {{ background: white; border-radius: 12px; padding: 24px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
.section h2 {{ font-size: 1.25rem; font-weight: 700; margin-bottom: 20px; padding-bottom: 12px; border-bottom: 2px solid #e2e8f0; }}
.finding-card {{ border: 1px solid #e2e8f0; border-radius: 10px; margin-bottom: 20px; overflow: hidden; }}
.finding-header {{ padding: 16px 20px; background: #f8fafc; display: flex; flex-direction: column; gap: 8px; }}
.finding-title {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
.badge {{ color: white; padding: 3px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 700; letter-spacing: 0.05em; }}
.badge-chain {{ background:#744210; color:#fefcbf; padding:2px 8px; border-radius:10px; font-size:0.72rem; font-weight:700; }}
.badge-multi {{ background:#1a365d; color:#bee3f8; padding:2px 8px; border-radius:10px; font-size:0.72rem; font-weight:700; }}
.badge-ai {{ background:#44337a; color:#e9d8fd; padding:2px 8px; border-radius:10px; font-size:0.72rem; font-weight:700; }}
.badge-unconfirmed {{ background:#d97706; color:#fff; padding:2px 8px; border-radius:10px; font-size:0.72rem; font-weight:700; cursor:help; }}
.badge-confidence {{ color:#fff; padding:2px 8px; border-radius:10px; font-size:0.72rem; font-weight:700; }}
.badge-diff-new {{ background:#276749; color:#f0fff4; padding:2px 8px; border-radius:10px; font-size:0.72rem; font-weight:700; }}
.badge-diff-persist {{ background:#2b6cb0; color:#ebf8ff; padding:2px 8px; border-radius:10px; font-size:0.72rem; font-weight:700; }}
.cvss-badge {{ color:white; padding:2px 8px; border-radius:10px; font-size:0.72rem; font-weight:700; cursor:help; }}
.filter-bar {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:20px; align-items:center; }}
.filter-bar label {{ font-size:0.85rem; color:#4a5568; font-weight:600; }}
.filter-bar select, .filter-bar input {{ border:1px solid #e2e8f0; border-radius:6px; padding:6px 10px; font-size:0.85rem; background:white; }}
.filter-bar input {{ min-width:200px; }}
.check-type {{ font-weight: 700; font-size: 1rem; }}
.field-name {{ color: #4a5568; font-size: 0.9rem; }}
.finding-url {{ font-size: 0.85rem; color: #718096; word-break: break-all; }}
.finding-body {{ padding: 20px; display: flex; flex-direction: column; gap: 16px; }}
.finding-detail h4 {{ font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.08em; color: #718096; margin-bottom: 8px; }}
.evidence-text {{ background: #fff8f0; border: 1px solid #fbd38d; border-radius: 6px; padding: 10px 14px; font-size: 0.9rem; color: #744210; }}
.payload-code {{ display: block; background: #1a202c; color: #68d391; padding: 10px 14px; border-radius: 6px; font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 0.85rem; word-break: break-all; white-space: pre-wrap; }}
.network-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
@media (max-width: 768px) {{ .network-grid {{ grid-template-columns: 1fr; }} }}
.network-box h4 {{ font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.08em; color: #718096; margin-bottom: 8px; }}
.network-content {{ background: #f7f8fa; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px 14px; font-family: monospace; font-size: 0.8rem; max-height: 200px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; }}
.screenshot-container h4 {{ font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.08em; color: #718096; margin-bottom: 8px; }}
.evidence-screenshot {{ width: 100%; border: 1px solid #e2e8f0; border-radius: 6px; cursor: pointer; transition: transform 0.2s; }}
.evidence-screenshot:hover {{ transform: scale(1.01); }}
.no-findings {{ text-align: center; padding: 48px; color: #718096; }}
.no-findings-icon {{ font-size: 4rem; color: #68d391; margin-bottom: 16px; }}
.no-findings p {{ font-size: 1.1rem; margin-bottom: 8px; }}
.no-findings .note {{ font-size: 0.85rem; color: #a0aec0; }}
.url-list {{ list-style: none; }}
.url-item {{ padding: 6px 12px; border-radius: 4px; font-family: monospace; font-size: 0.85rem; word-break: break-all; }}
.url-item:nth-child(even) {{ background: #f7f8fa; }}
.scan-meta {{ display: flex; gap: 24px; flex-wrap: wrap; }}
.meta-item {{ display: flex; flex-direction: column; gap: 2px; }}
.meta-label {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; color: #718096; }}
.meta-value {{ font-weight: 600; }}
.footer {{ text-align: center; color: #a0aec0; font-size: 0.8rem; padding: 32px; }}
.lightbox {{ display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.85); z-index: 1000; justify-content: center; align-items: center; }}
.lightbox.active {{ display: flex; }}
.lightbox img {{ max-width: 95%; max-height: 95vh; border-radius: 8px; }}
.lightbox-close {{ position: fixed; top: 20px; right: 20px; color: white; font-size: 2rem; cursor: pointer; background: rgba(0,0,0,0.5); width: 44px; height: 44px; border-radius: 50%; display: flex; align-items: center; justify-content: center; }}
/* ── Attack Plan styles ── */
.plan-section-meta {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:20px; }}
.plan-stat-card {{ background:#ebf8ff; border:1px solid #bee3f8; border-radius:8px; padding:12px 20px; text-align:center; min-width:100px; }}
.plan-stat-card .ps-count {{ font-size:1.8rem; font-weight:800; }}
.plan-stat-card .ps-label {{ font-size:0.75rem; color:#2b6cb0; text-transform:uppercase; letter-spacing:.05em; }}
.ps-high {{ background:#fff5f5; border-color:#fed7d7; }} .ps-high .ps-count {{ color:#e53e3e; }}
.ps-mid  {{ background:#fffaf0; border-color:#fbd38d; }} .ps-mid  .ps-count {{ color:#dd6b20; }}
.ps-low  {{ background:#f0fff4; border-color:#9ae6b4; }} .ps-low  .ps-count {{ color:#276749; }}
.plan-card {{ border:1px solid #bee3f8; border-radius:10px; margin-bottom:20px; overflow:hidden; }}
.plan-card-header {{ background:#ebf8ff; padding:14px 20px; border-bottom:1px solid #bee3f8; display:flex; justify-content:space-between; align-items:start; cursor:pointer; user-select:none; }}
.plan-card-header:hover {{ background:#dbeafe; }}
.plan-header-left {{ display:flex; flex-direction:column; gap:4px; }}
.plan-url {{ font-family:monospace; font-size:.85rem; color:#2b6cb0; word-break:break-all; }}
.plan-purpose {{ font-size:.9rem; color:#1a365d; font-weight:600; }}
.plan-by {{ font-size:.75rem; color:#718096; }}
.plan-by.llm {{ color:#6b46c1; font-weight:600; }}
.plan-toggle {{ font-size:1.2rem; color:#4299e1; transition:transform .2s; padding-left:12px; }}
.plan-card.collapsed .plan-toggle {{ transform:rotate(-90deg); }}
.plan-card.collapsed .plan-fields {{ display:none; }}
.plan-fields {{ padding:16px 20px; display:flex; flex-direction:column; gap:10px; }}
.plan-cols-header {{ display:grid; grid-template-columns:160px 56px 1fr 1.6fr; gap:12px; padding:0 0 6px; font-size:.72rem; font-weight:700; text-transform:uppercase; letter-spacing:.06em; color:#a0aec0; border-bottom:2px solid #e2e8f0; margin-bottom:6px; }}
.plan-field-row {{ display:grid; grid-template-columns:160px 56px 1fr 1.6fr; gap:12px; align-items:start; font-size:.85rem; border-bottom:1px solid #f0f4f8; padding-bottom:10px; }}
.plan-field-row:last-child {{ border-bottom:none; padding-bottom:0; }}
.plan-field-name {{ font-family:monospace; font-weight:600; color:#2d3748; word-break:break-all; }}
.plan-risk-badge {{ width:44px; height:44px; border-radius:50%; display:flex; align-items:center; justify-content:center; color:white; font-size:1.05rem; font-weight:800; flex-shrink:0; }}
.plan-checks {{ display:flex; flex-wrap:wrap; gap:4px; align-content:start; }}
.plan-check-badge {{ background:#e2e8f0; color:#4a5568; border-radius:4px; padding:2px 7px; font-size:.75rem; font-weight:600; }}
.plan-check-badge.priority-0 {{ background:#fed7d7; color:#742a2a; }}
.plan-check-badge.priority-1 {{ background:#feebc8; color:#7b341e; }}
.plan-rationale-col {{ display:flex; flex-direction:column; gap:6px; }}
.plan-rationale {{ color:#718096; font-size:.82rem; font-style:italic; }}
.cross-page-tag {{ display:inline-block; background:#e9d8fd; color:#553c9a; border-radius:4px; padding:1px 6px; font-size:.72rem; font-weight:700; font-style:normal; }}
.plan-payloads-toggle {{ font-size:.75rem; color:#4299e1; cursor:pointer; text-decoration:underline; margin-top:4px; }}
.plan-payload-list {{ display:none; margin-top:6px; background:#1a202c; border-radius:6px; padding:8px 12px; }}
.plan-payload-list.open {{ display:block; }}
.plan-payload-list code {{ display:block; color:#68d391; font-family:monospace; font-size:.78rem; padding:2px 0; word-break:break-all; }}
.plan-payload-type {{ color:#a0aec0; font-size:.7rem; margin-bottom:4px; }}
.no-plans {{ color:#a0aec0; font-size:.9rem; padding:16px 0; }}
@media (max-width:768px) {{ .plan-cols-header,.plan-field-row {{ grid-template-columns:1fr 44px 1fr; }} .plan-rationale-col {{ display:none; }} }}
/* ── Page Flow Diagram styles ── */
.page-flow-wrapper {{ overflow-x: auto; }}
.page-flow-svg {{ min-width: 100%; }}
.page-node {{ cursor: pointer; }}
.page-node rect {{ fill: #ebf8ff; stroke: #4299e1; stroke-width: 1.5; rx: 6; }}
.page-node.root rect {{ fill: #fefcbf; stroke: #d69e2e; stroke-width: 2; }}
.page-node text {{ font-size: 11px; fill: #1a365d; font-family: monospace; }}
.page-edge {{ stroke: #a0aec0; stroke-width: 1.5; fill: none; marker-end: url(#arrow); }}
.page-thumb {{ border: 1px solid #e2e8f0; border-radius: 4px; }}
/* ── CTF Flags styles ── */
.ctf-section {{ background: linear-gradient(135deg,#1a202c 0%,#2d3748 100%); border-radius:12px; padding:24px; margin-bottom:24px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }}
.ctf-section h2 {{ color:#ffd700; font-size:1.3rem; font-weight:800; margin-bottom:16px; padding-bottom:10px; border-bottom:2px solid #4a5568; letter-spacing:.03em; }}
.ctf-flag-list {{ display:flex; flex-direction:column; gap:10px; }}
.ctf-flag-item {{ background:#2d3748; border:1px solid #4a5568; border-radius:8px; padding:14px 18px; display:flex; flex-direction:column; gap:4px; }}
.ctf-flag-value {{ font-family:'Cascadia Code','Consolas',monospace; font-size:1.05rem; font-weight:700; color:#ffd700; letter-spacing:.04em; word-break:break-all; }}
.ctf-flag-source {{ font-size:.78rem; color:#a0aec0; }}
.ctf-flag-copy {{ display:inline-block; margin-top:4px; font-size:.75rem; color:#68d391; cursor:pointer; text-decoration:underline; }}
.ctf-no-flags {{ color:#a0aec0; font-style:italic; }}
/* ── AI Analysis / Attack Chains (⑧ ⑨) ── */
.ai-analysis-section {{ background: linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);
    border-radius:12px; padding:24px; margin-bottom:24px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.25); color:#e2e8f0; }}
.ai-analysis-section h2 {{ color:#90cdf4; font-size:1.25rem; font-weight:800;
    margin-bottom:16px; padding-bottom:10px; border-bottom:1px solid #2d3748; }}
.ai-analysis-body {{ font-size:.9rem; line-height:1.8; white-space:pre-wrap;
    word-break:break-word; color:#e2e8f0; }}
.ai-fix-section {{ background:#f0fff4; border:1px solid #9ae6b4;
    border-radius:8px; padding:14px 18px; }}
.ai-fix-section h4 {{ color:#276749; font-size:.8rem; text-transform:uppercase;
    letter-spacing:.08em; margin-bottom:8px; }}
.ai-fix-body {{ font-size:.88rem; color:#1c4532; line-height:1.7; }}
</style>
</head>
<body>
<div class="header">
    <h1>WScan Security Report</h1>
    <div class="subtitle">Automated Web Security Assessment</div>
    <div class="target">🎯 {self._escape(target)}</div>
</div>

<div class="container">
    <!-- Summary Cards -->
    <div class="summary-grid">
        <div class="summary-card">
            <div class="count total-count">{total}</div>
            <div class="label">Total Findings</div>
        </div>
        <div class="summary-card">
            <div class="count critical-count">{counts.get('critical', 0)}</div>
            <div class="label">Critical</div>
        </div>
        <div class="summary-card">
            <div class="count high-count">{counts.get('high', 0)}</div>
            <div class="label">High</div>
        </div>
        <div class="summary-card">
            <div class="count medium-count">{counts.get('medium', 0)}</div>
            <div class="label">Medium</div>
        </div>
        <div class="summary-card">
            <div class="count low-count">{counts.get('low', 0)}</div>
            <div class="label">Low</div>
        </div>
    </div>

    <!-- CTF Flags -->
    {ctf_flags_html}

    <!-- Scan Metadata -->
    <div class="section">
        <h2>Scan Information</h2>
        <div class="scan-meta">
            <div class="meta-item">
                <span class="meta-label">Target</span>
                <span class="meta-value">{self._escape(target)}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Scan Date</span>
                <span class="meta-value">{scan_date}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Checks Performed</span>
                <span class="meta-value">{', '.join(c.upper() for c in checks)}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Pages Scanned</span>
                <span class="meta-value">{len(visited_urls)}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Tool</span>
                <span class="meta-value">WScan v1.0</span>
            </div>
        </div>
    </div>

    <!-- AI Analysis / Attack Chains (⑧ ⑨) -->
    {ai_analysis_html}

    <!-- Attack Plans -->
    {attack_plan_html}

    <!-- Findings -->
    <div class="section">
        <h2>Vulnerability Findings ({total})</h2>
        <div class="filter-bar" id="finding-filters">
            <label>Filter:</label>
            <select id="filter-severity" onchange="applyFilters()">
                <option value="">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
            </select>
            <select id="filter-check" onchange="applyFilters()">
                <option value="">All Check Types</option>
                {' '.join(f'<option value="{c}">{c.upper()}</option>' for c in sorted(set(f.check_type for f in findings)))}
            </select>
            <input type="text" id="filter-search" placeholder="Search URL or field…" oninput="applyFilters()">
            <button onclick="document.getElementById('filter-severity').value='';document.getElementById('filter-check').value='';document.getElementById('filter-search').value='';applyFilters();" style="padding:6px 12px;border:1px solid #e2e8f0;border-radius:6px;cursor:pointer;font-size:0.85rem;">Reset</button>
        </div>
        {no_findings_html}
        <div id="findings-container">
        {findings_html}
        </div>
    </div>

    <!-- Page Flow Diagram -->
    {page_flow_html}

    <!-- Visited URLs -->
    <div class="section">
        <h2>Scanned URLs ({len(visited_urls)})</h2>
        <ul class="url-list">
            {urls_html}
        </ul>
    </div>
</div>

<!-- Lightbox for screenshots -->
<div class="lightbox" id="lightbox" onclick="this.classList.remove('active')">
    <div class="lightbox-close">✕</div>
    <img id="lightbox-img" src="" alt="">
</div>

<div class="footer">
    Generated by WScan — Authorized Security Testing Only
</div>

<script>
// Screenshot lightbox
document.querySelectorAll('.evidence-screenshot').forEach(img => {{
    img.addEventListener('click', (e) => {{
        e.stopPropagation();
        document.getElementById('lightbox-img').src = img.src;
        document.getElementById('lightbox').classList.add('active');
    }});
}});
// Finding filter (U-2 equivalent in report)
function applyFilters() {{
    const sev = document.getElementById('filter-severity').value.toLowerCase();
    const chk = document.getElementById('filter-check').value.toLowerCase();
    const q   = document.getElementById('filter-search').value.toLowerCase();
    document.querySelectorAll('#findings-container .finding-card').forEach(card => {{
        const cardSev   = (card.dataset.severity || '').toLowerCase();
        const cardCheck = (card.dataset.check || '').toLowerCase();
        const cardUrl   = (card.dataset.url || '').toLowerCase();
        const cardField = (card.dataset.field || '').toLowerCase();
        const sevOk   = !sev || cardSev === sev;
        const chkOk   = !chk || cardCheck === chk;
        const searchOk = !q  || cardUrl.includes(q) || cardField.includes(q);
        card.style.display = (sevOk && chkOk && searchOk) ? '' : 'none';
    }});
}}
// Plan card collapse/expand
document.querySelectorAll('.plan-card-header').forEach(header => {{
    header.addEventListener('click', () => {{
        header.closest('.plan-card').classList.toggle('collapsed');
    }});
}});
// Payload list expand
document.querySelectorAll('.plan-payloads-toggle').forEach(btn => {{
    btn.addEventListener('click', (e) => {{
        e.stopPropagation();
        const list = btn.nextElementSibling;
        list.classList.toggle('open');
        btn.textContent = list.classList.contains('open') ? '▲ ペイロードを隠す' : '▼ LLMペイロードを表示';
    }});
}});
</script>
</body>
</html>"""

    def _build_ai_analysis_html(self) -> str:
        """
        ⑧ Render the AI Analysis / Attack Chain section.
        Reads ai_analysis.md from the output directory (written by engine._ai_analysis_report).
        """
        analysis_path = self.output_dir / "ai_analysis.md"
        if not analysis_path.exists():
            return ""
        try:
            text = analysis_path.read_text(encoding="utf-8")
        except Exception:
            return ""
        if not text.strip():
            return ""

        safe_text = self._escape(text)
        return f"""
    <div class="ai-analysis-section">
        <h2>🤖 AI Security Analysis &amp; Attack Chains (⑧⑨)</h2>
        <div class="ai-analysis-body">{safe_text}</div>
    </div>"""

    def _build_ctf_flags_html(self, ctf_flags: list) -> str:
        """Render the CTF Flags section (only shown when CTF mode is active)."""
        if not ctf_flags:
            return ""

        items = ""
        for flag, source in ctf_flags:
            esc_flag = self._escape(flag)
            esc_src = self._escape(source)
            items += f"""
            <div class="ctf-flag-item">
                <div class="ctf-flag-value">{esc_flag}</div>
                <div class="ctf-flag-source">Found on: {esc_src}</div>
                <span class="ctf-flag-copy" data-flag="{esc_flag}" onclick="navigator.clipboard.writeText(this.dataset.flag).then(()=>this.textContent='Copied!')">📋 Copy to clipboard</span>
            </div>"""

        return f"""
    <div class="ctf-section">
        <h2>🚩 CTF Flags Captured ({len(ctf_flags)})</h2>
        <div class="ctf-flag-list">
            {items}
        </div>
    </div>"""

    def _build_attack_plan_html(self, attack_plans: list) -> str:
        """Render the Attack Planning section of the report (Phase 2 results)."""
        if not attack_plans:
            return ""

        # ── Risk distribution across all fields ─────────────────────
        all_fields = [fp for plan in attack_plans for fp in plan.fields]
        high_count = sum(1 for fp in all_fields if fp.risk_score >= 8)
        mid_count  = sum(1 for fp in all_fields if 5 <= fp.risk_score < 8)
        low_count  = sum(1 for fp in all_fields if fp.risk_score < 5)
        llm_pages  = sum(1 for p in attack_plans if p.planned_by == "llm")

        stat_html = f"""
        <div class="plan-section-meta">
            <div class="plan-stat-card">
                <div class="ps-count">{len(attack_plans)}</div>
                <div class="ps-label">Pages planned</div>
            </div>
            <div class="plan-stat-card">
                <div class="ps-count">{len(all_fields)}</div>
                <div class="ps-label">Fields analyzed</div>
            </div>
            <div class="plan-stat-card ps-high">
                <div class="ps-count">{high_count}</div>
                <div class="ps-label">High risk (8-10)</div>
            </div>
            <div class="plan-stat-card ps-mid">
                <div class="ps-count">{mid_count}</div>
                <div class="ps-label">Medium risk (5-7)</div>
            </div>
            <div class="plan-stat-card ps-low">
                <div class="ps-count">{low_count}</div>
                <div class="ps-label">Low risk (1-4)</div>
            </div>
            <div class="plan-stat-card" style="background:#faf5ff;border-color:#d6bcfa;">
                <div class="ps-count" style="color:#6b46c1;">{llm_pages}</div>
                <div class="ps-label" style="color:#6b46c1;">LLM planned</div>
            </div>
        </div>"""

        # ── Per-page plan cards ──────────────────────────────────────
        cards_html = ""
        for plan in attack_plans:
            sorted_fields = sorted(plan.fields, key=lambda f: f.risk_score, reverse=True)
            fields_rows = ""
            for fp in sorted_fields:
                color = _risk_color(fp.risk_score)
                checks_html = "".join(
                    f'<span class="plan-check-badge priority-{min(i, 2)}">{self._escape(c)}</span>'
                    for i, c in enumerate(fp.priority_checks)
                ) or '<span style="color:#a0aec0">—</span>'

                # Cross-page indicator
                rationale_text = fp.rationale or ""
                cross_tag = ""
                cross_keywords = ["cross-page", "stored", "second-order", "another page",
                                   "格納型", "別ページ", "クロスページ"]
                if any(kw.lower() in rationale_text.lower() for kw in cross_keywords):
                    cross_tag = '<span class="cross-page-tag">⚠ Cross-page</span> '

                # LLM-generated payloads
                payload_html = ""
                if fp.custom_payloads:
                    payload_items = ""
                    for check_type, payloads in fp.custom_payloads.items():
                        if not payloads:
                            continue
                        codes = "".join(
                            f'<code>{self._escape(p)}</code>' for p in payloads[:6]
                        )
                        payload_items += f'<div class="plan-payload-type">{self._escape(check_type)}</div>{codes}'
                    if payload_items:
                        payload_html = f"""
                        <span class="plan-payloads-toggle">▼ LLMペイロードを表示 ({sum(len(v) for v in fp.custom_payloads.values())}件)</span>
                        <div class="plan-payload-list">{payload_items}</div>"""

                fields_rows += f"""
                <div class="plan-field-row">
                    <div class="plan-field-name">{self._escape(fp.name)}</div>
                    <div><div class="plan-risk-badge" style="background:{color}">{fp.risk_score}</div></div>
                    <div class="plan-checks">{checks_html}</div>
                    <div class="plan-rationale-col">
                        <div class="plan-rationale">{cross_tag}{self._escape(rationale_text)}</div>
                        {payload_html}
                    </div>
                </div>"""

            planned_by_label = "🤖 AI (LLM)" if plan.planned_by == "llm" else "📐 Heuristic"
            by_class = "plan-by llm" if plan.planned_by == "llm" else "plan-by"
            cards_html += f"""
            <div class="plan-card">
                <div class="plan-card-header">
                    <div class="plan-header-left">
                        <div class="plan-url">{self._escape(plan.url)}</div>
                        <div class="plan-purpose">{self._escape(plan.page_purpose)}</div>
                        <div class="{by_class}">{planned_by_label} · {len(plan.fields)} fields</div>
                    </div>
                    <div class="plan-toggle">▾</div>
                </div>
                <div class="plan-fields">
                    <div class="plan-cols-header">
                        <span>Field / Parameter</span><span>Risk</span>
                        <span>Priority Checks</span><span>Rationale &amp; LLM Payloads</span>
                    </div>
                    {fields_rows or '<div class="no-plans">No testable fields found.</div>'}
                </div>
            </div>"""

        return f"""
    <div class="section">
        <h2>🗺 Attack Plan — Phase 2 ({len(attack_plans)} page{'s' if len(attack_plans) != 1 else ''})</h2>
        <p style="color:#718096;font-size:.9rem;margin-bottom:16px;">
            巡回完了後に LLM / ヒューリスティックが生成した攻撃プランです。
            リスクスコアが高いフィールドを優先的に攻撃しました。
            <strong style="color:#553c9a">⚠ Cross-page</strong> は格納型 XSS や別ページへの影響が疑われるフィールドを示します。
        </p>
        {stat_html}
        {cards_html}
    </div>"""

    def _build_page_flow_html(self, page_graph: dict) -> str:
        """
        B: D3.js 力指向グラフによるビジュアルサイトマップ。
        CDN が利用不可の場合はシンプルな <ul> ツリーにフォールバックする。

        page_graph: {url: {"parent": parent_url|None, "screenshot_b64": str, "depth": int}}
        """
        if not page_graph:
            return ""

        import json as _json

        # D3 用データ構築
        nodes = []
        links = []
        url_to_idx = {}
        for i, (url, info) in enumerate(page_graph.items()):
            url_to_idx[url] = i
            nodes.append({
                "id": i,
                "url": url,
                "short": url[-40:] if len(url) > 40 else url,
                "depth": info.get("depth", 0),
            })
        for url, info in page_graph.items():
            parent = info.get("parent")
            if parent and parent in url_to_idx:
                links.append({"source": url_to_idx[parent], "target": url_to_idx[url]})

        nodes_json = _json.dumps(nodes)
        links_json = _json.dumps(links)

        # フォールバック: <ul> ツリー
        fallback_items = "".join(
            f'<li style="margin:2px 0;font-size:0.8rem;font-family:monospace">'
            f'{"&nbsp;" * 4 * info.get("depth",0)}{"└─ " if info.get("depth",0) > 0 else ""}'
            f'<a href="{self._escape(url)}" target="_blank">{self._escape(url)}</a></li>'
            for url, info in page_graph.items()
        )

        return f"""
    <div class="section" id="site-map-section">
        <h2>🗺 Visual Site Map ({len(page_graph)} pages)</h2>
        <div id="site-map-graph" style="height:450px;border:1px solid #e2e8f0;border-radius:8px;background:#1a202c;position:relative;overflow:hidden">
            <svg id="d3-svg" width="100%" height="100%"></svg>
            <div id="site-map-fallback" style="display:none;padding:16px;overflow-y:auto;max-height:420px">
                <ul style="list-style:none;padding:0;margin:0">{fallback_items}</ul>
            </div>
        </div>
        <p style="font-size:0.75rem;color:#718096;margin-top:6px">
            赤色ノード = 脆弱性が検出されたページ / 青色ノード = 正常 / ドラッグ可能
        </p>
        <script>
        (function() {{
            var nodes = {nodes_json};
            var links = {links_json};
            var svgEl = document.getElementById('d3-svg');
            if (!svgEl) return;

            function runD3() {{
                var w = svgEl.parentElement.clientWidth || 800;
                var h = 450;
                var d3 = window.d3;
                if (!d3) {{ showFallback(); return; }}
                try {{
                    var svg = d3.select('#d3-svg').attr('width', w).attr('height', h);
                    svg.selectAll('*').remove();
                    var g = svg.append('g');
                    svg.call(d3.zoom().scaleExtent([0.2,4]).on('zoom', function(ev) {{
                        g.attr('transform', ev.transform);
                    }}));
                    var sim = d3.forceSimulation(nodes)
                        .force('link', d3.forceLink(links).id(function(d){{return d.id;}}).distance(100))
                        .force('charge', d3.forceManyBody().strength(-250))
                        .force('center', d3.forceCenter(w/2, h/2))
                        .force('collide', d3.forceCollide(55));
                    var link = g.append('g').selectAll('line').data(links).enter().append('line')
                        .attr('stroke','#4a5568').attr('stroke-width',1.5).attr('marker-end','url(#arr)');
                    svg.append('defs').append('marker').attr('id','arr').attr('viewBox','0 -4 8 8')
                        .attr('refX',18).attr('markerWidth',6).attr('markerHeight',6).attr('orient','auto')
                        .append('path').attr('d','M0,-4L8,0L0,4').attr('fill','#4a5568');
                    var nodeG = g.append('g').selectAll('g').data(nodes).enter().append('g')
                        .attr('cursor','pointer')
                        .call(d3.drag()
                            .on('start', function(ev,d){{if(!ev.active)sim.alphaTarget(0.3).restart();d.fx=d.x;d.fy=d.y;}})
                            .on('drag', function(ev,d){{d.fx=ev.x;d.fy=ev.y;}})
                            .on('end', function(ev,d){{if(!ev.active)sim.alphaTarget(0);d.fx=null;d.fy=null;}}))
                        .on('click', function(ev,d){{window.open(d.url,'_blank');}});
                    nodeG.append('circle').attr('r',18)
                        .attr('fill', function(d){{return d.depth===0?'#63b3ed':'#4299e1';}})
                        .attr('stroke','#2b6cb0').attr('stroke-width',1.5);
                    nodeG.append('text').attr('dy','0.35em').attr('text-anchor','middle')
                        .attr('font-size','9px').attr('fill','white')
                        .text(function(d){{var s=d.short;return s.length>20?s.slice(-20):s;}});
                    nodeG.append('title').text(function(d){{return d.url;}});
                    sim.on('tick', function() {{
                        link.attr('x1',function(d){{return d.source.x;}}).attr('y1',function(d){{return d.source.y;}})
                            .attr('x2',function(d){{return d.target.x;}}).attr('y2',function(d){{return d.target.y;}});
                        nodeG.attr('transform', function(d){{return 'translate('+d.x+','+d.y+')';}});
                    }});
                }} catch(e) {{ showFallback(); }}
            }}
            function showFallback() {{
                document.getElementById('d3-svg').style.display='none';
                document.getElementById('site-map-fallback').style.display='block';
            }}
            var script = document.createElement('script');
            script.src = 'https://d3js.org/d3.v7.min.js';
            script.onload = function() {{ runD3(); }};
            script.onerror = function() {{ showFallback(); }};
            document.head.appendChild(script);
        }})();
        </script>
    </div>"""

    def _format_request(self, req: dict) -> str:
        if not req:
            return '<div class="network-box"><h4>Request</h4><div class="network-content">N/A</div></div>'
        method = req.get("method", "GET")
        url = req.get("url", "")
        headers = req.get("headers", {})
        body = req.get("post_data", "") or ""
        headers_text = "\n".join(f"{k}: {v}" for k, v in list(headers.items())[:10])
        content = f"{method} {url}\n\n{headers_text}"
        if body:
            content += f"\n\n{body[:500]}"
        return f'<div class="network-box"><h4>HTTP Request</h4><div class="network-content">{self._escape(content)}</div></div>'

    def _format_response(self, resp: dict, finding: Finding) -> str:
        if not resp:
            return '<div class="network-box"><h4>Response</h4><div class="network-content">N/A</div></div>'
        status = resp.get("status", "")
        headers = resp.get("headers", {})
        body = finding.response.get("body", "") or ""
        headers_text = "\n".join(f"{k}: {v}" for k, v in list(headers.items())[:10])
        content = f"HTTP {status}\n\n{headers_text}"
        if body:
            content += f"\n\n{body[:1000]}"
        return f'<div class="network-box"><h4>HTTP Response</h4><div class="network-content">{self._escape(content)}</div></div>'

    @staticmethod
    def _escape(text: str) -> str:
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )

    # =========================================================================
    # F: Executive Report
    # =========================================================================

    def _build_executive_html(
        self, target, findings, visited_urls, checks,
        attack_plans, ctf_flags, page_graph, diff_result=None,
    ) -> str:
        """経営層向け: サマリーカード・リスク分布・コンプライアンス適合率・推奨事項。"""
        scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        counts = {sev: sum(1 for f in findings if f.severity == sev)
                  for sev in ["critical", "high", "medium", "low", "info"]}
        total = len(findings)

        # リスクスコア (CVSS重み付き平均)
        cvss_scores = [getattr(f, "cvss_score", 0.0) for f in findings]
        avg_cvss = (sum(cvss_scores) / len(cvss_scores)) if cvss_scores else 0.0

        # コンプライアンス違反タイプ集計
        top10_violations: dict[str, int] = {}
        pci_violations: dict[str, int] = {}
        for f in findings:
            refs = getattr(f, "compliance_refs", None) or {}
            if callable(getattr(refs, "get", None)):
                for ref in refs.get("owasp_top10", []):
                    top10_violations[ref] = top10_violations.get(ref, 0) + 1
                for ref in refs.get("pci_dss", []):
                    pci_violations[ref] = pci_violations.get(ref, 0) + 1

        top10_html = "".join(
            f'<li>{self._escape(k)}: <b>{v}件</b></li>'
            for k, v in sorted(top10_violations.items(), key=lambda x: -x[1])[:5]
        ) or "<li>違反なし</li>"

        pci_html = "".join(
            f'<li>{self._escape(k)}: <b>{v}件</b></li>'
            for k, v in sorted(pci_violations.items(), key=lambda x: -x[1])[:5]
        ) or "<li>違反なし</li>"

        # 差分サマリー
        diff_html = ""
        if diff_result:
            diff_html = f"""
            <div class="exec-card" style="border-left:4px solid #4299e1">
                <div class="exec-label">差分スキャン結果</div>
                <div style="font-size:0.9rem;margin-top:8px">
                    🆕 新規: <b>{len(diff_result.new_findings)}</b> 件 /
                    ✅ 修正済: <b>{len(diff_result.fixed_findings)}</b> 件 /
                    🔄 継続: <b>{len(diff_result.persistent_findings)}</b> 件
                </div>
            </div>"""

        # 推奨事項 (重要度別)
        recs = []
        if counts.get("critical", 0) > 0:
            recs.append("【緊急】クリティカルな脆弱性が検出されました。即時修正が必要です。")
        if counts.get("high", 0) > 0:
            recs.append("【高】高リスクの脆弱性が検出されました。速やかな対応を推奨します。")
        if "security_headers" in checks:
            recs.append("セキュリティヘッダ (CSP, HSTS, X-Frame-Options) の設定を確認してください。")
        recs.append("定期的なペネトレーションテストの実施を推奨します。")
        rec_html = "".join(f"<li>{self._escape(r)}</li>" for r in recs)

        return f"""<!DOCTYPE html>
<html lang="ja"><head><meta charset="UTF-8">
<title>Executive Report — {self._escape(target)}</title>
<style>
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f7f8fa;color:#1a202c;margin:0}}
.hdr{{background:linear-gradient(135deg,#1a202c,#2d3748);color:#fff;padding:40px}}
.hdr h1{{font-size:1.8rem;font-weight:700}} .hdr .sub{{color:#a0aec0;font-size:.9rem;margin-top:6px}}
.container{{max-width:1000px;margin:0 auto;padding:32px 24px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:24px}}
.exec-card{{background:#fff;border-radius:12px;padding:20px;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
.exec-count{{font-size:2.5rem;font-weight:800}} .exec-label{{font-size:.8rem;color:#718096;text-transform:uppercase;letter-spacing:.05em}}
.critical{{color:#e53e3e}} .high{{color:#dd6b20}} .medium{{color:#d69e2e}} .low{{color:#38a169}}
.section{{background:#fff;border-radius:12px;padding:24px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
.section h2{{font-size:1.1rem;font-weight:700;margin-bottom:16px;border-bottom:2px solid #e2e8f0;padding-bottom:8px}}
ul li{{margin:4px 0;font-size:.9rem}} .footer{{text-align:center;color:#a0aec0;font-size:.75rem;padding:24px}}
</style></head><body>
<div class="hdr">
  <h1>Executive Security Report</h1>
  <div class="sub">{self._escape(target)} &nbsp;|&nbsp; {scan_date} &nbsp;|&nbsp; 検査項目: {len(checks)} 種</div>
</div>
<div class="container">
  <div class="grid">
    <div class="exec-card" style="border-left:4px solid #e53e3e">
      <div class="exec-count critical">{counts.get("critical",0)}</div>
      <div class="exec-label">Critical</div>
    </div>
    <div class="exec-card" style="border-left:4px solid #dd6b20">
      <div class="exec-count high">{counts.get("high",0)}</div>
      <div class="exec-label">High</div>
    </div>
    <div class="exec-card" style="border-left:4px solid #d69e2e">
      <div class="exec-count medium">{counts.get("medium",0)}</div>
      <div class="exec-label">Medium</div>
    </div>
    <div class="exec-card" style="border-left:4px solid #38a169">
      <div class="exec-count low">{counts.get("low",0)}</div>
      <div class="exec-label">Low</div>
    </div>
    <div class="exec-card">
      <div class="exec-count" style="color:#4299e1">{total}</div>
      <div class="exec-label">Total Findings</div>
    </div>
    <div class="exec-card">
      <div class="exec-count" style="color:#805ad5">{avg_cvss:.1f}</div>
      <div class="exec-label">Avg CVSS Score</div>
    </div>
    {diff_html}
  </div>
  <div class="section">
    <h2>OWASP Top 10 違反 (上位5件)</h2>
    <ul>{top10_html}</ul>
  </div>
  <div class="section">
    <h2>PCI DSS 違反 (上位5件)</h2>
    <ul>{pci_html}</ul>
  </div>
  <div class="section">
    <h2>推奨事項</h2>
    <ul>{rec_html}</ul>
  </div>
  <div class="section">
    <h2>スキャン範囲</h2>
    <p style="font-size:.9rem">{len(visited_urls)} ページを検査 / 検査項目: {", ".join(checks)}</p>
  </div>
</div>
<div class="footer">WScan Security Report &mdash; Executive Summary</div>
</body></html>"""

    # =========================================================================
    # F: Developer Report
    # =========================================================================

    def _build_developer_html(
        self, target, findings, visited_urls, checks,
        attack_plans, ctf_flags, page_graph, diff_result=None,
    ) -> str:
        """開発者向け: チェックリスト形式・修正コード例・重要度別ソート。"""
        scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        items_html = ""
        for i, f in enumerate(findings):
            color = SEVERITY_COLORS.get(f.severity, "#718096")
            ai_fix = getattr(f, "ai_fix", "") or ""
            ai_fix_html = ""
            if ai_fix:
                safe_fix = self._escape(ai_fix).replace("\n", "<br>")
                ai_fix_html = f'<div class="fix-box"><b>修正ガイダンス:</b><br>{safe_fix}</div>'

            compliance_refs = getattr(f, "compliance_refs", None) or {}
            refs_parts = []
            if compliance_refs.get("owasp_top10"):
                refs_parts.append(", ".join(compliance_refs["owasp_top10"]))
            if compliance_refs.get("pci_dss"):
                refs_parts.append(", ".join(compliance_refs["pci_dss"][:2]))
            refs_html = f'<div class="refs">{self._escape(" / ".join(refs_parts))}</div>' if refs_parts else ""

            conf = getattr(f, "confidence", "tentative")
            diff_status = getattr(f, "_diff_status", "") or f.__dict__.get("_diff_status", "")
            status_badge = ""
            if diff_status == "new":
                status_badge = '<span class="new-badge">NEW</span>'
            elif diff_status == "fixed":
                status_badge = '<span class="fixed-badge">FIXED</span>'

            items_html += f"""
            <div class="finding-item" style="border-left:4px solid {color}">
                <div class="fi-header">
                    <input type="checkbox" class="fi-check" id="fix-{i}">
                    <label for="fix-{i}">
                        <span class="sev-tag" style="background:{color}">{f.severity.upper()}</span>
                        <b>{self._escape(f.check_type.upper())}</b>
                        {status_badge}
                        — <code>{self._escape(f.field_name)}</code>
                    </label>
                    <span class="conf-tag">信頼度: {conf}</span>
                </div>
                <div class="fi-body">
                    <div class="fi-url">{self._escape(f.url)}</div>
                    <div class="fi-evidence">{self._escape(f.evidence)}</div>
                    <code class="fi-payload">{self._escape(f.payload)}</code>
                    {refs_html}
                    {ai_fix_html}
                </div>
            </div>"""

        diff_summary = ""
        if diff_result:
            diff_summary = f"""
            <div class="diff-bar">
                🆕 新規 {len(diff_result.new_findings)} / ✅ 修正済 {len(diff_result.fixed_findings)} / 🔄 継続 {len(diff_result.persistent_findings)}
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="ja"><head><meta charset="UTF-8">
<title>Developer Report — {self._escape(target)}</title>
<style>
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f7f8fa;color:#1a202c;margin:0}}
.hdr{{background:#1a202c;color:#fff;padding:32px}} .hdr h1{{font-size:1.6rem;font-weight:700}}
.hdr .sub{{color:#a0aec0;font-size:.85rem;margin-top:4px}}
.container{{max-width:960px;margin:0 auto;padding:24px}}
.finding-item{{background:#fff;border-radius:8px;margin-bottom:12px;box-shadow:0 1px 2px rgba(0,0,0,.08);overflow:hidden}}
.fi-header{{padding:12px 16px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;background:#f8fafc}}
.fi-header label{{display:flex;align-items:center;gap:8px;cursor:pointer;flex:1}}
.fi-body{{padding:12px 16px;display:none}}
.fi-check:checked ~ label + * + .fi-body, input:checked ~ .fi-body {{ display:block }}
.finding-item:has(.fi-check:checked) .fi-body{{display:block}}
.sev-tag{{color:#fff;padding:2px 8px;border-radius:12px;font-size:.72rem;font-weight:700}}
.conf-tag{{font-size:.75rem;color:#718096;margin-left:auto}}
.fi-url{{font-size:.82rem;color:#718096;font-family:monospace;word-break:break-all;margin-bottom:6px}}
.fi-evidence{{background:#fff8f0;border:1px solid #fbd38d;border-radius:4px;padding:8px;font-size:.85rem;margin-bottom:6px}}
.fi-payload{{display:block;background:#1a202c;color:#68d391;padding:8px;border-radius:4px;font-size:.8rem;word-break:break-all;margin-bottom:6px;white-space:pre-wrap}}
.fix-box{{background:#f0fff4;border:1px solid #9ae6b4;border-radius:4px;padding:10px;font-size:.85rem;margin-top:6px}}
.refs{{font-size:.75rem;color:#4a5568;margin-top:4px}}
.new-badge{{background:#276749;color:#f0fff4;padding:2px 6px;border-radius:8px;font-size:.7rem;font-weight:700}}
.fixed-badge{{background:#2b6cb0;color:#ebf8ff;padding:2px 6px;border-radius:8px;font-size:.7rem;font-weight:700}}
.diff-bar{{background:#ebf8ff;border:1px solid #bee3f8;border-radius:8px;padding:10px 16px;margin-bottom:16px;font-size:.9rem}}
.footer{{text-align:center;color:#a0aec0;font-size:.75rem;padding:20px}}
</style></head><body>
<div class="hdr">
  <h1>Developer Security Checklist</h1>
  <div class="sub">{self._escape(target)} &nbsp;|&nbsp; {scan_date} &nbsp;|&nbsp; {len(findings)} 件の検出</div>
</div>
<div class="container">
  {diff_summary}
  <p style="font-size:.85rem;color:#4a5568;margin-bottom:12px">各項目をクリックして詳細を展開してください。チェックボックスで修正完了を記録できます。</p>
  {items_html if items_html else '<p style="color:#38a169;font-weight:600">✓ 検出された脆弱性はありません。</p>'}
</div>
<div class="footer">WScan Security Report &mdash; Developer Checklist</div>
<script>
document.querySelectorAll('.finding-item').forEach(function(item) {{
    item.querySelector('.fi-header').addEventListener('click', function(e) {{
        if (e.target.classList.contains('fi-check')) return;
        var body = item.querySelector('.fi-body');
        body.style.display = body.style.display === 'block' ? 'none' : 'block';
    }});
}});
</script>
</body></html>"""
