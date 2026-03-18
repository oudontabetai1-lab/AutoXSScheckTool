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
    ):
        """Generate HTML report and save to output directory."""
        sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
        html = self._build_html(target, sorted_findings, visited_urls, checks,
                                attack_plans or [], ctf_flags or [])
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
    ) -> str:
        attack_plans = attack_plans or []
        ctf_flags = ctf_flags or []
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

            findings_html += f"""
            <div class="finding-card" id="finding-{i}">
                <div class="finding-header" style="border-left: 4px solid {color}">
                    <div class="finding-title">
                        <span class="badge" style="background:{color}">{f.severity.upper()}</span>
                        <span class="check-type">{f.check_type.upper()}</span>
                        <span class="field-name">Field: {self._escape(f.field_name)}</span>
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
/* ── CTF Flags styles ── */
.ctf-section {{ background: linear-gradient(135deg,#1a202c 0%,#2d3748 100%); border-radius:12px; padding:24px; margin-bottom:24px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }}
.ctf-section h2 {{ color:#ffd700; font-size:1.3rem; font-weight:800; margin-bottom:16px; padding-bottom:10px; border-bottom:2px solid #4a5568; letter-spacing:.03em; }}
.ctf-flag-list {{ display:flex; flex-direction:column; gap:10px; }}
.ctf-flag-item {{ background:#2d3748; border:1px solid #4a5568; border-radius:8px; padding:14px 18px; display:flex; flex-direction:column; gap:4px; }}
.ctf-flag-value {{ font-family:'Cascadia Code','Consolas',monospace; font-size:1.05rem; font-weight:700; color:#ffd700; letter-spacing:.04em; word-break:break-all; }}
.ctf-flag-source {{ font-size:.78rem; color:#a0aec0; }}
.ctf-flag-copy {{ display:inline-block; margin-top:4px; font-size:.75rem; color:#68d391; cursor:pointer; text-decoration:underline; }}
.ctf-no-flags {{ color:#a0aec0; font-style:italic; }}
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

    <!-- Attack Plans -->
    {attack_plan_html}

    <!-- Findings -->
    <div class="section">
        <h2>Vulnerability Findings ({total})</h2>
        {no_findings_html}
        {findings_html}
    </div>

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
                <span class="ctf-flag-copy" onclick="navigator.clipboard.writeText('{esc_flag}').then(()=>this.textContent='Copied!')">📋 Copy to clipboard</span>
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
        )
