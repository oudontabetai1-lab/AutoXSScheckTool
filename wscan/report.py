"""
WScan Report Generator
Generates a self-contained HTML security assessment report.
"""
import datetime
import json
from pathlib import Path
from typing import Optional

from .scanners.base import Finding

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {
    "critical": "#e53e3e",
    "high": "#dd6b20",
    "medium": "#d69e2e",
    "low": "#38a169",
    "info": "#4299e1",
}


class ReportGenerator:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    def generate(
        self,
        target: str,
        findings: list[Finding],
        visited_urls: list[str],
        checks: list[str],
    ):
        """Generate HTML report and save to output directory."""
        sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
        html = self._build_html(target, sorted_findings, visited_urls, checks)
        report_path = self.output_dir / "report.html"
        report_path.write_text(html, encoding="utf-8")
        return report_path

    def _build_html(
        self,
        target: str,
        findings: list[Finding],
        visited_urls: list[str],
        checks: list[str],
    ) -> str:
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

            findings_html += f"""
            <div class="finding-card" id="finding-{i}">
                <div class="finding-header" style="border-left: 4px solid {color}">
                    <div class="finding-title">
                        <span class="badge" style="background:{color}">{f.severity.upper()}</span>
                        <span class="check-type">{f.check_type.upper()}</span>
                        <span class="field-name">Field: {self._escape(f.field_name)}</span>
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
document.querySelectorAll('.evidence-screenshot').forEach(img => {{
    img.addEventListener('click', (e) => {{
        e.stopPropagation();
        document.getElementById('lightbox-img').src = img.src;
        document.getElementById('lightbox').classList.add('active');
    }});
}});
</script>
</body>
</html>"""

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
