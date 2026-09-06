"""
Modern Interactive Standalone HTML Report Generator for AegisScan.
Produces zero-dependency, self-contained executive security dashboards.
"""

import html
import json
from pathlib import Path
from aegisscan.core.models import ScanResult, Severity


def generate_html_report(result: ScanResult, output_path: str) -> None:
    """Generates an executive HTML report file."""
    summary = result.summary
    findings = result.findings
    headers = result.headers
    exposures = result.exposures
    tls = result.tls
    dns = result.dns_mail

    # Grade color mapping
    grade_colors = {
        "A+": "#10b981",
        "A": "#10b981",
        "B": "#06b6d4",
        "C": "#f59e0b",
        "D": "#ef4444",
        "F": "#dc2626",
    }
    accent_color = grade_colors.get(summary.grade, "#3b82f6")

    # Build findings HTML
    findings_html = []
    for f in findings:
        sev_class = f"badge-{f.severity.value.lower()}"
        evidence_block = ""
        if f.evidence:
            evidence_block = f"""
            <div class="evidence-box">
                <span class="evidence-title">Evidence / Response Snippet:</span>
                <pre><code>{html.escape(f.evidence)}</code></pre>
            </div>
            """

        ref_links = ""
        if f.references:
            links = "".join([f'<a href="{html.escape(r)}" target="_blank" rel="noopener">{html.escape(r)}</a>' for r in f.references])
            ref_links = f'<div class="references"><strong>References:</strong> {links}</div>'

        item_html = f"""
        <div class="finding-card card" data-severity="{f.severity.value.lower()}">
            <div class="finding-header">
                <div>
                    <span class="badge {sev_class}">{f.severity.value}</span>
                    <span class="finding-category">{html.escape(f.category.value)}</span>
                    <h3 class="finding-title">{html.escape(f.title)}</h3>
                </div>
                <span class="finding-id">{html.escape(f.id)}</span>
            </div>
            <div class="finding-body">
                <div class="section-row">
                    <span class="section-label">Description:</span>
                    <p>{html.escape(f.description)}</p>
                </div>
                <div class="section-row impact">
                    <span class="section-label">Impact:</span>
                    <p>{html.escape(f.impact)}</p>
                </div>
                <div class="section-row remediation">
                    <span class="section-label">Remediation:</span>
                    <p>{html.escape(f.remediation)}</p>
                </div>
                {evidence_block}
                {ref_links}
            </div>
        </div>
        """
        findings_html.append(item_html)

    # Build headers table rows
    header_rows = []
    for h in headers:
        status_badge = f'<span class="status-badge status-{h.status.lower()}">{h.status}</span>'
        val_display = html.escape(h.value) if h.value else '<span class="text-muted">Not Set</span>'
        header_rows.append(f"""
        <tr>
            <td class="font-mono">{html.escape(h.header)}</td>
            <td>{status_badge}</td>
            <td class="font-mono text-xs">{val_display}</td>
            <td>{html.escape(h.recommendation)}</td>
        </tr>
        """)

    # Build exposures table rows
    exposed_items = [e for e in exposures if e.exposed]
    exposure_rows = []
    for exp in (exposed_items or exposures[:8]):
        badge_cls = f"badge-{exp.risk_level.value.lower()}"
        status_text = '<span class="badge badge-critical">EXPOSED</span>' if exp.exposed else '<span class="text-muted">Protected</span>'
        snippet = html.escape(exp.evidence_snippet[:80]) if exp.evidence_snippet else "-"
        exposure_rows.append(f"""
        <tr>
            <td class="font-mono">{html.escape(exp.path)}</td>
            <td>{status_text}</td>
            <td><span class="badge {badge_cls}">{exp.risk_level.value}</span></td>
            <td>{html.escape(exp.category)}</td>
            <td class="font-mono text-xs">{snippet}</td>
        </tr>
        """)

    # TLS & DNS Information
    tls_info = f"""
    <div class="info-grid-item">
        <div class="info-label">Issuer</div>
        <div class="info-value">{html.escape(tls.issuer or 'N/A')}</div>
    </div>
    <div class="info-grid-item">
        <div class="info-label">Protocol</div>
        <div class="info-value">{html.escape(tls.protocol_version or 'N/A')}</div>
    </div>
    <div class="info-grid-item">
        <div class="info-label">Certificate Expiration</div>
        <div class="info-value">{'Expired' if tls and tls.is_expired else (f'{tls.days_left} days remaining' if tls and tls.days_left is not None else 'N/A')}</div>
    </div>
    """ if tls and tls.supported else "<p class='text-muted'>TLS connection failed or service is plain HTTP.</p>"

    dns_info = f"""
    <div class="info-grid-item">
        <div class="info-label">SPF Policy</div>
        <div class="info-value">{html.escape(dns.spf_status)}</div>
    </div>
    <div class="info-grid-item">
        <div class="info-label">DMARC Policy</div>
        <div class="info-value">{html.escape(dns.dmarc_status)}</div>
    </div>
    <div class="info-grid-item">
        <div class="info-label">DNSSEC</div>
        <div class="info-value">{'Enabled' if dns.dnssec_enabled else 'Disabled / Not Found'}</div>
    </div>
    """ if dns else "<p class='text-muted'>DNS audit skipped.</p>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AegisScan Security Report - {html.escape(summary.target_host)}</title>
    <style>
        :root {{
            --bg: #090d16;
            --card-bg: #111827;
            --card-border: #1f2937;
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --accent: {accent_color};
            --crit: #ef4444;
            --high: #f97316;
            --med: #f59e0b;
            --low: #3b82f6;
            --info: #06b6d4;
            --pass: #10b981;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.5;
            padding: 24px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--card-border);
            padding-bottom: 20px;
            margin-bottom: 24px;
        }}
        .logo {{ display: flex; align-items: center; gap: 12px; }}
        .logo-icon {{
            font-size: 28px;
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid var(--pass);
            border-radius: 8px;
            padding: 4px 8px;
        }}
        .logo h1 {{ font-size: 24px; font-weight: 800; letter-spacing: -0.5px; }}
        .logo span {{ font-size: 13px; color: var(--text-secondary); }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: #dc2626; color: #fff; }}
        .badge-high {{ background: #ea580c; color: #fff; }}
        .badge-medium {{ background: #d97706; color: #fff; }}
        .badge-low {{ background: #2563eb; color: #fff; }}
        .badge-info {{ background: #0891b2; color: #fff; }}

        .hero-banner {{
            display: grid;
            grid-template-columns: 200px 1fr;
            gap: 24px;
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            align-items: center;
        }}
        .grade-box {{
            text-align: center;
            border-right: 1px solid var(--card-border);
            padding-right: 20px;
        }}
        .grade-circle {{
            width: 100px;
            height: 100px;
            border-radius: 50%;
            border: 6px solid var(--accent);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
            font-weight: 900;
            color: var(--accent);
            margin: 0 auto 10px;
            box-shadow: 0 0 20px rgba(16, 185, 129, 0.2);
        }}
        .meta-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 16px;
        }}
        .stat-card {{
            background: #0e1524;
            border: 1px solid var(--card-border);
            border-radius: 8px;
            padding: 12px 16px;
        }}
        .stat-val {{ font-size: 22px; font-weight: 800; }}
        .stat-label {{ font-size: 12px; color: var(--text-secondary); text-transform: uppercase; }}

        /* Tabs & Filter */
        .controls {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 12px;
        }}
        .filter-buttons {{ display: flex; gap: 8px; }}
        .btn {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            color: var(--text-primary);
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 13px;
            cursor: pointer;
            transition: 0.2s;
        }}
        .btn.active, .btn:hover {{ background: #1f2937; border-color: #374151; }}
        .search-box {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            color: var(--text-primary);
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 13px;
            width: 250px;
        }}

        /* Cards & Findings */
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 16px;
        }}
        .finding-card {{ border-left: 5px solid var(--card-border); }}
        .finding-card[data-severity="critical"] {{ border-left-color: var(--crit); }}
        .finding-card[data-severity="high"] {{ border-left-color: var(--high); }}
        .finding-card[data-severity="medium"] {{ border-left-color: var(--med); }}
        .finding-card[data-severity="low"] {{ border-left-color: var(--low); }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 14px;
        }}
        .finding-title {{ font-size: 17px; font-weight: 700; margin-top: 6px; }}
        .finding-category {{ font-size: 12px; color: var(--text-secondary); margin-left: 8px; }}
        .finding-id {{ font-family: monospace; font-size: 12px; color: var(--text-secondary); }}
        .section-row {{ margin-bottom: 10px; }}
        .section-label {{
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-secondary);
            display: block;
            margin-bottom: 2px;
        }}
        .impact p {{ color: #fca5a5; }}
        .remediation p {{ color: #86efac; }}
        .evidence-box {{
            background: #090d16;
            border: 1px solid #1e293b;
            border-radius: 6px;
            padding: 12px;
            margin-top: 10px;
        }}
        .evidence-title {{ font-size: 11px; color: #94a3b8; font-weight: bold; text-transform: uppercase; }}
        pre {{ overflow-x: auto; margin-top: 4px; }}
        code {{ font-family: monospace; font-size: 12px; color: #38bdf8; }}
        .references {{ font-size: 12px; margin-top: 10px; color: var(--text-secondary); }}
        .references a {{ color: #38bdf8; text-decoration: none; margin-left: 6px; word-break: break-all; }}

        /* Tables */
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 13px;
        }}
        th, td {{
            padding: 12px 14px;
            border-bottom: 1px solid var(--card-border);
        }}
        th {{
            background: #0f172a;
            color: var(--text-secondary);
            font-size: 11px;
            text-transform: uppercase;
            font-weight: 700;
        }}
        .status-badge {{
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
        }}
        .status-pass {{ background: rgba(16, 185, 129, 0.2); color: #10b981; }}
        .status-fail {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; }}
        .status-warn {{ background: rgba(245, 158, 11, 0.2); color: #f59e0b; }}
        .font-mono {{ font-family: monospace; }}
        .text-xs {{ font-size: 11px; }}
        .text-muted {{ color: var(--text-secondary); }}

        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
        }}
        .info-grid-item {{
            background: #0c1220;
            border: 1px solid var(--card-border);
            border-radius: 6px;
            padding: 12px;
        }}
        .info-label {{ font-size: 11px; color: var(--text-secondary); text-transform: uppercase; }}
        .info-value {{ font-size: 14px; font-weight: 600; margin-top: 4px; word-break: break-all; }}

        footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--card-border);
            font-size: 13px;
            color: var(--text-secondary);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                <div class="logo-icon">🛡️</div>
                <div>
                    <h1>AegisScan</h1>
                    <span>Modern Web Security Posture & Exposure Audit Tool</span>
                </div>
            </div>
            <div>
                <span class="badge" style="background: #1f2937; color: #94a3b8;">v1.0.0</span>
                <span class="badge" style="background: rgba(16, 185, 129, 0.15); color: #10b981; margin-left: 6px;">Automated Security Audit</span>
            </div>
        </header>

        <!-- Hero Banner with Score & Metrics -->
        <div class="hero-banner">
            <div class="grade-box">
                <div class="grade-circle">{summary.grade}</div>
                <div style="font-weight: 800; font-size: 18px;">Score: {summary.score} / 100</div>
                <div style="font-size: 12px; color: var(--text-secondary);">Security Posture Grade</div>
            </div>
            <div class="meta-stats">
                <div class="stat-card">
                    <div class="stat-val" style="color: var(--crit);">{summary.critical_count}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card">
                    <div class="stat-val" style="color: var(--high);">{summary.high_count}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card">
                    <div class="stat-val" style="color: var(--med);">{summary.medium_count}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card">
                    <div class="stat-val" style="color: var(--low);">{summary.low_count}</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat-card">
                    <div class="stat-val">{summary.scan_duration_sec}s</div>
                    <div class="stat-label">Duration</div>
                </div>
            </div>
        </div>

        <!-- Target Info -->
        <div class="card">
            <div class="info-grid">
                <div class="info-grid-item">
                    <div class="info-label">Target URL</div>
                    <div class="info-value font-mono">{html.escape(summary.target_url)}</div>
                </div>
                <div class="info-grid-item">
                    <div class="info-label">Target Host</div>
                    <div class="info-value font-mono">{html.escape(summary.target_host)}</div>
                </div>
                <div class="info-grid-item">
                    <div class="info-label">Scan Date</div>
                    <div class="info-value">{summary.scan_date}</div>
                </div>
                <div class="info-grid-item">
                    <div class="info-label">Auditor Engine</div>
                    <div class="info-value">AegisScan Core 1.0 (RobsHs)</div>
                </div>
            </div>
        </div>

        <!-- Controls: Filters & Search -->
        <div class="controls">
            <div class="filter-buttons">
                <button class="btn active" onclick="filterFindings('all', this)">All ({len(findings)})</button>
                <button class="btn" onclick="filterFindings('critical', this)">Critical ({summary.critical_count})</button>
                <button class="btn" onclick="filterFindings('high', this)">High ({summary.high_count})</button>
                <button class="btn" onclick="filterFindings('medium', this)">Medium ({summary.medium_count})</button>
                <button class="btn" onclick="filterFindings('low', this)">Low ({summary.low_count})</button>
            </div>
            <input type="text" id="searchBar" class="search-box" placeholder="Search findings..." onkeyup="searchFindings()">
        </div>

        <!-- Identified Findings -->
        <section id="findingsSection">
            <h2 style="font-size: 20px; font-weight: 800; margin-bottom: 16px;">Detailed Vulnerability & Posture Findings</h2>
            {''.join(findings_html) if findings_html else '<div class="card"><p style="color: #10b981; font-weight: bold;">✔ No security issues detected for this host!</p></div>'}
        </section>

        <!-- HTTP Security Headers Checklist -->
        <section style="margin-top: 36px;">
            <h2 style="font-size: 20px; font-weight: 800; margin-bottom: 16px;">HTTP Security Headers Analysis</h2>
            <div class="card" style="padding: 0; overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Security Header</th>
                            <th>Status</th>
                            <th>Value</th>
                            <th>Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(header_rows)}
                    </tbody>
                </table>
            </div>
        </section>

        <!-- Sensitive Path Exposure -->
        <section style="margin-top: 36px;">
            <h2 style="font-size: 20px; font-weight: 800; margin-bottom: 16px;">Sensitive Path & Information Exposure Audit</h2>
            <div class="card" style="padding: 0; overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Path Tested</th>
                            <th>Exposure Status</th>
                            <th>Risk</th>
                            <th>Category</th>
                            <th>Evidence Preview</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(exposure_rows) if exposure_rows else '<tr><td colspan="5" style="text-align: center; color: #10b981;">No sensitive paths exposed</td></tr>'}
                    </tbody>
                </table>
            </div>
        </section>

        <!-- SSL/TLS & DNS Posture -->
        <section style="margin-top: 36px;">
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                <div class="card">
                    <h3 style="font-size: 16px; font-weight: 700; margin-bottom: 12px;">🔒 SSL / TLS Certificate Status</h3>
                    <div class="info-grid">
                        {tls_info}
                    </div>
                </div>
                <div class="card">
                    <h3 style="font-size: 16px; font-weight: 700; margin-bottom: 12px;">📧 DNS & Anti-Spoofing Posture</h3>
                    <div class="info-grid">
                        {dns_info}
                    </div>
                </div>
            </div>
        </section>

        <footer>
            <p>Report generated by <strong>AegisScan</strong> &bull; Open Source Web Security Posture & Exposure Audit Tool</p>
            <p style="margin-top: 4px;">Author: <strong>RobsHs</strong> &bull; Released under the MIT License</p>
        </footer>
    </div>

    <script>
        function filterFindings(severity, btn) {{
            document.querySelectorAll('.filter-buttons .btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            const cards = document.querySelectorAll('.finding-card');
            cards.forEach(card => {{
                if (severity === 'all' || card.getAttribute('data-severity') === severity) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}

        function searchFindings() {{
            const query = document.getElementById('searchBar').value.toLowerCase();
            const cards = document.querySelectorAll('.finding-card');
            cards.forEach(card => {{
                const text = card.innerText.toLowerCase();
                card.style.display = text.includes(query) ? 'block' : 'none';
            }});
        }}
    </script>
</body>
</html>
"""
    Path(output_path).write_text(html_content, encoding="utf-8")

