# Generates HTML and PDF audit reports from the results returned by the audit engine.
# The HTML template is embedded as a string so the reports are fully self-contained files.

import os
from datetime import datetime
from jinja2 import Template


# Full standalone HTML template with all styles inlined.
# Keeping it here means no separate template file is needed for report generation.
REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ISO 27001 Audit Report - {{ summary.hostname }}</title>
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
        font-family: 'Inter', -apple-system, sans-serif;
        background: #ffffff;
        color: #1e293b;
        line-height: 1.6;
        font-size: 11pt;
    }

    .report-container {
        max-width: 900px;
        margin: 0 auto;
        padding: 40px 50px;
    }

    /* Header */
    .report-header {
        border-bottom: 3px solid #1e40af;
        padding-bottom: 24px;
        margin-bottom: 32px;
    }
    .report-header h1 {
        font-size: 24pt;
        font-weight: 700;
        color: #1e293b;
        margin-bottom: 4px;
    }
    .report-header .subtitle {
        font-size: 13pt;
        color: #64748b;
        font-weight: 400;
    }
    .report-meta {
        display: flex;
        flex-wrap: wrap;
        gap: 24px;
        margin-top: 16px;
        font-size: 9.5pt;
        color: #475569;
    }
    .report-meta span { display: flex; align-items: center; gap: 6px; }
    .report-meta strong { color: #1e293b; }

    /* Summary Cards */
    .summary-section {
        display: flex;
        gap: 16px;
        margin-bottom: 32px;
    }
    .summary-card {
        flex: 1;
        padding: 20px;
        border-radius: 8px;
        text-align: center;
        border: 1px solid #e2e8f0;
    }
    .summary-card.total { background: #f1f5f9; }
    .summary-card.passed { background: #f0fdf4; border-color: #bbf7d0; }
    .summary-card.failed { background: #fef2f2; border-color: #fecaca; }
    .summary-card.score { background: #eff6ff; border-color: #bfdbfe; }
    .summary-card .number {
        font-size: 28pt;
        font-weight: 700;
        line-height: 1.2;
    }
    .summary-card.total .number { color: #334155; }
    .summary-card.passed .number { color: #16a34a; }
    .summary-card.failed .number { color: #dc2626; }
    .summary-card.score .number { color: #2563eb; }
    .summary-card .label {
        font-size: 9pt;
        color: #64748b;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        font-weight: 600;
        margin-top: 4px;
    }

    /* Severity Summary */
    .severity-table {
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 32px;
        font-size: 10pt;
    }
    .severity-table th {
        background: #f8fafc;
        padding: 10px 16px;
        text-align: left;
        font-weight: 600;
        color: #334155;
        border-bottom: 2px solid #e2e8f0;
    }
    .severity-table td {
        padding: 10px 16px;
        border-bottom: 1px solid #f1f5f9;
    }
    .severity-badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 4px;
        font-size: 8.5pt;
        font-weight: 600;
        text-transform: uppercase;
    }
    .severity-high { background: #fef2f2; color: #991b1b; }
    .severity-medium { background: #fffbeb; color: #92400e; }
    .severity-low { background: #f0fdf4; color: #166534; }

    /* Control Sections */
    .control-section {
        margin-bottom: 28px;
        page-break-inside: avoid;
    }
    .control-header {
        background: #f8fafc;
        padding: 12px 20px;
        border-left: 4px solid #1e40af;
        margin-bottom: 12px;
        border-radius: 0 6px 6px 0;
    }
    .control-header h2 {
        font-size: 13pt;
        font-weight: 600;
        color: #1e293b;
    }

    /* Check Results */
    .check-result {
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        margin-bottom: 10px;
        overflow: hidden;
    }
    .check-header {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 12px 20px;
        background: #ffffff;
    }
    .status-badge {
        display: inline-block;
        padding: 3px 12px;
        border-radius: 4px;
        font-size: 8.5pt;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        flex-shrink: 0;
    }
    .status-pass { background: #dcfce7; color: #15803d; }
    .status-fail { background: #fee2e2; color: #b91c1c; }
    .status-error { background: #fef3c7; color: #92400e; }
    .check-title {
        font-weight: 600;
        color: #1e293b;
        font-size: 10.5pt;
    }
    .check-id {
        margin-left: auto;
        font-size: 9pt;
        color: #94a3b8;
        font-weight: 500;
        flex-shrink: 0;
    }
    .check-details {
        padding: 12px 20px;
        background: #fafbfc;
        border-top: 1px solid #f1f5f9;
        font-size: 9.5pt;
    }
    .check-details p {
        margin-bottom: 8px;
        color: #475569;
    }
    .detail-row {
        display: flex;
        gap: 8px;
        margin-bottom: 4px;
    }
    .detail-label {
        font-weight: 600;
        color: #334155;
        min-width: 100px;
    }
    .detail-value { color: #475569; }
    .remediation {
        margin-top: 12px;
        padding: 12px 16px;
        background: #fff7ed;
        border-left: 3px solid #f97316;
        border-radius: 0 6px 6px 0;
        font-size: 9pt;
    }
    .remediation-title {
        font-weight: 700;
        color: #c2410c;
        margin-bottom: 6px;
        font-size: 9.5pt;
    }
    .remediation pre {
        white-space: pre-wrap;
        font-family: 'Courier New', monospace;
        font-size: 8.5pt;
        color: #44403c;
        line-height: 1.5;
    }

    /* Footer */
    .report-footer {
        margin-top: 40px;
        padding-top: 16px;
        border-top: 1px solid #e2e8f0;
        font-size: 8.5pt;
        color: #94a3b8;
        text-align: center;
    }

    @media print {
        body { font-size: 10pt; }
        .report-container { padding: 20px; }
        .control-section { page-break-inside: avoid; }
        .check-result { page-break-inside: avoid; }
    }
</style>
</head>
<body>
<div class="report-container">

    <!-- Header -->
    <div class="report-header">
        <h1>ISO 27001 Audit Report</h1>
        <div class="subtitle">Annex A Section 8 — Technology Controls</div>
        <div class="report-meta">
            <span><strong>Host:</strong> {{ summary.hostname }}</span>
            <span><strong>OS:</strong> {{ summary.os }}</span>
            <span><strong>Collected:</strong> {{ summary.collection_date }}</span>
            <span><strong>Report Generated:</strong> {{ summary.timestamp[:19] }}</span>
        </div>
    </div>

    <!-- Executive Summary -->
    <div class="summary-section">
        <div class="summary-card total">
            <div class="number">{{ summary.total }}</div>
            <div class="label">Total Checks</div>
        </div>
        <div class="summary-card passed">
            <div class="number">{{ summary.passed }}</div>
            <div class="label">Passed</div>
        </div>
        <div class="summary-card failed">
            <div class="number">{{ summary.failed }}</div>
            <div class="label">Failed</div>
        </div>
        <div class="summary-card score">
            <div class="number">{{ summary.compliance_percentage }}%</div>
            <div class="label">Compliance</div>
        </div>
    </div>

    <!-- Severity Summary -->
    <table class="severity-table">
        <thead>
            <tr>
                <th>Severity</th>
                <th>Passed</th>
                <th>Failed</th>
                <th>Total</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td><span class="severity-badge severity-high">HIGH</span></td>
                <td>{{ severity_summary.high.passed }}</td>
                <td>{{ severity_summary.high.failed }}</td>
                <td>{{ severity_summary.high.passed + severity_summary.high.failed }}</td>
            </tr>
            <tr>
                <td><span class="severity-badge severity-medium">MEDIUM</span></td>
                <td>{{ severity_summary.medium.passed }}</td>
                <td>{{ severity_summary.medium.failed }}</td>
                <td>{{ severity_summary.medium.passed + severity_summary.medium.failed }}</td>
            </tr>
            <tr>
                <td><span class="severity-badge severity-low">LOW</span></td>
                <td>{{ severity_summary.low.passed }}</td>
                <td>{{ severity_summary.low.failed }}</td>
                <td>{{ severity_summary.low.passed + severity_summary.low.failed }}</td>
            </tr>
        </tbody>
    </table>

    <!-- Detailed Results by Control -->
    {% for control in controls %}
    <div class="control-section">
        <div class="control-header">
            <h2>{{ control.control }} — {{ control.control_name }}</h2>
        </div>

        {% for check in control.checks %}
        <div class="check-result">
            <div class="check-header">
                <span class="status-badge status-{{ check.status|lower }}">{{ check.status }}</span>
                <span class="check-title">{{ check.title }}</span>
                <span class="check-id">{{ check.id }}</span>
            </div>
            <div class="check-details">
                <p>{{ check.description }}</p>
                <div class="detail-row">
                    <span class="detail-label">Severity:</span>
                    <span class="detail-value"><span class="severity-badge severity-{{ check.severity }}">{{ check.severity|upper }}</span></span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Expected:</span>
                    <span class="detail-value">{{ check.expected_value }}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Actual:</span>
                    <span class="detail-value">{{ check.actual_value }}</span>
                </div>
                {% if check.remediation %}
                <div class="remediation">
                    <div class="remediation-title">⚠ Remediation Steps</div>
                    <pre>{{ check.remediation }}</pre>
                </div>
                {% endif %}
            </div>
        </div>
        {% endfor %}
    </div>
    {% endfor %}

    <!-- Footer -->
    <div class="report-footer">
        ISO 27001:2022 Annex A Section 8 Audit Report — Generated by ISO Audit App
    </div>
</div>
</body>
</html>"""


class ReportGenerator:

    def __init__(self, reports_dir=None):
        if reports_dir is None:
            reports_dir = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                'reports'
            )
        self.reports_dir = reports_dir
        os.makedirs(self.reports_dir, exist_ok=True)

    def generate_html_report(self, audit_data, audit_id):
        template = Template(REPORT_TEMPLATE)
        html_content = template.render(
            summary=audit_data['summary'],
            results=audit_data['results'],
            controls=audit_data['controls'],
            severity_summary=audit_data['severity_summary'],
        )

        filename = f"audit_report_{audit_id}.html"
        filepath = os.path.join(self.reports_dir, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return filepath

    def generate_pdf_report(self, audit_data, audit_id):
        try:
            from xhtml2pdf import pisa
        except ImportError:
            print("[WARNING] xhtml2pdf not installed. Run: pip install xhtml2pdf")
            return None

        template = Template(REPORT_TEMPLATE)
        html_content = template.render(
            summary=audit_data['summary'],
            results=audit_data['results'],
            controls=audit_data['controls'],
            severity_summary=audit_data['severity_summary'],
        )
        # xhtml2pdf can't fetch external URLs, so strip the Google Fonts import
        html_content = html_content.replace(
            "@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');",
            ""
        )

        filename = f"audit_report_{audit_id}.pdf"
        filepath = os.path.join(self.reports_dir, filename)

        try:
            with open(filepath, 'wb') as pdf_file:
                result = pisa.CreatePDF(html_content, dest=pdf_file, encoding='utf-8')
            if result.err:
                print(f"[ERROR] PDF generation had errors (err={result.err})")
                return None
            return filepath
        except Exception as e:
            print(f"[ERROR] PDF generation failed: {e}")
            return None
