"""
WebShield AI - Multi-Format Report Generator Module
Creates professional HTML, JSON, and plaintext TXT assessment reports
with executive summaries, finding evidence, and remediation plans.
"""

import json
import os
import datetime
from typing import Dict, Any

DEFAULT_REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")

class ReportGenerator:
    """Generates structured HTML, JSON, and TXT security audit deliverables."""

    def __init__(self, output_dir: str = DEFAULT_REPORTS_DIR):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_all(self, scan_data: Dict[str, Any]) -> Dict[str, str]:
        """
        Builds HTML, JSON, and TXT reports and writes them to reports directory.
        Returns paths dict: {"html": ..., "json": ..., "txt": ...}
        """
        scan_id = scan_data.get("id", "scan_" + datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S"))
        domain = scan_data.get("domain", "target").replace(":", "_").replace("/", "_")

        base_name = f"webshield_{domain}_{scan_id}"
        json_path = os.path.join(self.output_dir, f"{base_name}.json")
        txt_path = os.path.join(self.output_dir, f"{base_name}.txt")
        html_path = os.path.join(self.output_dir, f"{base_name}.html")

        # 1. JSON
        json_content = self.generate_json(scan_data)
        with open(json_path, "w", encoding="utf-8") as f:
            f.write(json_content)

        # 2. Plain TXT
        txt_content = self.generate_txt(scan_data)
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(txt_content)

        # 3. HTML
        html_content = self.generate_html(scan_data)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return {
            "json": json_path,
            "txt": txt_path,
            "html": html_path,
        }

    def generate_json(self, scan_data: Dict[str, Any]) -> str:
        """Serializes complete scan payload with indent."""
        return json.dumps(scan_data, indent=2, ensure_ascii=False)

    def generate_txt(self, scan_data: Dict[str, Any]) -> str:
        """Generates clean human-readable plain text report."""
        lines = []
        lines.append("=" * 76)
        lines.append("              WEBSHIELD AI — WEBSITE SECURITY REPORT")
        lines.append("=" * 76)
        lines.append("")
        lines.append(f"Assessment ID   : {scan_data.get('id', 'N/A')}")
        lines.append(f"Target Domain   : {scan_data.get('domain', 'N/A')}")
        lines.append(f"Target URL      : {scan_data.get('target_url', 'N/A')}")
        lines.append(f"Assessment Date : {scan_data.get('timestamp', 'N/A')} UTC")
        lines.append(f"Authorized Scope: Explicit Permission Confirmed (Safe Non-Destructive Mode)")
        lines.append(f"Execution Time  : {scan_data.get('duration_seconds', 0):.2f} seconds")
        lines.append("")

        score_data = scan_data.get("score_data", {})
        lines.append("-" * 76)
        lines.append(f"SECURITY POSTURE SCORE: {score_data.get('score', 'N/A')} / 100  [ Grade: {score_data.get('grade', 'N/A')} ]")
        lines.append("-" * 76)
        lines.append(score_data.get("explanation", "Score computed from baseline audit rules."))
        lines.append("")

        counts = score_data.get("counts", {})
        lines.append(
            f"Findings Summary: Critical: {counts.get('Critical', 0)} | "
            f"High: {counts.get('High', 0)} | Medium: {counts.get('Medium', 0)} | "
            f"Low: {counts.get('Low', 0)} | Informational: {counts.get('Informational', 0)}"
        )
        lines.append("")

        lines.append("-" * 76)
        lines.append("CHECKS PERFORMED")
        lines.append("-" * 76)
        for check in scan_data.get("checks_performed", []):
            lines.append(f" [✓] {check}")
        lines.append("")

        lines.append("-" * 76)
        lines.append("DETAILED SECURITY FINDINGS & RECOMMENDATIONS")
        lines.append("-" * 76)
        findings = scan_data.get("findings", [])
        if not findings:
            lines.append("No security anomalies or missing defensive controls observed.")
        else:
            for idx, f in enumerate(findings, 1):
                sev = f.get("severity", "Info").upper()
                lines.append(f"\n[{idx}] [{sev}] {f.get('check_name')} (ID: {f.get('id')})")
                lines.append(f"    Component   : {f.get('affected_component', 'N/A')}")
                lines.append(f"    Confidence  : {f.get('confidence_level', 'High')}")
                lines.append(f"    Evidence    : {f.get('evidence', 'None')}")
                lines.append(f"    Explanation : {f.get('technical_explanation', 'N/A')}")
                lines.append(f"    Risk Impact : {f.get('potential_impact', 'N/A')}")
                lines.append(f"    Remediation : {f.get('recommended_fix', 'N/A')}")
                lines.append(f"    Verification: {f.get('verification_steps', 'N/A')}")

        lines.append("\n" + "-" * 76)
        lines.append("SCAN LIMITATIONS & DEFENSIVE SCOPE NOTICE")
        lines.append("-" * 76)
        lines.append(
            "1. This assessment only evaluates externally observable network endpoints, TLS configurations,\n"
            "   DNS records, and HTTP response headers.\n"
            "2. No exploitation, authentication bypass, denial of service, or source code reverse engineering\n"
            "   was attempted or included.\n"
            "3. WebShield AI is designed to assist authorized owners in applying defensive hardening fixes.\n"
        )
        lines.append("=" * 76)
        lines.append("Generated by WebShield AI (Termux & Web Edition)")
        lines.append("=" * 76)
        return "\n".join(lines)

    def generate_html(self, scan_data: Dict[str, Any]) -> str:
        """Generates responsive, self-contained modern HTML report."""
        score_data = scan_data.get("score_data", {})
        score = score_data.get("score", "N/A")
        grade = score_data.get("grade", "N/A")
        counts = score_data.get("counts", {})
        findings = scan_data.get("findings", [])

        # Color mapping
        grade_color = "#10b981" if grade in ("A+", "A") else "#f59e0b" if grade == "B" else "#ef4444"

        findings_html = []
        for idx, f in enumerate(findings, 1):
            sev = f.get("severity", "Informational")
            badge_class = (
                "bg-red-950 text-red-300 border-red-800" if sev == "Critical" else
                "bg-orange-950 text-orange-300 border-orange-800" if sev == "High" else
                "bg-amber-950 text-amber-300 border-amber-800" if sev == "Medium" else
                "bg-blue-950 text-blue-300 border-blue-800" if sev == "Low" else
                "bg-slate-900 text-slate-300 border-slate-700"
            )

            findings_html.append(f"""
            <div class="mb-6 p-5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm">
                <div class="flex flex-wrap items-center justify-between gap-3 mb-3">
                    <div class="flex items-center gap-3">
                        <span class="text-xs px-2.5 py-1 rounded font-semibold border {badge_class}">{sev.upper()}</span>
                        <h4 class="text-base font-bold text-slate-100">{f.get('check_name')}</h4>
                    </div>
                    <span class="text-xs font-mono text-slate-400">ID: {f.get('id')} · Confidence: {f.get('confidence_level', 'High')}</span>
                </div>
                <div class="space-y-2 text-sm text-slate-300">
                    <p><strong class="text-slate-200">Component:</strong> <span class="font-mono text-xs">{f.get('affected_component', 'N/A')}</span></p>
                    <p><strong class="text-slate-200">Evidence:</strong> <span class="font-mono text-xs text-cyan-300">{f.get('evidence', 'None')}</span></p>
                    <p><strong class="text-slate-200">Technical Analysis:</strong> {f.get('technical_explanation', 'N/A')}</p>
                    <p><strong class="text-slate-200">Potential Impact:</strong> {f.get('potential_impact', 'N/A')}</p>
                    <div class="mt-3 p-3 rounded-lg bg-slate-950 border border-slate-800">
                        <div class="text-xs font-semibold text-emerald-400 mb-1">RECOMMENDED REMEDIATION:</div>
                        <div class="text-xs text-slate-200">{f.get('recommended_fix', 'N/A')}</div>
                        <div class="text-xs font-mono text-slate-400 mt-2 bg-slate-900 p-2 rounded">
                            <span class="text-slate-500"># Verification step:</span><br/>
                            {f.get('verification_steps', 'N/A')}
                        </div>
                    </div>
                </div>
            </div>
            """)

        rendered_findings = "".join(findings_html) if findings_html else "<p class='text-slate-400'>No anomalies observed.</p>"

        checks_html = "".join([f"<li class='flex items-center gap-2'><span class='text-emerald-400'>✓</span> {c}</li>" for c in scan_data.get("checks_performed", [])])

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebShield AI Security Report - {scan_data.get('domain')}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=Plus+Jakarta+Sans:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        body {{ font-family: 'Plus Jakarta Sans', sans-serif; }}
        code, pre, .font-mono {{ font-family: 'JetBrains Mono', monospace; }}
    </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen p-6 md:p-12">
    <div class="max-w-4xl mx-auto">
        <!-- Header -->
        <div class="flex flex-wrap items-center justify-between border-b border-slate-800 pb-6 mb-8 gap-4">
            <div>
                <div class="text-xs font-mono text-cyan-400 font-semibold tracking-wider uppercase mb-1">WebShield AI Security Assessment</div>
                <h1 class="text-2xl md:text-3xl font-bold text-white tracking-tight">{scan_data.get('domain')}</h1>
                <div class="text-xs text-slate-400 mt-1">Generated {scan_data.get('timestamp')} UTC · Target URL: {scan_data.get('target_url')}</div>
            </div>
            <div class="p-4 rounded-xl bg-slate-900 border border-slate-800 text-center min-w-[130px]">
                <div class="text-3xl font-black font-mono" style="color: {grade_color}">{score}</div>
                <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Grade: {grade}</div>
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 mb-8">
            <h2 class="text-base font-bold text-white mb-2">Executive Summary & Audit Scope</h2>
            <p class="text-sm text-slate-300 leading-relaxed mb-4">{score_data.get('explanation')}</p>
            <div class="grid grid-cols-2 md:grid-cols-5 gap-3 pt-3 border-t border-slate-800 text-center">
                <div class="p-2.5 rounded-lg bg-red-950/40 border border-red-900/60">
                    <div class="text-xl font-bold text-red-400 font-mono">{counts.get('Critical', 0)}</div>
                    <div class="text-xs text-slate-400 uppercase">Critical</div>
                </div>
                <div class="p-2.5 rounded-lg bg-orange-950/40 border border-orange-900/60">
                    <div class="text-xl font-bold text-orange-400 font-mono">{counts.get('High', 0)}</div>
                    <div class="text-xs text-slate-400 uppercase">High</div>
                </div>
                <div class="p-2.5 rounded-lg bg-amber-950/40 border border-amber-900/60">
                    <div class="text-xl font-bold text-amber-400 font-mono">{counts.get('Medium', 0)}</div>
                    <div class="text-xs text-slate-400 uppercase">Medium</div>
                </div>
                <div class="p-2.5 rounded-lg bg-blue-950/40 border border-blue-900/60">
                    <div class="text-xl font-bold text-blue-400 font-mono">{counts.get('Low', 0)}</div>
                    <div class="text-xs text-slate-400 uppercase">Low</div>
                </div>
                <div class="p-2.5 rounded-lg bg-slate-800/40 border border-slate-700/60">
                    <div class="text-xl font-bold text-slate-400 font-mono">{counts.get('Informational', 0)}</div>
                    <div class="text-xs text-slate-400 uppercase">Informational</div>
                </div>
            </div>
        </div>

        <!-- Checks Run -->
        <div class="mb-8">
            <h3 class="text-sm font-bold text-slate-300 uppercase tracking-wider mb-3">Checks Completed</h3>
            <ul class="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs text-slate-400 bg-slate-900/40 p-4 rounded-xl border border-slate-800">
                {checks_html}
            </ul>
        </div>

        <!-- Findings -->
        <div class="mb-10">
            <h3 class="text-base font-bold text-white mb-4">Detailed Findings & Remediation</h3>
            {rendered_findings}
        </div>

        <!-- Limitations & Disclaimer -->
        <div class="p-5 rounded-xl bg-slate-900/40 border border-slate-800/80 text-xs text-slate-400 space-y-2">
            <div class="font-bold text-slate-300 uppercase tracking-wider">Audit Limitations & Notice</div>
            <p>{score_data.get('disclaimer')}</p>
            <p>Assessment executed by WebShield AI in authorized defensive configuration auditing mode.</p>
        </div>
    </div>
</body>
</html>"""
