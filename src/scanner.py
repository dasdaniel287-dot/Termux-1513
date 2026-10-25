"""
WebShield AI - Core Assessment Orchestration Engine
Coordinates safe HTTP probes, DNS inspections, TLS handshakes, header audits,
configuration hygiene checks, scoring, reporting, and database storage.
"""

import time
import datetime
import uuid
import urllib.parse
from typing import Dict, Any, Optional, Callable

import requests

from .safety import SafetyManager, SafetyViolation
from .headers import HeaderAnalyzer
from .tls_checker import TLSChecker
from .dns_checker import DNSChecker
from .scoring import ScoringEngine
from .reports import ReportGenerator
from .database import ScanDatabase

class WebShieldScanner:
    """Core scanning orchestrator for WebShield AI."""

    DEFAULT_USER_AGENT = "WebShield-AI/1.0 (+https://github.com/webshield-ai; Security-Audit-Bot; Termux)"

    def __init__(
        self,
        allow_local_testing: bool = False,
        request_timeout: float = 6.0,
        reports_dir: Optional[str] = None,
        db_path: Optional[str] = None,
    ):
        self.safety = SafetyManager(allow_local_testing=allow_local_testing, request_timeout=request_timeout)
        self.headers_analyzer = HeaderAnalyzer()
        self.tls_checker = TLSChecker(timeout=request_timeout)
        self.dns_checker = DNSChecker(timeout=request_timeout)
        self.scoring = ScoringEngine()
        self.reporter = ReportGenerator(output_dir=reports_dir) if reports_dir else ReportGenerator()
        self.database = ScanDatabase(db_path=db_path) if db_path else ScanDatabase()
        self.timeout = request_timeout

    def run_scan(
        self,
        target_url: str,
        user_confirmed_authorization: bool,
        progress_callback: Optional[Callable[[str, int, str], None]] = None,
    ) -> Dict[str, Any]:
        """
        Executes a comprehensive, non-destructive security assessment.
        Progress callback receives (step_name, percentage, status_message).
        """
        start_time = time.time()
        scan_id = f"ws_{int(time.time())}_{uuid.uuid4().hex[:6]}"
        timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        def notify(step: str, pct: int, msg: str):
            if progress_callback:
                progress_callback(step, pct, msg)

        # 1. Authorization Verification
        notify("Authorization", 10, "Validating explicit consent and authorization scope...")
        self.safety.validate_authorization(user_confirmed_authorization)

        # 2. URL Parse and Normalization
        notify("Validation", 20, "Normalizing URL and verifying scheme/port parameters...")
        norm_url, hostname, port, scheme = self.safety.parse_and_validate_url(target_url)

        # 3. Anti-SSRF and DNS Resolution Check
        notify("Anti-SSRF", 30, f"Resolving domain '{hostname}' and checking destination safety...")
        resolved_ips = self.safety.verify_ssrf_safety(hostname)

        checks_performed = [
            "Authorization Confirmation Check",
            "URL Format and Scope Validation",
            "Anti-SSRF and Private Range Guardrails",
        ]
        all_findings = []

        # 4. DNS Records Inspection
        notify("DNS Inspection", 45, f"Auditing DNS records (A, AAAA, MX, NS, TXT, DMARC) for {hostname}...")
        dns_res = self.dns_checker.check(hostname)
        all_findings.extend(dns_res.get("findings", []))
        checks_performed.append("DNS Record & Email Anti-Spoofing Audit (SPF/DMARC)")

        # 5. TLS / SSL Certificate Handshake
        tls_res = {}
        if scheme == "https" or port == 443:
            notify("TLS Handshake", 60, f"Performing cryptographic TLS handshake on {hostname}:{port}...")
            tls_res = self.tls_checker.check(hostname, port)
            all_findings.extend(tls_res.get("findings", []))
            checks_performed.append("TLS/SSL Certificate Expiration & Cipher Suite Verification")

        # 6. HTTP / HTTPS Availability & Redirect Safety
        notify("HTTP Probing", 75, f"Inspecting HTTP response, status codes, and redirect safety...")
        http_data = self._probe_http_availability(norm_url, hostname, scheme, port, all_findings, checks_performed)

        # 7. Security Header Analysis
        notify("Header Analysis", 85, "Analyzing defensive security headers (HSTS, CSP, XCTO, XFO)...")
        headers = http_data.get("headers", {})
        header_res = self.headers_analyzer.analyze(headers, norm_url, is_https=(scheme == "https"))
        all_findings.extend(header_res.get("findings", []))
        checks_performed.append("HTTP Defensive Security Headers Analysis")

        # 8. Safe Configuration and Public Resource Checks
        notify("Config Checks", 92, "Checking safe public resource indicators (robots.txt, security.txt)...")
        self._check_safe_resources(hostname, scheme, port, all_findings, checks_performed)

        # 9. Scoring Computation
        notify("Scoring", 98, "Calculating explainable security score and risk classification...")
        score_data = self.scoring.compute(all_findings, scan_status="completed")

        duration = round(time.time() - start_time, 2)

        scan_payload = {
            "id": scan_id,
            "timestamp": timestamp,
            "target_url": norm_url,
            "domain": hostname,
            "port": port,
            "scheme": scheme,
            "resolved_ips": resolved_ips,
            "duration_seconds": duration,
            "status": "completed",
            "checks_performed": checks_performed,
            "http_info": http_data,
            "tls_info": tls_res.get("tls_info", {}),
            "dns_records": dns_res.get("records", {}),
            "findings": all_findings,
            "score_data": score_data,
            "summary": {
                "score": score_data.get("score"),
                "grade": score_data.get("grade"),
                "total_findings": len(all_findings),
                "counts": score_data.get("counts", {}),
            },
        }

        # 10. Generate Deliverable Reports
        report_paths = self.reporter.generate_all(scan_payload)
        scan_payload["report_paths"] = report_paths

        # 11. Store in SQLite Database
        self.database.save_scan(scan_payload)

        notify("Completed", 100, f"Assessment complete! Security Score: {score_data.get('score')}/100 [Grade {score_data.get('grade')}]")
        return scan_payload

    def _probe_http_availability(
        self,
        url: str,
        hostname: str,
        scheme: str,
        port: int,
        findings: list,
        checks: list,
    ) -> Dict[str, Any]:
        """Probes endpoint availability, response latency, and safe redirect behavior."""
        checks.append("HTTP Endpoint Availability & Latency Audit")
        session = requests.Session()
        session.headers.update({"User-Agent": self.DEFAULT_USER_AGENT})

        http_info = {
            "status_code": None,
            "response_time_ms": 0.0,
            "redirect_chain": [],
            "final_url": url,
            "headers": {},
        }

        try:
            req_start = time.time()
            resp = session.get(url, timeout=self.timeout, allow_redirects=True)
            latency = round((time.time() - req_start) * 1000, 1)

            http_info["status_code"] = resp.status_code
            http_info["response_time_ms"] = latency
            http_info["final_url"] = resp.url
            http_info["headers"] = dict(resp.headers)

            for r in resp.history:
                http_info["redirect_chain"].append({
                    "url": r.url,
                    "status_code": r.status_code,
                })

            # Check for HTTP-to-HTTPS redirect if initial target was plain HTTP
            if scheme == "http":
                final_scheme = urllib.parse.urlsplit(resp.url).scheme.lower()
                if final_scheme != "https":
                    findings.append({
                        "id": "CFG-NO-HTTPS-REDIRECT",
                        "check_name": "HTTP Does Not Redirect to Secure HTTPS",
                        "severity": "High",
                        "evidence": f"Request to {url} resulted in {resp.url} (Final Status: {resp.status_code})",
                        "affected_component": "HTTP Transport Routing",
                        "current_value": "Plaintext HTTP preserved",
                        "technical_explanation": (
                            "Web traffic remains unencrypted without automated redirection from HTTP to HTTPS."
                        ),
                        "potential_impact": "Plaintext credentials and cookies can be intercepted on public Wi-Fi networks.",
                        "recommended_fix": "Configure permanent 301 or 308 redirect from HTTP port 80 to HTTPS port 443.",
                        "verification_steps": f"curl -sI http://{hostname} | grep -i location",
                        "confidence_level": "Confirmed",
                    })
                else:
                    findings.append({
                        "id": "CFG-HTTPS-REDIRECT-OK",
                        "check_name": "Automatic HTTPS Redirection Active",
                        "severity": "Informational",
                        "evidence": f"HTTP traffic redirected to {resp.url}",
                        "affected_component": "HTTP Transport Routing",
                        "current_value": "HTTPS Enforced",
                        "technical_explanation": "Insecure HTTP connections are safely upgraded to HTTPS.",
                        "potential_impact": "None. Defensive control validated.",
                        "recommended_fix": "Maintain redirection rule with 301 Moved Permanently.",
                        "verification_steps": f"curl -sI http://{hostname}",
                        "confidence_level": "Confirmed",
                    })

            # Status code evaluation
            if resp.status_code >= 500:
                findings.append({
                    "id": "AVAIL-SERVER-ERROR",
                    "check_name": "HTTP 5xx Server Error Response",
                    "severity": "Medium",
                    "evidence": f"Received HTTP {resp.status_code} from {url}",
                    "affected_component": "Web Server / Application",
                    "current_value": f"HTTP {resp.status_code}",
                    "technical_explanation": "The web application returned a 5xx server-side failure during baseline probing.",
                    "potential_impact": "Indicates application unreliability or unhandled exception state.",
                    "recommended_fix": "Inspect server application logs for fatal backend stack traces.",
                    "verification_steps": f"curl -sI {url}",
                    "confidence_level": "High",
                })

        except requests.exceptions.SSLError as e:
            findings.append({
                "id": "AVAIL-SSL-ERROR",
                "check_name": "HTTP Client SSL Verification Error",
                "severity": "Critical",
                "evidence": str(e),
                "affected_component": "HTTPS Connection",
                "current_value": "SSL Validation Failed",
                "technical_explanation": "Client failed certificate validation while initiating HTTPS request.",
                "potential_impact": "Visitors will receive security warnings and cannot safely connect.",
                "recommended_fix": "Deploy a valid, CA-signed certificate.",
                "verification_steps": f"curl -Iv {url}",
                "confidence_level": "Confirmed",
            })
        except requests.exceptions.Timeout:
            findings.append({
                "id": "AVAIL-TIMEOUT",
                "check_name": "HTTP Request Timeout",
                "severity": "High",
                "evidence": f"Request exceeded {self.timeout}s timeout.",
                "affected_component": "HTTP Listener",
                "current_value": "Timeout",
                "technical_explanation": "Server did not return an HTTP response within safe timeout window.",
                "potential_impact": "Service unreachability.",
                "recommended_fix": "Verify hosting server status and firewall configuration.",
                "verification_steps": f"curl -Iv --connect-timeout 5 {url}",
                "confidence_level": "Confirmed",
            })
        except requests.exceptions.ConnectionError as e:
            findings.append({
                "id": "AVAIL-CONN-ERROR",
                "check_name": "HTTP Connection Failed",
                "severity": "High",
                "evidence": str(e),
                "affected_component": "HTTP Listener",
                "current_value": "Connection Failed",
                "technical_explanation": "Could not establish TCP connection to web server.",
                "potential_impact": "Target is unreachable.",
                "recommended_fix": "Ensure web server is running and accessible from the public internet.",
                "verification_steps": f"curl -Iv {url}",
                "confidence_level": "Confirmed",
            })

        return http_info

    def _check_safe_resources(self, hostname: str, scheme: str, port: int, findings: list, checks: list) -> None:
        """
        Safely inspects public resource files (robots.txt, .well-known/security.txt).
        Does NOT download sensitive files, crawl private paths, or attempt brute force.
        """
        checks.append("Public Security Policy & Crawling Hygiene (security.txt, robots.txt)")
        base = f"{scheme}://{hostname}"
        if (scheme == "https" and port != 443) or (scheme == "http" and port != 80):
            base += f":{port}"

        session = requests.Session()
        session.headers.update({"User-Agent": self.DEFAULT_USER_AGENT})

        # 1. security.txt (RFC 9116)
        sec_url = f"{base}/.well-known/security.txt"
        try:
            resp = session.get(sec_url, timeout=3.0, allow_redirects=True)
            if resp.status_code == 200 and "contact:" in resp.text.lower():
                findings.append({
                    "id": "CFG-SECURITY-TXT-OK",
                    "check_name": "security.txt Policy Discovered (RFC 9116)",
                    "severity": "Informational",
                    "evidence": f"Found valid security.txt at {sec_url}",
                    "affected_component": "/.well-known/security.txt",
                    "current_value": "Configured",
                    "technical_explanation": (
                        "A standard RFC 9116 security.txt file exists providing vulnerability disclosure contacts."
                    ),
                    "potential_impact": "None. Excellent coordinated disclosure posture.",
                    "recommended_fix": "Ensure contact email and PGP keys are kept current.",
                    "verification_steps": f"curl -s {sec_url}",
                    "confidence_level": "Confirmed",
                })
            else:
                findings.append({
                    "id": "CFG-SECURITY-TXT-MISSING",
                    "check_name": "security.txt Vulnerability Disclosure Policy Missing",
                    "severity": "Informational",
                    "evidence": f"{sec_url} returned status {resp.status_code}",
                    "affected_component": "/.well-known/security.txt",
                    "current_value": "Absent",
                    "technical_explanation": (
                        "RFC 9116 recommends publishing /.well-known/security.txt so ethical security researchers "
                        "can report security vulnerabilities responsibly."
                    ),
                    "potential_impact": "Security researchers may have difficulty contacting security team.",
                    "recommended_fix": "Publish /.well-known/security.txt with 'Contact: mailto:security@yourdomain.example'.",
                    "verification_steps": f"curl -s {sec_url}",
                    "confidence_level": "High",
                })
        except Exception:
            pass

        # 2. robots.txt safe inspection
        robots_url = f"{base}/robots.txt"
        try:
            r_resp = session.get(robots_url, timeout=3.0, allow_redirects=True)
            if r_resp.status_code == 200:
                content = r_resp.text.lower()
                # Check if dangerous sensitive admin paths are listed openly in Disallow
                sensitive_hints = ["/admin", "/backup", "/config", "/secret", "/internal", "/db"]
                disallowed_sensitive = [p for p in sensitive_hints if f"disallow: {p}" in content or f"disallow:/{p}" in content]
                if disallowed_sensitive:
                    findings.append({
                        "id": "CFG-ROBOTS-SENSITIVE-PATH",
                        "check_name": "Sensitive Path Disclosed in robots.txt",
                        "severity": "Low",
                        "evidence": f"robots.txt disallows: {', '.join(disallowed_sensitive)}",
                        "affected_component": "/robots.txt",
                        "current_value": f"Disallows: {', '.join(disallowed_sensitive)}",
                        "technical_explanation": (
                            "Listing administrative or internal directories in robots.txt advertises their existence "
                            "to web crawlers and reconnaissance scanners."
                        ),
                        "potential_impact": "Guides malicious scanners directly to sensitive application locations.",
                        "recommended_fix": (
                            "Protect sensitive endpoints with proper authentication rather than relying on robots.txt obscurity. "
                            "Remove sensitive path enumerations if feasible."
                        ),
                        "verification_steps": f"curl -s {robots_url}",
                        "confidence_level": "High",
                    })
        except Exception:
            pass
