"""
WebShield AI - HTTP Security Header Checker Module
Analyzes server HTTP response headers against modern security standards,
providing actionable remediation advice, evidence, and risk classification.
"""

from typing import Dict, List, Any, Optional

class HeaderAnalyzer:
    """Evaluates HTTP response headers for defensive security postures."""

    SECURITY_HEADERS = [
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    ]

    def analyze(self, headers: Dict[str, str], target_url: str, is_https: bool) -> Dict[str, Any]:
        """
        Runs comprehensive analysis on normalized headers.
        Returns findings list, posture summary, and raw observed headers.
        """
        # Case-fold headers for lookup
        h = {k.lower(): v for k, v in headers.items()}
        findings: List[Dict[str, Any]] = []

        # 1. Strict-Transport-Security (HSTS)
        hsts = h.get("strict-transport-security")
        if not is_https:
            findings.append({
                "id": "HDR-HSTS-PLAIN",
                "check_name": "Strict-Transport-Security on Plain HTTP",
                "severity": "Informational",
                "evidence": "Target evaluated over plain HTTP.",
                "affected_component": "HTTP Response Headers",
                "current_value": "N/A (HTTP target)",
                "technical_explanation": (
                    "HSTS is only recognized by browsers when delivered over a secure HTTPS connection. "
                    "Serving HSTS over plain HTTP is ignored by user agents."
                ),
                "potential_impact": "Users can be subject to SSL stripping attacks on unencrypted channels.",
                "recommended_fix": "Deploy TLS encryption and enforce HTTPS with an HSTS header.",
                "verification_steps": "curl -sI https://your-domain.example | grep -i strict-transport-security",
                "confidence_level": "Confirmed",
            })
        elif not hsts:
            findings.append({
                "id": "HDR-HSTS-MISSING",
                "check_name": "Strict-Transport-Security Missing",
                "severity": "High",
                "evidence": "Strict-Transport-Security header not present in HTTPS response.",
                "affected_component": "HTTP Response Headers",
                "current_value": None,
                "technical_explanation": (
                    "HTTP Strict Transport Security (HSTS) instructs compliant browsers that the domain "
                    "must only be contacted over HTTPS for a specified duration."
                ),
                "potential_impact": (
                    "Vulnerable to Man-in-the-Middle (MitM) SSL stripping and insecure HTTP downgrades "
                    "when users first visit via bookmark or typed domain."
                ),
                "recommended_fix": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' in web server config.",
                "verification_steps": "curl -sI https://your-domain.example | grep -i strict-transport-security",
                "confidence_level": "Confirmed",
            })
        else:
            # Check max-age
            max_age = 0
            for part in hsts.split(";"):
                part = part.strip().lower()
                if part.startswith("max-age="):
                    try:
                        max_age = int(part.split("=")[1])
                    except ValueError:
                        pass
            if max_age < 15552000: # Less than 180 days
                findings.append({
                    "id": "HDR-HSTS-SHORT",
                    "check_name": "HSTS Duration Below Recommended Threshold",
                    "severity": "Low",
                    "evidence": f"Observed HSTS: {hsts}",
                    "affected_component": "HTTP Response Headers",
                    "current_value": hsts,
                    "technical_explanation": (
                        f"Current max-age is {max_age} seconds. Industry best practice recommends at least "
                        "31,536,000 seconds (1 year) for comprehensive browser enforcement."
                    ),
                    "potential_impact": "Security protection window expires quickly if visitors do not return frequently.",
                    "recommended_fix": "Increase max-age to 31536000 (1 year) or 63072000 (2 years).",
                    "verification_steps": "Inspect the max-age directive in curl -sI output.",
                    "confidence_level": "High",
                })
            else:
                findings.append({
                    "id": "HDR-HSTS-OK",
                    "check_name": "Strict-Transport-Security Configured",
                    "severity": "Informational",
                    "evidence": f"HSTS header present: {hsts}",
                    "affected_component": "HTTP Response Headers",
                    "current_value": hsts,
                    "technical_explanation": "Valid HSTS configuration detected with sufficient retention duration.",
                    "potential_impact": "None. Defensive control verified.",
                    "recommended_fix": "Maintain configuration; verify includeSubDomains and preload if eligible.",
                    "verification_steps": "curl -sI https://your-domain.example | grep -i strict-transport-security",
                    "confidence_level": "Confirmed",
                })

        # 2. Content-Security-Policy (CSP)
        csp = h.get("content-security-policy")
        if not csp:
            findings.append({
                "id": "HDR-CSP-MISSING",
                "check_name": "Content-Security-Policy Header Missing",
                "severity": "High",
                "evidence": "Content-Security-Policy header not returned in response.",
                "affected_component": "HTTP Response Headers",
                "current_value": None,
                "technical_explanation": (
                    "Content Security Policy (CSP) is a critical defensive HTTP response header that helps "
                    "prevent and mitigate Cross-Site Scripting (XSS), data injection, and malicious clickjacking."
                ),
                "potential_impact": "Higher blast radius if an XSS flaw exists on the application layer.",
                "recommended_fix": (
                    "Define a strict CSP beginning with: default-src 'self'; script-src 'self'; object-src 'none'; "
                    "base-uri 'self'; frame-ancestors 'none';"
                ),
                "verification_steps": "curl -sI https://your-domain.example | grep -i content-security-policy",
                "confidence_level": "Confirmed",
            })
        else:
            # Check for weak directives
            csp_lower = csp.lower()
            weaknesses = []
            if "'unsafe-inline'" in csp_lower:
                weaknesses.append("'unsafe-inline' in script or style sources")
            if "'unsafe-eval'" in csp_lower:
                weaknesses.append("'unsafe-eval' permits dynamic string code execution")
            if "default-src *" in csp_lower or "script-src *" in csp_lower:
                weaknesses.append("Wildcard '*' source allows external resource loading")

            if weaknesses:
                findings.append({
                    "id": "HDR-CSP-WEAK",
                    "check_name": "Content-Security-Policy Contains Permissive Directives",
                    "severity": "Medium",
                    "evidence": f"Observed CSP: {csp} (Identified: {', '.join(weaknesses)})",
                    "affected_component": "HTTP Response Headers",
                    "current_value": csp,
                    "technical_explanation": (
                        "The Content Security Policy allows unsafe directives which degrade protection against XSS."
                    ),
                    "potential_impact": "Attackers may bypass XSS defenses if inline scripts or evals can be influenced.",
                    "recommended_fix": "Refactor inline scripts to use cryptographic nonces or hashes (e.g. 'nonce-...').",
                    "verification_steps": "Review CSP directives in web server or reverse proxy configuration.",
                    "confidence_level": "High",
                })
            else:
                findings.append({
                    "id": "HDR-CSP-OK",
                    "check_name": "Content-Security-Policy Configured",
                    "severity": "Informational",
                    "evidence": f"CSP present: {csp[:80]}...",
                    "affected_component": "HTTP Response Headers",
                    "current_value": csp,
                    "technical_explanation": "Content-Security-Policy header is active without obvious wildcards.",
                    "potential_impact": "None. Active defense layer in place.",
                    "recommended_fix": "Continuously test CSP using browser reporting (report-to / report-uri).",
                    "verification_steps": "Check browser developer console for CSP violation reports.",
                    "confidence_level": "Confirmed",
                })

        # 3. X-Content-Type-Options
        xcto = h.get("x-content-type-options")
        if not xcto:
            findings.append({
                "id": "HDR-XCTO-MISSING",
                "check_name": "X-Content-Type-Options Header Missing",
                "severity": "Medium",
                "evidence": "X-Content-Type-Options header was not returned.",
                "affected_component": "HTTP Response Headers",
                "current_value": None,
                "technical_explanation": (
                    "X-Content-Type-Options stops browsers from MIME-sniffing a response away from the declared content-type."
                ),
                "potential_impact": (
                    "Browsers may interpret non-executable MIME types (e.g., image/png or text/plain) as executable "
                    "JavaScript or HTML, leading to Drive-by downloads or XSS."
                ),
                "recommended_fix": "Configure header: X-Content-Type-Options: nosniff",
                "verification_steps": "curl -sI https://your-domain.example | grep -i x-content-type-options",
                "confidence_level": "Confirmed",
            })
        elif "nosniff" not in xcto.lower():
            findings.append({
                "id": "HDR-XCTO-INVALID",
                "check_name": "X-Content-Type-Options Misconfigured",
                "severity": "Medium",
                "evidence": f"Current value: {xcto}",
                "affected_component": "HTTP Response Headers",
                "current_value": xcto,
                "technical_explanation": "The only valid standard directive for X-Content-Type-Options is 'nosniff'.",
                "potential_impact": "MIME-sniffing protection disabled or non-functional.",
                "recommended_fix": "Set value strictly to 'nosniff'.",
                "verification_steps": "curl -sI https://your-domain.example | grep -i x-content-type-options",
                "confidence_level": "Confirmed",
            })
        else:
            findings.append({
                "id": "HDR-XCTO-OK",
                "check_name": "X-Content-Type-Options Configured",
                "severity": "Informational",
                "evidence": f"X-Content-Type-Options: {xcto}",
                "affected_component": "HTTP Response Headers",
                "current_value": xcto,
                "technical_explanation": "MIME-type sniffing prevention active with nosniff directive.",
                "potential_impact": "None. Defensive control validated.",
                "recommended_fix": "Retain header.",
                "verification_steps": "curl -sI https://your-domain.example | grep -i x-content-type-options",
                "confidence_level": "Confirmed",
            })

        # 4. X-Frame-Options
        xfo = h.get("x-frame-options")
        if not xfo and (not csp or "frame-ancestors" not in csp.lower()):
            findings.append({
                "id": "HDR-XFO-MISSING",
                "check_name": "Clickjacking Protection Missing (X-Frame-Options)",
                "severity": "Medium",
                "evidence": "Neither X-Frame-Options nor CSP frame-ancestors detected.",
                "affected_component": "HTTP Response Headers",
                "current_value": None,
                "technical_explanation": (
                    "The X-Frame-Options header (or CSP 'frame-ancestors') indicates whether a browser should be "
                    "allowed to render a page inside a <frame>, <iframe>, <embed> or <object>."
                ),
                "potential_impact": "UI redressing / Clickjacking attacks could trick authenticated users into unauthorized clicks.",
                "recommended_fix": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', and include CSP 'frame-ancestors'.",
                "verification_steps": "Test framing via a local HTML file with <iframe src='target_url'>.",
                "confidence_level": "Confirmed",
            })
        elif xfo:
            val = xfo.strip().upper()
            if val in ("DENY", "SAMEORIGIN"):
                findings.append({
                    "id": "HDR-XFO-OK",
                    "check_name": "X-Frame-Options Configured",
                    "severity": "Informational",
                    "evidence": f"X-Frame-Options: {xfo}",
                    "affected_component": "HTTP Response Headers",
                    "current_value": xfo,
                    "technical_explanation": f"Framing restricted with {val} policy.",
                    "potential_impact": "None. Anti-clickjacking active.",
                    "recommended_fix": "Ensure CSP frame-ancestors also matches this policy for future standard alignment.",
                    "verification_steps": "curl -sI https://your-domain.example | grep -i x-frame-options",
                    "confidence_level": "Confirmed",
                })

        # 5. Referrer-Policy
        ref_pol = h.get("referrer-policy")
        if not ref_pol:
            findings.append({
                "id": "HDR-REF-MISSING",
                "check_name": "Referrer-Policy Header Missing",
                "severity": "Low",
                "evidence": "Referrer-Policy header is absent.",
                "affected_component": "HTTP Response Headers",
                "current_value": None,
                "technical_explanation": (
                    "Referrer-Policy governs how much referrer information (URL paths, sensitive query parameters) "
                    "is sent along with requests made from your site."
                ),
                "potential_impact": "Sensitive URL parameters (tokens, session IDs, reset codes) may leak to third-party endpoints.",
                "recommended_fix": "Configure 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
                "verification_steps": "curl -sI https://your-domain.example | grep -i referrer-policy",
                "confidence_level": "Confirmed",
            })
        else:
            findings.append({
                "id": "HDR-REF-OK",
                "check_name": "Referrer-Policy Configured",
                "severity": "Informational",
                "evidence": f"Referrer-Policy: {ref_pol}",
                "affected_component": "HTTP Response Headers",
                "current_value": ref_pol,
                "technical_explanation": f"Browser referrer transmission governed by '{ref_pol}'.",
                "potential_impact": "None.",
                "recommended_fix": "Verify that policy meets minimum requirement of strict-origin-when-cross-origin.",
                "verification_steps": "curl -sI https://your-domain.example | grep -i referrer-policy",
                "confidence_level": "Confirmed",
            })

        # 6. Permissions-Policy
        perm_pol = h.get("permissions-policy") or h.get("feature-policy")
        if not perm_pol:
            findings.append({
                "id": "HDR-PERM-MISSING",
                "check_name": "Permissions-Policy Header Missing",
                "severity": "Low",
                "evidence": "Permissions-Policy (Feature-Policy) header not present.",
                "affected_component": "HTTP Response Headers",
                "current_value": None,
                "technical_explanation": (
                    "Permissions-Policy allows site owners to selectively restrict browser hardware features "
                    "(geolocation, microphone, camera, payment, autoplay, USB) for current page and iframes."
                ),
                "potential_impact": "Embedded third-party scripts or frames may attempt to invoke hardware APIs.",
                "recommended_fix": "Specify 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()'.",
                "verification_steps": "curl -sI https://your-domain.example | grep -i permissions-policy",
                "confidence_level": "Confirmed",
            })
        else:
            findings.append({
                "id": "HDR-PERM-OK",
                "check_name": "Permissions-Policy Configured",
                "severity": "Informational",
                "evidence": f"Permissions-Policy: {perm_pol[:60]}...",
                "affected_component": "HTTP Response Headers",
                "current_value": perm_pol,
                "technical_explanation": "Client hardware and browser API delegations are explicitly bounded.",
                "potential_impact": "None.",
                "recommended_fix": "Maintain restricted feature lists as application evolves.",
                "verification_steps": "curl -sI https://your-domain.example | grep -i permissions-policy",
                "confidence_level": "Confirmed",
            })

        # 7. Technology Leakage (Server & X-Powered-By)
        server_val = h.get("server")
        powered_val = h.get("x-powered-by")
        if powered_val:
            findings.append({
                "id": "HDR-POWERED-LEAK",
                "check_name": "Technology Disclosure via X-Powered-By",
                "severity": "Low",
                "evidence": f"X-Powered-By: {powered_val}",
                "affected_component": "HTTP Response Headers",
                "current_value": powered_val,
                "technical_explanation": (
                    f"Server advertises backend technology framework ({powered_val}) to public callers."
                ),
                "potential_impact": "Assists attackers in targeting version-specific known exploits or CVEs.",
                "recommended_fix": "Disable X-Powered-By in web server or application framework settings.",
                "verification_steps": "curl -sI https://your-domain.example | grep -i x-powered-by",
                "confidence_level": "Confirmed",
            })
        if server_val and any(char.isdigit() for char in server_val):
            findings.append({
                "id": "HDR-SERVER-VERSION",
                "check_name": "Server Version Disclosure",
                "severity": "Low",
                "evidence": f"Server: {server_val}",
                "affected_component": "HTTP Response Headers",
                "current_value": server_val,
                "technical_explanation": (
                    f"Server banner discloses detailed product version string ({server_val})."
                ),
                "potential_impact": "Informs reconnaissance scans of precise server software build.",
                "recommended_fix": "Configure server tokens to prod/minimal (e.g. ServerTokens Prod in Apache, server_tokens off in Nginx).",
                "verification_steps": "curl -sI https://your-domain.example | grep -i server",
                "confidence_level": "Confirmed",
            })

        return {
            "findings": findings,
            "raw_headers": dict(headers),
            "checked_url": target_url,
        }
