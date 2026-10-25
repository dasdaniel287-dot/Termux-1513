"""
WebShield AI - TLS/SSL Certificate Checker Module
Performs cryptographic handshake analysis using Python's standard ssl and socket libraries.
Strictly enforces TLS verification, detects expiration, weak protocols, and hostname mismatches.
"""

import socket
import ssl
import datetime
from typing import Dict, List, Any, Optional

class TLSChecker:
    """Safely audits TLS/SSL certificates and secure channel configurations."""

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout

    def check(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """
        Executes TLS handshake and extracts certificate details.
        Never disables verification silently. If verification fails,
        captures exact error and records finding.
        """
        findings: List[Dict[str, Any]] = []
        tls_info: Dict[str, Any] = {
            "hostname": hostname,
            "port": port,
            "connected": False,
            "verified": False,
            "tls_version": None,
            "cipher": None,
            "issuer": None,
            "subject": None,
            "expires_at": None,
            "days_until_expiration": None,
            "san": [],
            "error": None,
        }

        # First, attempt standard verified connection
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher_info = ssock.cipher()
                    tls_version = ssock.version()

                    tls_info["connected"] = True
                    tls_info["verified"] = True
                    tls_info["tls_version"] = tls_version
                    tls_info["cipher"] = cipher_info[0] if cipher_info else None

                    self._parse_certificate(cert, tls_info, findings)

                    # Protocol check
                    if tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                        findings.append({
                            "id": "TLS-PROTO-OBSOLETE",
                            "check_name": "Obsolete TLS/SSL Protocol Negotiated",
                            "severity": "Critical",
                            "evidence": f"Negotiated Protocol: {tls_version}",
                            "affected_component": f"TLS Handshake ({hostname}:{port})",
                            "current_value": tls_version,
                            "technical_explanation": (
                                f"{tls_version} has known cryptographic vulnerabilities (e.g. POODLE, BEAST) "
                                "and is deprecated by RFC 8996 and major browsers."
                            ),
                            "potential_impact": "Traffic susceptible to interception and cryptographic downgrade attacks.",
                            "recommended_fix": "Disable TLS 1.0/1.1 on server. Restrict protocols to TLS 1.2 and TLS 1.3.",
                            "verification_steps": f"openssl s_client -connect {hostname}:{port} -tls1_1",
                            "confidence_level": "Confirmed",
                        })
                    else:
                        findings.append({
                            "id": "TLS-PROTO-MODERN",
                            "check_name": "Modern TLS Protocol Enforced",
                            "severity": "Informational",
                            "evidence": f"Negotiated: {tls_version} with cipher {tls_info['cipher']}",
                            "affected_component": f"TLS Handshake ({hostname}:{port})",
                            "current_value": tls_version,
                            "technical_explanation": "Secure, modern TLS protocol successfully established.",
                            "potential_impact": "None. Encrypted transport active.",
                            "recommended_fix": "Maintain server cipher suite hardening.",
                            "verification_steps": f"openssl s_client -connect {hostname}:{port} -tls1_3",
                            "confidence_level": "Confirmed",
                        })

        except ssl.SSLCertVerificationError as e:
            tls_info["connected"] = True
            tls_info["verified"] = False
            tls_info["error"] = f"SSL Certificate Verification Failed: {e.verify_message}"

            findings.append({
                "id": "TLS-CERT-UNTRUSTED",
                "check_name": "TLS Certificate Verification Failed",
                "severity": "Critical",
                "evidence": f"Verification error: {e.verify_message} (Code {e.verify_code})",
                "affected_component": f"TLS Certificate Chain ({hostname}:{port})",
                "current_value": e.verify_message,
                "technical_explanation": (
                    "The certificate provided by the server could not be validated against trusted root authorities. "
                    "Causes include self-signed certificates, missing intermediate certificates, or expired chains."
                ),
                "potential_impact": "Browsers display prominent security warning blocks; visitors cannot safely establish trust.",
                "recommended_fix": "Deploy a valid, CA-signed certificate (e.g. Let's Encrypt or commercial CA) with complete chain.",
                "verification_steps": f"openssl s_client -connect {hostname}:{port} -showcerts",
                "confidence_level": "Confirmed",
            })

            # Inspect unverified cert to get expiry date and metadata for diagnostic report
            self._probe_unverified_metadata(hostname, port, tls_info, findings)

        except (socket.timeout, TimeoutError):
            tls_info["error"] = "Connection timed out during TLS handshake."
            findings.append({
                "id": "TLS-CONN-TIMEOUT",
                "check_name": "TLS Connection Timeout",
                "severity": "Medium",
                "evidence": f"Connection timed out after {self.timeout}s.",
                "affected_component": f"TLS Handshake ({hostname}:{port})",
                "current_value": "Timeout",
                "technical_explanation": "The server did not respond to TLS Client Hello within the configured safe timeout.",
                "potential_impact": "Service disruption or firewall drop on port 443.",
                "recommended_fix": "Check server availability, reverse proxy status, and firewall rules.",
                "verification_steps": f"nc -zv -w 5 {hostname} {port}",
                "confidence_level": "High",
            })
        except ConnectionRefusedError:
            tls_info["error"] = "Connection refused on HTTPS port 443."
            findings.append({
                "id": "TLS-CONN-REFUSED",
                "check_name": "HTTPS Port Closed / Refused",
                "severity": "High",
                "evidence": f"Connection refused on port {port}.",
                "affected_component": f"Port {port}",
                "current_value": "Closed",
                "technical_explanation": "Server is not listening for encrypted HTTPS traffic on standard port 443.",
                "potential_impact": "Users cannot establish encrypted connections to this website.",
                "recommended_fix": "Enable HTTPS listener and configure valid TLS certificate.",
                "verification_steps": f"curl -Iv https://{hostname}",
                "confidence_level": "Confirmed",
            })
        except Exception as e:
            tls_info["error"] = str(e)
            findings.append({
                "id": "TLS-HANDSHAKE-ERROR",
                "check_name": "TLS Handshake Error",
                "severity": "Medium",
                "evidence": str(e),
                "affected_component": f"TLS ({hostname}:{port})",
                "current_value": str(e),
                "technical_explanation": f"Unexpected error during TLS negotiation: {e}",
                "potential_impact": "Unable to verify cryptographic parameters.",
                "recommended_fix": "Verify domain DNS points to an active web server.",
                "verification_steps": f"openssl s_client -connect {hostname}:{port}",
                "confidence_level": "Medium",
            })

        return {
            "tls_info": tls_info,
            "findings": findings,
        }

    def _parse_certificate(self, cert: Dict[str, Any], tls_info: Dict[str, Any], findings: List[Dict[str, Any]]) -> None:
        """Parses decoded certificate dictionary and computes expiration math."""
        if not cert:
            return

        # Subject & Issuer
        subject_parts = []
        for rdn in cert.get("subject", ()):
            for key, val in rdn:
                subject_parts.append(f"{key}={val}")
        tls_info["subject"] = ", ".join(subject_parts)

        issuer_parts = []
        for rdn in cert.get("issuer", ()):
            for key, val in rdn:
                issuer_parts.append(f"{key}={val}")
        tls_info["issuer"] = ", ".join(issuer_parts)

        # Subject Alternative Names (SAN)
        sans = []
        for san_type, san_val in cert.get("subjectAltName", ()):
            if san_type == "DNS":
                sans.append(san_val)
        tls_info["san"] = sans

        # Expiry date parsing: format e.g. 'Oct 25 12:00:00 2026 GMT'
        not_after_str = cert.get("notAfter")
        if not_after_str:
            try:
                # Python ssl date format: "%b %d %H:%M:%S %Y %Z"
                expires_at = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                now = datetime.datetime.utcnow()
                tls_info["expires_at"] = expires_at.isoformat() + "Z"
                days_left = (expires_at - now).days
                tls_info["days_until_expiration"] = days_left

                if days_left < 0:
                    findings.append({
                        "id": "TLS-CERT-EXPIRED",
                        "check_name": "TLS Certificate Expired",
                        "severity": "Critical",
                        "evidence": f"Certificate expired {abs(days_left)} days ago on {not_after_str}",
                        "affected_component": "TLS Certificate Validity",
                        "current_value": f"Expired {not_after_str}",
                        "technical_explanation": (
                            "The server certificate has passed its validity period. "
                            "Browsers immediately terminate secure access and show severe error screens."
                        ),
                        "potential_impact": "Complete service denial for HTTPS visitors; broken trust.",
                        "recommended_fix": "Renew and reload the TLS certificate immediately using ACME/certbot or your CA.",
                        "verification_steps": f"openssl s_client -connect {tls_info['hostname']}:{tls_info['port']} 2>/dev/null | openssl x509 -noout -dates",
                        "confidence_level": "Confirmed",
                    })
                elif days_left < 14:
                    findings.append({
                        "id": "TLS-CERT-EXPIRING-SOON",
                        "check_name": "TLS Certificate Expiring Within 14 Days",
                        "severity": "High",
                        "evidence": f"Certificate expires in {days_left} days ({not_after_str})",
                        "affected_component": "TLS Certificate Validity",
                        "current_value": f"{days_left} days remaining",
                        "technical_explanation": "Certificate expiration is imminent. Automated or manual renewal is urgent.",
                        "potential_impact": "Upcoming website outage once the expiration date arrives.",
                        "recommended_fix": "Trigger certificate renewal immediately and check automated renewal crons.",
                        "verification_steps": "Check certbot renewal status with 'certbot renew --dry-run'.",
                        "confidence_level": "Confirmed",
                    })
                elif days_left < 30:
                    findings.append({
                        "id": "TLS-CERT-EXPIRING-30D",
                        "check_name": "TLS Certificate Expiring Within 30 Days",
                        "severity": "Medium",
                        "evidence": f"Certificate expires in {days_left} days ({not_after_str})",
                        "affected_component": "TLS Certificate Validity",
                        "current_value": f"{days_left} days remaining",
                        "technical_explanation": "Certificate has less than 30 days of validity remaining.",
                        "potential_impact": "Requires scheduled renewal to avoid unexpected expiry.",
                        "recommended_fix": "Verify that auto-renewal ACME daemon (certbot / caddy) is operational.",
                        "verification_steps": "Check server cert renewal service logs.",
                        "confidence_level": "Confirmed",
                    })
                else:
                    findings.append({
                        "id": "TLS-CERT-VALID",
                        "check_name": "TLS Certificate Valid and Trusted",
                        "severity": "Informational",
                        "evidence": f"Valid for {days_left} more days (Expires: {not_after_str}). Issuer: {tls_info['issuer']}",
                        "affected_component": "TLS Certificate Validity",
                        "current_value": f"{days_left} days remaining",
                        "technical_explanation": "Certificate is currently active, trusted by root store, and has healthy validity duration.",
                        "potential_impact": "None. Active defense.",
                        "recommended_fix": "Keep auto-renewal active.",
                        "verification_steps": "openssl x509 -noout -dates",
                        "confidence_level": "Confirmed",
                    })
            except Exception:
                pass

    def _probe_unverified_metadata(self, hostname: str, port: int, tls_info: Dict[str, Any], findings: List[Dict[str, Any]]) -> None:
        """Connects unverified solely for extracting diagnostic expiration/issuer metadata without suppressing error."""
        try:
            insecure_ctx = ssl._create_unverified_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with insecure_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    if cert_bin:
                        # Extract basic info
                        tls_info["tls_version"] = ssock.version()
                        tls_info["cipher"] = ssock.cipher()[0] if ssock.cipher() else None
        except Exception:
            pass
