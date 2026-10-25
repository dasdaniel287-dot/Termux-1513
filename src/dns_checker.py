"""
WebShield AI - DNS and Domain Record Inspector Module
Safely queries A, AAAA, MX, NS, TXT, and CNAME records using dnspython
with graceful fallback to standard library socket lookups.
Evaluates email authentication hygiene (SPF, DMARC) and nameserver presence.
"""

import socket
from typing import Dict, List, Any, Optional

try:
    import dns.resolver
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False

class DNSChecker:
    """Performs defensive DNS record auditing and security hygiene analysis."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def check(self, domain: str) -> Dict[str, Any]:
        """
        Inspects DNS records for domain.
        Returns records dictionary and security hygiene findings.
        """
        findings: List[Dict[str, Any]] = []
        records: Dict[str, List[str]] = {
            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": [],
            "CNAME": [],
            "DMARC": [],
        }

        if DNSPYTHON_AVAILABLE:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout

            for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
                try:
                    answers = resolver.resolve(domain, rtype)
                    for rdata in answers:
                        records[rtype].append(str(rdata).strip('"'))
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                    pass
                except Exception:
                    pass

            # Also check _dmarc.<domain>
            try:
                dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
                for rdata in dmarc_answers:
                    records["DMARC"].append(str(rdata).strip('"'))
            except Exception:
                pass
        else:
            # Fallback to standard library getaddrinfo for A and AAAA
            try:
                for res in socket.getaddrinfo(domain, 80, socket.AF_INET):
                    ip = res[4][0]
                    if ip not in records["A"]:
                        records["A"].append(ip)
            except Exception:
                pass

            try:
                for res in socket.getaddrinfo(domain, 80, socket.AF_INET6):
                    ip = res[4][0]
                    if ip not in records["AAAA"]:
                        records["AAAA"].append(ip)
            except Exception:
                pass

        # Evaluate Findings
        # 1. Domain Resolution Check
        if not records["A"] and not records["AAAA"] and not records["CNAME"]:
            findings.append({
                "id": "DNS-RESOLUTION-FAIL",
                "check_name": "No Address (A/AAAA) Records Found",
                "severity": "High",
                "evidence": f"Zero IP addresses returned for {domain}",
                "affected_component": f"DNS Resolution ({domain})",
                "current_value": "None",
                "technical_explanation": "Domain does not map to any IPv4 (A) or IPv6 (AAAA) addresses in public DNS.",
                "potential_impact": "Users cannot reach the host; complete site unreachability.",
                "recommended_fix": "Add appropriate A or AAAA records in authoritative DNS provider settings.",
                "verification_steps": f"dig +short {domain} A",
                "confidence_level": "Confirmed",
            })
        else:
            findings.append({
                "id": "DNS-RESOLUTION-OK",
                "check_name": "Domain Resolution Functional",
                "severity": "Informational",
                "evidence": f"Resolved A: {', '.join(records['A']) or 'None'} | AAAA: {', '.join(records['AAAA']) or 'None'}",
                "affected_component": f"DNS Resolution ({domain})",
                "current_value": f"{len(records['A'])} IPv4, {len(records['AAAA'])} IPv6",
                "technical_explanation": "Domain resolves properly across public DNS namespaces.",
                "potential_impact": "None. Functional.",
                "recommended_fix": "Maintain DNS records and DNSSEC where available.",
                "verification_steps": f"dig +short {domain} A",
                "confidence_level": "Confirmed",
            })

        # 2. IPv6 Readiness
        if not records["AAAA"]:
            findings.append({
                "id": "DNS-IPV6-ABSENT",
                "check_name": "IPv6 (AAAA) Record Not Configured",
                "severity": "Informational",
                "evidence": "No AAAA record discovered.",
                "affected_component": f"DNS IPv6 Routing ({domain})",
                "current_value": "Absent",
                "technical_explanation": "The domain operates on IPv4 only. Modern dual-stack networks benefit from IPv6.",
                "potential_impact": "Minor routing inefficiency on mobile IPv6-only carrier backbones.",
                "recommended_fix": "Deploy an IPv6 address (AAAA record) if supported by hosting infrastructure.",
                "verification_steps": f"dig +short {domain} AAAA",
                "confidence_level": "High",
            })

        # 3. Email Security: SPF
        has_mx = len(records["MX"]) > 0
        spf_records = [t for t in records["TXT"] if "v=spf1" in t.lower()]

        if has_mx and not spf_records:
            findings.append({
                "id": "DNS-SPF-MISSING",
                "check_name": "Sender Policy Framework (SPF) Record Missing",
                "severity": "Medium",
                "evidence": f"MX records exist ({len(records['MX'])} present) but no TXT SPF record was found.",
                "affected_component": f"DNS TXT / Email Authentication ({domain})",
                "current_value": "None",
                "technical_explanation": (
                    "SPF (RFC 7208) allows domain owners to specify which mail servers are authorized to send "
                    "emails on behalf of their domain."
                ),
                "potential_impact": "Threat actors can easily forge and spoof emails using your domain in phishing campaigns.",
                "recommended_fix": "Add a TXT record with SPF definition, e.g. 'v=spf1 include:_spf.example.com ~all'.",
                "verification_steps": f"dig +short {domain} TXT | grep spf",
                "confidence_level": "High",
            })
        elif spf_records:
            spf_val = spf_records[0]
            if "+all" in spf_val.lower():
                findings.append({
                    "id": "DNS-SPF-PERMISSIVE",
                    "check_name": "SPF Record Contains Permissive '+all' Directive",
                    "severity": "High",
                    "evidence": f"Observed SPF: {spf_val}",
                    "affected_component": f"DNS TXT ({domain})",
                    "current_value": spf_val,
                    "technical_explanation": "The '+all' directive authorizes ANY sender on the internet to send mail for this domain.",
                    "potential_impact": "Neutralizes email sender verification; allows unrestricted email spoofing.",
                    "recommended_fix": "Change '+all' to '-all' (hard fail) or '~all' (soft fail).",
                    "verification_steps": f"dig +short {domain} TXT",
                    "confidence_level": "Confirmed",
                })
            else:
                findings.append({
                    "id": "DNS-SPF-OK",
                    "check_name": "SPF Record Configured",
                    "severity": "Informational",
                    "evidence": f"Observed SPF: {spf_val}",
                    "affected_component": f"DNS TXT ({domain})",
                    "current_value": spf_val,
                    "technical_explanation": "Valid SPF record detected with sender restriction.",
                    "potential_impact": "None. Defensive email posture active.",
                    "recommended_fix": "Periodically review authorized sending IPs in SPF.",
                    "verification_steps": f"dig +short {domain} TXT",
                    "confidence_level": "Confirmed",
                })

        # 4. Email Security: DMARC
        dmarc_records = records["DMARC"] or [t for t in records["TXT"] if "v=dmarc1" in t.lower()]
        if has_mx and not dmarc_records:
            findings.append({
                "id": "DNS-DMARC-MISSING",
                "check_name": "DMARC Record Missing",
                "severity": "Medium",
                "evidence": f"_dmarc.{domain} record not found.",
                "affected_component": f"DNS TXT (_dmarc.{domain})",
                "current_value": "None",
                "technical_explanation": (
                    "DMARC (RFC 7489) enables domain owners to protect their domain from unauthorized use and "
                    "defines how receiving mail systems should treat unauthenticated messages."
                ),
                "potential_impact": "Unmonitored phishing and impersonation using domain name.",
                "recommended_fix": "Publish a DMARC policy at _dmarc.yourdomain.com: 'v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com'.",
                "verification_steps": f"dig +short _dmarc.{domain} TXT",
                "confidence_level": "High",
            })
        elif dmarc_records:
            findings.append({
                "id": "DNS-DMARC-OK",
                "check_name": "DMARC Record Configured",
                "severity": "Informational",
                "evidence": f"Observed DMARC: {dmarc_records[0]}",
                "affected_component": f"DNS TXT (_dmarc.{domain})",
                "current_value": dmarc_records[0],
                "technical_explanation": "DMARC record actively instructs receiving mail servers on enforcement rules.",
                "potential_impact": "None. Defensive anti-spoofing enabled.",
                "recommended_fix": "Progress policy towards p=reject for highest protection.",
                "verification_steps": f"dig +short _dmarc.{domain} TXT",
                "confidence_level": "Confirmed",
            })

        return {
            "records": records,
            "findings": findings,
            "nameservers_count": len(records["NS"]),
        }
