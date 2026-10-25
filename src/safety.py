"""
WebShield AI - Safety & Scope Controls Module
Enforces strict target authorization, URL validation, anti-SSRF protection,
and rate limiting to prevent unauthorized or hazardous network interactions.
"""

import ipaddress
import socket
import urllib.parse
from typing import Tuple, Optional, List

class SafetyViolation(Exception):
    """Raised when an operation violates authorization or safety rules."""
    pass

class SafetyManager:
    """Manages authorization validation, target bounds, and anti-SSRF protections."""

    def __init__(self, allow_local_testing: bool = False, request_timeout: float = 6.0):
        self.allow_local_testing = allow_local_testing
        self.request_timeout = request_timeout

    def validate_authorization(self, user_confirmed: bool) -> bool:
        """
        Ensures the user has explicitly confirmed authorization before network checks begin.
        """
        if not user_confirmed:
            raise SafetyViolation(
                "Assessment halted: Explicit authorization not confirmed. "
                "WebShield AI requires confirmed ownership or written consent."
            )
        return True

    def parse_and_validate_url(self, raw_url: str) -> Tuple[str, str, int, str]:
        """
        Normalizes and validates target URL.
        Returns: (normalized_url, hostname, port, scheme)
        """
        if not raw_url or not isinstance(raw_url, str):
            raise SafetyViolation("Invalid target: Empty or non-string URL provided.")

        raw_url = raw_url.strip()
        if "://" in raw_url:
            existing_scheme = raw_url.split("://", 1)[0].lower()
            if existing_scheme not in ("http", "https"):
                raise SafetyViolation(f"Unsupported scheme '{existing_scheme}'. Only HTTP and HTTPS are permitted.")
        else:
            # Default to https for security-first scanning
            raw_url = "https://" + raw_url

        try:
            parsed = urllib.parse.urlsplit(raw_url)
        except Exception as e:
            raise SafetyViolation(f"Malformed URL structure: {e}")

        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            raise SafetyViolation(f"Unsupported scheme '{scheme}'. Only HTTP and HTTPS are permitted.")

        hostname = parsed.hostname
        if not hostname:
            raise SafetyViolation("Target URL is missing a valid domain hostname.")

        hostname = hostname.lower().strip()

        # Port validation
        port = parsed.port
        if not port:
            port = 443 if scheme == "https" else 80

        if port not in (80, 443, 8080, 8443, 3000, 5000, 8000) and not self.allow_local_testing:
            raise SafetyViolation(f"Restricted port {port}. Standard web ports (80, 443, 8080, 8443) only.")

        normalized_url = f"{scheme}://{hostname}"
        if (scheme == "https" and port != 443) or (scheme == "http" and port != 80):
            normalized_url += f":{port}"
        if parsed.path and parsed.path != "/":
            normalized_url += parsed.path
        else:
            normalized_url += "/"

        return normalized_url, hostname, port, scheme

    def verify_ssrf_safety(self, hostname: str) -> List[str]:
        """
        Resolves domain to IP addresses and rejects loopback, private,
        link-local, multicast, or reserved ranges unless safe local testing is active.
        """
        resolved_ips: List[str] = []
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            for item in addr_info:
                ip_str = item[4][0]
                if ip_str not in resolved_ips:
                    resolved_ips.append(ip_str)
        except socket.gaierror as e:
            raise SafetyViolation(f"DNS Resolution failed for target '{hostname}': {e}")
        except Exception as e:
            raise SafetyViolation(f"Network error resolving '{hostname}': {e}")

        if not resolved_ips:
            raise SafetyViolation(f"No IP addresses resolved for domain '{hostname}'.")

        for ip_str in resolved_ips:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                raise SafetyViolation(f"Resolved invalid IP address: {ip_str}")

            if not self.allow_local_testing:
                if ip_obj.is_loopback:
                    raise SafetyViolation(
                        f"SSRF Protection triggered: Loopback target ({ip_str}) rejected."
                    )
                if ip_obj.is_private:
                    raise SafetyViolation(
                        f"SSRF Protection triggered: Private RFC 1918/ULA address ({ip_str}) rejected."
                    )
                if ip_obj.is_link_local:
                    raise SafetyViolation(
                        f"SSRF Protection triggered: Link-local address ({ip_str}) rejected."
                    )
                if ip_obj.is_multicast or ip_obj.is_reserved:
                    raise SafetyViolation(
                        f"SSRF Protection triggered: Multicast/Reserved address ({ip_str}) rejected."
                    )
                if ip_str in ("0.0.0.0", "255.255.255.255", "::"):
                    raise SafetyViolation(
                        f"SSRF Protection triggered: Null/Broadcast destination ({ip_str}) rejected."
                    )

        return resolved_ips

    def is_in_scope(self, initial_domain: str, target_url: str) -> bool:
        """
        Validates that redirects or subsequent requests stay strictly within the approved domain.
        """
        try:
            parsed = urllib.parse.urlsplit(target_url)
            dest_host = (parsed.hostname or "").lower()
            initial_host = initial_domain.lower()

            # Exact match or subdomain match
            if dest_host == initial_host:
                return True
            if dest_host.endswith("." + initial_host):
                return True
            # Also allow www <-> apex transitions if legitimate
            if initial_host.startswith("www.") and dest_host == initial_host[4:]:
                return True
            if dest_host.startswith("www.") and dest_host[4:] == initial_host:
                return True
            return False
        except Exception:
            return False
