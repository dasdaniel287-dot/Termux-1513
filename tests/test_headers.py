import pytest
from src.headers import HeaderAnalyzer

def test_missing_all_security_headers():
    analyzer = HeaderAnalyzer()
    res = analyzer.analyze({}, "https://insecure.test", is_https=True)
    findings = res["findings"]
    ids = [f["id"] for f in findings]
    assert "HDR-HSTS-MISSING" in ids
    assert "HDR-CSP-MISSING" in ids
    assert "HDR-XCTO-MISSING" in ids
    assert "HDR-XFO-MISSING" in ids
    assert "HDR-REF-MISSING" in ids
    assert "HDR-PERM-MISSING" in ids

def test_well_hardened_headers():
    analyzer = HeaderAnalyzer()
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    }
    res = analyzer.analyze(headers, "https://hardened.test", is_https=True)
    findings = res["findings"]
    # All should be informational
    severities = {f["severity"] for f in findings}
    assert severities == {"Informational"}

def test_weak_csp_and_banner_leakage():
    analyzer = HeaderAnalyzer()
    headers = {
        "Content-Security-Policy": "default-src *; script-src 'unsafe-inline' 'unsafe-eval'",
        "X-Powered-By": "PHP/8.1.2",
        "Server": "Apache/2.4.52 (Ubuntu)",
    }
    res = analyzer.analyze(headers, "https://leaky.test", is_https=True)
    findings = res["findings"]
    ids = [f["id"] for f in findings]
    assert "HDR-CSP-WEAK" in ids
    assert "HDR-POWERED-LEAK" in ids
    assert "HDR-SERVER-VERSION" in ids
