import pytest
from src.safety import SafetyManager, SafetyViolation

def test_authorization_required():
    mgr = SafetyManager()
    with pytest.raises(SafetyViolation) as exc:
        mgr.validate_authorization(False)
    assert "Explicit authorization not confirmed" in str(exc.value)

    assert mgr.validate_authorization(True) is True

def test_url_normalization_and_defaults():
    mgr = SafetyManager()
    url, host, port, scheme = mgr.parse_and_validate_url("example.com")
    assert scheme == "https"
    assert host == "example.com"
    assert port == 443
    assert url == "https://example.com/"

    url2, host2, port2, scheme2 = mgr.parse_and_validate_url("http://test.org:8080/path")
    assert scheme2 == "http"
    assert host2 == "test.org"
    assert port2 == 8080
    assert url2 == "http://test.org:8080/path"

def test_unsupported_scheme_rejected():
    mgr = SafetyManager()
    with pytest.raises(SafetyViolation) as exc:
        mgr.parse_and_validate_url("ftp://example.com")
    assert "Unsupported scheme" in str(exc.value)

def test_restricted_ports_rejected():
    mgr = SafetyManager(allow_local_testing=False)
    with pytest.raises(SafetyViolation) as exc:
        mgr.parse_and_validate_url("https://example.com:22")
    assert "Restricted port" in str(exc.value)

def test_ssrf_rejects_loopback_and_private():
    mgr = SafetyManager(allow_local_testing=False)
    # localhost should resolve to 127.0.0.1 or ::1 and be rejected
    with pytest.raises(SafetyViolation) as exc:
        mgr.verify_ssrf_safety("localhost")
    assert "SSRF Protection" in str(exc.value)

def test_scope_enforcement():
    mgr = SafetyManager()
    assert mgr.is_in_scope("example.com", "https://example.com/login") is True
    assert mgr.is_in_scope("example.com", "https://api.example.com/v1") is True
    assert mgr.is_in_scope("example.com", "https://www.example.com") is True
    assert mgr.is_in_scope("example.com", "https://evil-attacker.com") is False
