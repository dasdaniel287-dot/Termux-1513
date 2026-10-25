import pytest
from src.scoring import ScoringEngine

def test_perfect_score_when_no_penalties():
    engine = ScoringEngine()
    findings = [
        {"id": "HDR-HSTS-OK", "severity": "Informational", "confidence_level": "Confirmed"},
        {"id": "HDR-CSP-OK", "severity": "Informational", "confidence_level": "Confirmed"},
    ]
    res = engine.compute(findings, scan_status="completed")
    assert res["score"] == 100
    assert res["grade"] == "A+"
    assert res["total_deduction"] == 0

def test_deductions_for_critical_and_high():
    engine = ScoringEngine()
    findings = [
        {"id": "TLS-CERT-EXPIRED", "severity": "Critical", "confidence_level": "Confirmed"}, # -25
        {"id": "HDR-HSTS-MISSING", "severity": "High", "confidence_level": "Confirmed"}, # -15
    ]
    res = engine.compute(findings, scan_status="completed")
    assert res["score"] == 60 # 100 - 40
    # Any critical should cap grade to D
    assert res["grade"] == "D"
    assert res["counts"]["Critical"] == 1
    assert res["counts"]["High"] == 1

def test_incomplete_scan_withholds_score():
    engine = ScoringEngine()
    res = engine.compute([], scan_status="failed")
    assert res["score"] is None
    assert res["grade"] == "Incomplete"
