import os
import json
import tempfile
import pytest
from src.reports import ReportGenerator

def test_report_generation_formats():
    with tempfile.TemporaryDirectory() as tmp_dir:
        gen = ReportGenerator(output_dir=tmp_dir)
        payload = {
            "id": "scan_rep_test",
            "domain": "test.example",
            "target_url": "https://test.example/",
            "timestamp": "2026-10-25 12:00:00",
            "duration_seconds": 1.2,
            "checks_performed": ["Check A", "Check B"],
            "score_data": {
                "score": 85,
                "grade": "B",
                "counts": {"Critical": 0, "High": 1, "Medium": 0, "Low": 0, "Informational": 1},
                "explanation": "Testing report explanation",
                "disclaimer": "Test disclaimer",
            },
            "findings": [
                {
                    "id": "TEST-01",
                    "check_name": "Test Check",
                    "severity": "High",
                    "confidence_level": "Confirmed",
                    "affected_component": "Header",
                    "evidence": "Value X",
                    "technical_explanation": "Details",
                    "potential_impact": "Impact",
                    "recommended_fix": "Fix",
                    "verification_steps": "curl",
                }
            ],
        }

        paths = gen.generate_all(payload)
        assert os.path.exists(paths["json"])
        assert os.path.exists(paths["txt"])
        assert os.path.exists(paths["html"])

        # Check JSON parseable
        with open(paths["json"], "r", encoding="utf-8") as f:
            data = json.load(f)
            assert data["id"] == "scan_rep_test"

        # Check HTML contains essential elements
        with open(paths["html"], "r", encoding="utf-8") as f:
            html = f.read()
            assert "test.example" in html
            assert "TEST-01" in html

        # Check TXT
        with open(paths["txt"], "r", encoding="utf-8") as f:
            txt = f.read()
            assert "WEBSHIELD AI — WEBSITE SECURITY REPORT" in txt
            assert "test.example" in txt
