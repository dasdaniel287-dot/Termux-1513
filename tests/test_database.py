import os
import tempfile
import pytest
from src.database import ScanDatabase

def test_database_crud_operations():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    try:
        db = ScanDatabase(db_path=db_path)
        scan_id = "test_scan_001"
        data = {
            "id": scan_id,
            "timestamp": "2026-10-25 12:00:00",
            "target_url": "https://test.example.com/",
            "domain": "test.example.com",
            "status": "completed",
            "score_data": {
                "score": 92,
                "grade": "A",
                "counts": {"Critical": 0, "High": 0, "Medium": 1, "Low": 0, "Informational": 2},
            },
            "findings": [
                {"id": "HDR-XCTO-MISSING", "severity": "Medium", "check_name": "X-Content-Type-Options Missing"}
            ],
            "duration_seconds": 1.45,
            "report_paths": {"json": "/path/test.json", "html": "/path/test.html", "txt": "/path/test.txt"},
            "summary": {"test": "val"},
        }

        # 1. Save
        saved_id = db.save_scan(data)
        assert saved_id == scan_id

        # 2. Get list
        all_scans = db.get_all_scans()
        assert len(all_scans) == 1
        assert all_scans[0]["domain"] == "test.example.com"
        assert all_scans[0]["score"] == 92

        # 3. Get single
        scan = db.get_scan_by_id(scan_id)
        assert scan is not None
        assert scan["id"] == scan_id
        assert len(scan["findings"]) == 1
        assert scan["findings"][0]["id"] == "HDR-XCTO-MISSING"

        # 4. Delete
        deleted = db.delete_scan(scan_id)
        assert deleted is True
        assert db.get_scan_by_id(scan_id) is None
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)
