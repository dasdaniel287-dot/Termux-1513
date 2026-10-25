"""
WebShield AI - SQLite Database History Module
Stores and manages historical website security assessment runs,
scores, findings snapshots, and generated report links.
"""

import sqlite3
import json
import os
from typing import List, Dict, Any, Optional

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "webshield.db")

class ScanDatabase:
    """Provides SQLite persistence for scan records and historical tracking."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    score INTEGER,
                    grade TEXT,
                    status TEXT NOT NULL,
                    total_findings INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    info_count INTEGER DEFAULT 0,
                    duration_seconds REAL DEFAULT 0.0,
                    report_json_path TEXT,
                    report_html_path TEXT,
                    report_txt_path TEXT,
                    findings_json TEXT,
                    raw_summary_json TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp DESC)")
            conn.commit()

    def save_scan(self, scan_data: Dict[str, Any]) -> str:
        """Inserts a completed or failed assessment run into SQLite."""
        scan_id = scan_data["id"]
        findings = scan_data.get("findings", [])
        counts = scan_data.get("score_data", {}).get("counts", {})

        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO scans (
                    id, timestamp, target_url, domain, score, grade, status,
                    total_findings, critical_count, high_count, medium_count, low_count, info_count,
                    duration_seconds, report_json_path, report_html_path, report_txt_path,
                    findings_json, raw_summary_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                scan_data.get("timestamp", ""),
                scan_data.get("target_url", ""),
                scan_data.get("domain", ""),
                scan_data.get("score_data", {}).get("score"),
                scan_data.get("score_data", {}).get("grade", "N/A"),
                scan_data.get("status", "completed"),
                len(findings),
                counts.get("Critical", 0),
                counts.get("High", 0),
                counts.get("Medium", 0),
                counts.get("Low", 0),
                counts.get("Informational", 0),
                scan_data.get("duration_seconds", 0.0),
                scan_data.get("report_paths", {}).get("json"),
                scan_data.get("report_paths", {}).get("html"),
                scan_data.get("report_paths", {}).get("txt"),
                json.dumps(findings),
                json.dumps(scan_data.get("summary", {})),
            ))
            conn.commit()
        return scan_id

    def get_all_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves list of past scans sorted by most recent first."""
        with self._get_connection() as conn:
            cur = conn.execute("""
                SELECT id, timestamp, target_url, domain, score, grade, status,
                       total_findings, critical_count, high_count, medium_count, low_count, info_count,
                       duration_seconds, report_json_path, report_html_path, report_txt_path
                FROM scans
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            rows = cur.fetchall()
            return [dict(r) for r in rows]

    def get_scan_by_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves complete details of a single scan including stored findings."""
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
            row = cur.fetchone()
            if not row:
                return None
            res = dict(row)
            # Try to load full JSON report if available on disk
            json_path = res.get("report_json_path")
            if json_path and os.path.exists(json_path):
                try:
                    with open(json_path, "r", encoding="utf-8") as f:
                        full_payload = json.load(f)
                        return full_payload
                except Exception:
                    pass

            if res.get("findings_json"):
                try:
                    res["findings"] = json.loads(res["findings_json"])
                except Exception:
                    res["findings"] = []
            else:
                res["findings"] = []

            if res.get("raw_summary_json"):
                try:
                    res["summary"] = json.loads(res["raw_summary_json"])
                except Exception:
                    res["summary"] = {}

            # Guarantee score_data structure
            res["score_data"] = {
                "score": res.get("score", 0),
                "grade": res.get("grade", "N/A"),
                "status": res.get("status", "completed"),
                "total_deduction": 0,
                "explanation": f"Security score of {res.get('score', 0)}/100 (Grade {res.get('grade', 'N/A')}).",
                "counts": {
                    "Critical": res.get("critical_count", 0),
                    "High": res.get("high_count", 0),
                    "Medium": res.get("medium_count", 0),
                    "Low": res.get("low_count", 0),
                    "Informational": res.get("info_count", 0),
                },
                "disclaimer": (
                    "WebShield AI Score Notice: This security score evaluates observable external configurations "
                    "(HTTP security headers, TLS parameters, DNS records, safe redirects)."
                ),
            }
            if "resolved_ips" not in res:
                res["resolved_ips"] = []
            if "checks_performed" not in res:
                res["checks_performed"] = [
                    "HTTP Security Headers Analysis",
                    "TLS/SSL Certificate Verification",
                    "DNS Record & Anti-Spoofing Audit",
                    "Safe Configuration Checks"
                ]
            if "scheme" not in res:
                res["scheme"] = "https" if res.get("target_url", "").startswith("https") else "http"
            if "port" not in res:
                res["port"] = 443 if res.get("scheme") == "https" else 80

            return res

    def delete_scan(self, scan_id: str) -> bool:
        """Deletes a scan entry by ID."""
        with self._get_connection() as conn:
            cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.commit()
            return cur.rowcount > 0

    def clear_history(self) -> int:
        """Clears all scan history."""
        with self._get_connection() as conn:
            cur = conn.execute("DELETE FROM scans")
            conn.commit()
            return cur.rowcount
