"""
WebShield AI - Explainable Security Scoring Engine
Calculates a transparent, deterministic security posture score (0 - 100)
based on findings, severity tiers, and confidence levels with full audit trails.
"""

from typing import List, Dict, Any

class ScoringEngine:
    """Calculates defensible security scores with transparent mathematical breakdowns."""

    BASE_SCORE = 100

    SEVERITY_WEIGHTS = {
        "Critical": 25,
        "High": 15,
        "Medium": 8,
        "Low": 3,
        "Informational": 0,
    }

    CONFIDENCE_MULTIPLIERS = {
        "Confirmed": 1.0,
        "High": 0.85,
        "Medium": 0.65,
        "Low": 0.40,
    }

    def compute(self, findings: List[Dict[str, Any]], scan_status: str = "completed") -> Dict[str, Any]:
        """
        Computes score, breakdown items, grade, and legal disclaimer.
        """
        if scan_status != "completed":
            return {
                "score": None,
                "grade": "Incomplete",
                "status": scan_status,
                "explanation": "Score withheld because the security assessment could not be fully completed.",
                "deductions": [],
                "counts": {
                    "Critical": 0,
                    "High": 0,
                    "Medium": 0,
                    "Low": 0,
                    "Informational": 0,
                },
                "disclaimer": self._disclaimer_text(),
            }

        total_deduction = 0.0
        deductions: List[Dict[str, Any]] = []
        counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Informational": 0,
        }

        for f in findings:
            sev = f.get("severity", "Informational")
            conf = f.get("confidence_level", "Confirmed")
            counts[sev] = counts.get(sev, 0) + 1

            base_deduction = self.SEVERITY_WEIGHTS.get(sev, 0)
            multiplier = self.CONFIDENCE_MULTIPLIERS.get(conf, 1.0)
            applied_deduction = round(base_deduction * multiplier, 1)

            if applied_deduction > 0:
                total_deduction += applied_deduction
                deductions.append({
                    "finding_id": f.get("id"),
                    "check_name": f.get("check_name"),
                    "severity": sev,
                    "confidence": conf,
                    "base_penalty": base_deduction,
                    "multiplier": multiplier,
                    "points_deducted": applied_deduction,
                })

        final_score = max(0, min(100, int(round(self.BASE_SCORE - total_deduction))))
        grade = self._calculate_grade(final_score, counts["Critical"])

        explanation = (
            f"Base Score of 100 with {len(deductions)} risk deductions totaling "
            f"{round(total_deduction, 1)} points applied. "
            f"Findings summary: {counts['Critical']} Critical, {counts['High']} High, "
            f"{counts['Medium']} Medium, {counts['Low']} Low, {counts['Informational']} Informational."
        )

        return {
            "score": final_score,
            "grade": grade,
            "status": "completed",
            "total_deduction": round(total_deduction, 1),
            "deductions": deductions,
            "counts": counts,
            "explanation": explanation,
            "disclaimer": self._disclaimer_text(),
        }

    def _calculate_grade(self, score: int, critical_count: int) -> str:
        # Hard fail if any unaddressed critical vulnerabilities exist
        if critical_count > 0 and score > 65:
            return "D"
        if score >= 95:
            return "A+"
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"

    def _disclaimer_text(self) -> str:
        return (
            "WebShield AI Score Notice: This security score evaluates observable external configurations "
            "(HTTP security headers, TLS parameters, DNS records, safe redirects). A high score reflects "
            "strong baseline defensive hygiene, but does NOT guarantee total immunity against internal application logic, "
            "database flaws, or 0-day exploits. Regular holistic security audits are recommended."
        )
