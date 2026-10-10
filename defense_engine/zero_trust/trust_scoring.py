"""
Zero Trust Trust Scoring Module — Calculates dynamic context-aware trust scores
for users and hosts based on telemetry and anomaly indicators.
"""

import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class TrustScoringEngine:
    """
    Computes and maintains real-time trust scores (0 to 100) for network subjects.
    Scores decay based on malicious action detections, failed logins, and anomalies.
    """

    def __init__(self, default_score: float = 100.0):
        self.default_score = default_score
        # Map: subject_id -> score
        self.scores: Dict[str, float] = {}

    def get_trust_score(self, subject_id: str) -> float:
        """Retrieves current trust score for a host or user."""
        if subject_id not in self.scores:
            self.scores[subject_id] = self.default_score
        return self.scores[subject_id]

    def evaluate_activity(self, subject_id: str, activity_type: str, severity: str = "INFO") -> float:
        """
        Processes telemetry event details and adjusts the trust score dynamically.
        Uses the maximum penalty of either the activity classification or the log severity level.
        """
        current = self.get_trust_score(subject_id)
        
        # 1. Determine activity type base deduction
        type_deduction = 0.0
        if activity_type == "failed_login":
            type_deduction = 10.0
        elif activity_type == "out_of_hours_access":
            type_deduction = 20.0
        elif activity_type == "malicious_process":
            type_deduction = 50.0
        elif activity_type == "data_exfiltration":
            type_deduction = 80.0
            
        # 2. Determine severity level baseline deduction
        sev_deduction = 0.0
        if severity == "WARNING":
            sev_deduction = 20.0
        elif severity == "CRITICAL":
            sev_deduction = 50.0
            
        # 3. Take the maximum deduction
        deduction = max(type_deduction, sev_deduction)
            
        new_score = max(0.0, current - deduction)
        self.scores[subject_id] = new_score
        
        logger.warning(
            f"Trust Score evaluated for '{subject_id}': decreased from {current} to {new_score} "
            f"due to activity: {activity_type} ({severity})"
        )
        return new_score

    def reset_score(self, subject_id: str):
        """Resets the trust score to default."""
        self.scores[subject_id] = self.default_score
        logger.info(f"Trust score reset for subject '{subject_id}'")
