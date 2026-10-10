"""
Zero Trust Continuous Authentication Module — Simulates periodic auth challenges
to confirm principal identity and dynamically enforce session timeouts.
"""

import logging
import random
from typing import Dict, Any, Optional
from defense_engine.zero_trust.trust_scoring import TrustScoringEngine

logger = logging.getLogger(__name__)

class ContinuousAuthentication:
    """
    Implements multi-factor authentication challenges and session validity monitoring.
    """

    def __init__(self, trust_engine: TrustScoringEngine):
        self.trust_engine = trust_engine
        # Tracks active sessions and MFA failure counts
        self.sessions: Dict[str, Dict[str, Any]] = {}

    def start_session(self, session_id: str, principal: str):
        """Registers a new active session."""
        self.sessions[session_id] = {
            "principal": principal,
            "failed_challenges": 0,
            "valid": True
        }
        logger.info(f"Continuous auth session '{session_id}' registered for '{principal}'")

    def trigger_mfa_challenge(self, session_id: str, success_probability: float = 0.95) -> bool:
        """
        Triggers a periodic MFA prompt.
        If challenge fails, session is invalidated and user's trust score decays.
        """
        session = self.sessions.get(session_id)
        if not session or not session["valid"]:
            return False
            
        success = random.random() < success_probability
        if success:
            logger.info(f"MFA challenge succeeded for session '{session_id}'")
            return True
            
        # Handle failure
        session["failed_challenges"] += 1
        principal = session["principal"]
        
        # Penalize trust score
        self.trust_engine.evaluate_activity(principal, "failed_login", severity="WARNING")
        
        if session["failed_challenges"] >= 2:
            session["valid"] = False
            logger.critical(f"Session '{session_id}' terminated: Exceeded maximum MFA challenge failures.")
            
        return False
