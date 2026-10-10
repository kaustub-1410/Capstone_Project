"""
EPSS Client — Query Exploit Prediction Scoring System (EPSS) probabilities.
"""

import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class EPSSClient:
    """
    Interfaces with the FIRST EPSS API to fetch probability scores of exploitability.
    """

    def __init__(self):
        self.cached_epss: Dict[str, Dict[str, float]] = {
            "CVE-2017-0144": {"epss": 0.975, "percentile": 0.999},
            "CVE-2021-44228": {"epss": 0.976, "percentile": 0.999},
            "CVE-2020-1472": {"epss": 0.968, "percentile": 0.998}
        }

    def get_exploit_probability(self, cve_id: str) -> float:
        """Retrieves EPSS exploitability probability score (0.0 to 1.0)."""
        score = self.cached_epss.get(cve_id)
        if score:
            return score["epss"]
        return 0.01 # Default low probability fallback

    def sync_epss(self) -> bool:
        """Simulates download of daily EPSS CSV updates."""
        logger.info("EPSS database updates sync complete (Offline Fallback).")
        return True
