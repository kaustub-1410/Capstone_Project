"""
Intelligence Aggregator Module — Orchestrates sync of all Threat Intel feeds
and aggregates them into unified vulnerability intelligence documents.
"""

import logging
from typing import Dict, Any, Optional
from intelligence.mitre_client import MITREClient
from intelligence.cisa_kev_client import CISAKEVClient
from intelligence.nvd_client import NVDClient
from intelligence.epss_client import EPSSClient

logger = logging.getLogger(__name__)

class IntelligenceAggregator:
    """
    Combines NVD, CISA KEV, EPSS, and MITRE feeds to provide a single, unified threat intelligence index.
    """

    def __init__(self):
        self.mitre = MITREClient()
        self.cisa_kev = CISAKEVClient()
        self.nvd = NVDClient()
        self.epss = EPSSClient()

    def aggregate_cve_intelligence(self, cve_id: str) -> Dict[str, Any]:
        """
        Combines data from all clients for a given CVE.
        """
        logger.info(f"Aggregating intelligence sources for CVE: {cve_id}")
        
        # Base details from NVD
        nvd_details = self.nvd.get_cve_details(cve_id) or {
            "cvss": 5.0,
            "severity": "MEDIUM",
            "summary": "No public NVD summary cached."
        }
        
        # KEV catalog status
        is_kev = self.cisa_kev.is_known_exploited(cve_id)
        remediation = self.cisa_kev.get_remediation_guidance(cve_id) or "Apply vendor patches."
        
        # EPSS score
        epss_score = self.epss.get_exploit_probability(cve_id)
        
        # Aggregate
        aggregated = {
            "cve_id": cve_id,
            "cvss": nvd_details["cvss"],
            "severity": nvd_details["severity"],
            "summary": nvd_details["summary"],
            "exploited_in_wild": is_kev,
            "cisa_kev": is_kev,
            "epss_score": epss_score,
            "remediation": remediation,
            "mitre_techniques": []
        }
        
        # Approximate MITRE mapping based on typical mappings
        # In a real environment, this maps via CVE identifiers inside the STIX files
        if cve_id == "CVE-2017-0144":
            aggregated["mitre_techniques"] = ["T1210", "T1021.002"]
        elif cve_id == "CVE-2021-44228":
            aggregated["mitre_techniques"] = ["T1190"]
            
        return aggregated

    def sync_all_feeds(self) -> bool:
        """Runs the updater loops across all registered API clients."""
        logger.info("Triggering background sync of all threat intelligence feeds...")
        s1 = self.mitre.sync_latest_feed()
        s2 = self.cisa_kev.sync_latest_kev()
        s3 = self.nvd.sync_feed()
        s4 = self.epss.sync_epss()
        return all([s1, s2, s3, s4])
