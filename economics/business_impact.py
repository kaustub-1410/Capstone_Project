"""
Business Impact Analyzer — Models Recovery Time Objectives (RTO),
critical service availability, and business interruption downtime metrics.
"""

import logging
from typing import Dict, Any, List
from shared.models import Host
from simulation_engine.network import NetworkTopology

logger = logging.getLogger(__name__)

class BusinessImpactAnalyzer:
    """
    Evaluates corporate operations availability and recovery speed parameters.
    """

    def __init__(self):
        pass

    def analyze_impact(self, topo: NetworkTopology) -> Dict[str, Any]:
        """
        Analyzes the service disruption state of the network.
        Estimates the Recovery Time Objective (RTO) and overall network availability.
        """
        total_hosts = len(topo.hosts)
        if total_hosts == 0:
            return {"service_availability_percent": 100.0, "rto_hours": 0.0, "status": "OPERATIONAL"}

        compromised_count = sum(1 for h in topo.hosts.values() if h.compromised)
        isolated_count = sum(1 for h in topo.hosts.values() if h.isolated)
        
        # Operational hosts are those that are neither compromised nor isolated
        operational_count = sum(1 for h in topo.hosts.values() if not h.compromised and not h.isolated)
        
        availability = (operational_count / total_hosts) * 100.0
        
        # Estimate RTO (hours) based on the number of hosts requiring remediation
        # (compromised hosts need re-imaging, isolated hosts need verification)
        rto = (compromised_count * 2.0) + (isolated_count * 0.5)
        
        status = "OPERATIONAL"
        if availability < 50.0:
            status = "CRITICAL_OUTAGE"
        elif availability < 90.0:
            status = "DEGRADED"
            
        logger.info(f"Business Impact analyzed: Availability={availability:.1f}% | RTO={rto:.1f} hours")
        
        return {
            "service_availability_percent": round(availability, 1),
            "rto_hours": round(rto, 1),
            "operational_status": status,
            "hosts_down_count": compromised_count + isolated_count
        }
