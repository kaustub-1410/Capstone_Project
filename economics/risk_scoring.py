"""
Risk Scoring Module — Computes global enterprise-wide cyber risk ratings.
"""

import logging
from simulation_engine.network import NetworkTopology

logger = logging.getLogger(__name__)

class RiskScoringEngine:
    """
    Evaluates topological risk exposure, threat propagation speed, and overall compliance gaps.
    """

    def __init__(self):
        pass

    def calculate_enterprise_risk(self, topo: NetworkTopology) -> float:
        """
        Computes a composite security risk index from 0.0 (safest) to 100.0 (highest threat).
        Factors:
        - Ratio of compromised hosts
        - Ratio of un-isolated compromised hosts
        - Total vulnerabilities density
        - Critical assets compromise (e.g. Domain Controller status)
        """
        num_hosts = len(topo.hosts)
        if num_hosts == 0:
            return 0.0

        compromised_count = sum(1 for h in topo.hosts.values() if h.compromised)
        active_compromises = sum(1 for h in topo.hosts.values() if h.compromised and not h.isolated)
        total_vulns = sum(len(s.vulnerabilities) for h in topo.hosts.values() for s in h.services)
        
        # 1. Compromise ratio factor (up to 40 points)
        comp_factor = (compromised_count / num_hosts) * 40.0
        
        # 2. Containment factor (up to 30 points)
        active_factor = (active_compromises / num_hosts) * 30.0
        
        # 3. Vulnerability density factor (up to 15 points)
        vuln_density = total_vulns / num_hosts
        vuln_factor = min(15.0, vuln_density * 5.0)
        
        # 4. Critical assets impact (up to 15 points)
        critical_compromised = False
        for host in topo.hosts.values():
            if host.sensitivity_level == "critical" and host.compromised:
                critical_compromised = True
                break
                
        crit_factor = 15.0 if critical_compromised else 0.0
        
        risk_score = comp_factor + active_factor + vuln_factor + crit_factor
        risk_score = min(100.0, max(0.0, round(risk_score, 1)))
        
        logger.info(f"Enterprise Risk Score calculated: {risk_score}/100")
        return risk_score
