"""
Financial Loss Estimator Module — Computes cyber loss metrics,
regulatory penalties, business interruption costs, and remediation expenses.
"""

import logging
from typing import Dict, Any, List
from shared.models import Host
from simulation_engine.network import NetworkTopology

logger = logging.getLogger(__name__)

class FinancialLossEstimator:
    """
    Estimates the financial impact of cyber security incidents in USD.
    """

    def __init__(self):
        # Operational downtime cost per hour per host role
        self.downtime_costs_per_hour = {
            "domain_controller": 5000.0,
            "db_server": 2500.0,
            "web_server": 1000.0,
            "file_server": 500.0,
            "workstation": 100.0
        }
        # Compliance and recovery cost multipliers by data sensitivity
        self.sensitivity_multipliers = {
            "critical": 5.0,
            "high": 3.0,
            "medium": 1.5,
            "low": 1.0
        }

    def estimate_loss(self, topo: NetworkTopology, active_incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Estimates total financial loss based on currently compromised hosts,
        incident severity, and data exposure levels.
        """
        direct_asset_loss = 0.0
        business_interruption_loss = 0.0
        compliance_penalty = 0.0
        
        compromised_hosts = [h for h in topo.hosts.values() if h.compromised]
        
        for host in compromised_hosts:
            # 1. Direct asset loss (cost of replacement / clean install)
            direct_asset_loss += host.asset_value
            
            # 2. Business interruption: downtime cost * hours (assume 4 hours default recovery time)
            base_hourly_cost = self.downtime_costs_per_hour.get(host.role, 100.0)
            business_interruption_loss += base_hourly_cost * 4.0
            
            # 3. Compliance penalty (sensitive data exposure)
            sens = (host.sensitivity_level or "low").lower()
            mult = self.sensitivity_multipliers.get(sens, 1.0)
            compliance_penalty += 500.0 * mult # Baseline $500 per host * sensitivity

        # Add specific incident costs
        incident_response_cost = 0.0
        for inc in active_incidents:
            inc_type = inc.get("type", "generic")
            if inc_type == "ransomware":
                incident_response_cost += 50000.0  # Decryption/crisis negotiation costs
            elif inc_type == "exfiltration":
                incident_response_cost += 100000.0 # Notification and PR costs
            else:
                incident_response_cost += 10000.0

        total_loss = direct_asset_loss + business_interruption_loss + compliance_penalty + incident_response_cost
        
        logger.info(f"Financial Loss computed: total=${total_loss:.2f} USD")
        
        return {
            "total_estimated_loss_usd": round(total_loss, 2),
            "breakdown": {
                "direct_asset_loss": round(direct_asset_loss, 2),
                "business_interruption": round(business_interruption_loss, 2),
                "compliance_penalties": round(compliance_penalty, 2),
                "incident_response_cost": round(incident_response_cost, 2)
            }
        }
