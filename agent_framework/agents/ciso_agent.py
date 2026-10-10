"""
CISO Agent — Business impact assessment and risk-based decision making.

Calculates business impact of security incidents, approves high-risk
mitigations, estimates downtime, and provides executive-level risk
assessments balancing security posture with operational continuity.

Part of Phase 1: Multi-Agent Society.
"""

import logging
from typing import Any, Dict, List, Optional

from agent_framework.cognitive import CognitiveAgent
from agent_framework.reasoning import (
    DecisionExplanation,
    Evidence,
    EvidenceType,
)
from simulation_engine.core import SimulationEngine
from simulation_engine.network import NetworkTopology

logger = logging.getLogger(__name__)

# Asset value estimates (USD/hour of downtime) by role
ASSET_VALUE_MAP = {
    "domain_controller": 50000.0,
    "db_server": 35000.0,
    "web_server": 20000.0,
    "file_server": 10000.0,
    "workstation": 500.0,
}

# Remediation cost estimates by action type
REMEDIATION_COSTS = {
    "isolate_host": {"cost_usd": 5000, "downtime_hours": 4, "risk": "low"},
    "patch_service": {"cost_usd": 2000, "downtime_hours": 1, "risk": "low"},
    "restore_backup": {"cost_usd": 15000, "downtime_hours": 8, "risk": "medium"},
    "credential_rotation": {"cost_usd": 8000, "downtime_hours": 2, "risk": "medium"},
    "full_rebuild": {"cost_usd": 50000, "downtime_hours": 24, "risk": "high"},
    "network_segmentation": {"cost_usd": 30000, "downtime_hours": 6, "risk": "medium"},
}


class CISOAgent(CognitiveAgent):
    """
    Chief Information Security Officer Agent.

    Responsibilities:
    - Calculate business impact of security incidents
    - Approve or reject high-risk mitigations
    - Estimate downtime and financial exposure
    - Provide executive risk assessments
    - Balance security investment vs. operational continuity
    """

    def __init__(self, agent_id: str = "CISO-01", risk_tolerance: float = 0.3, **kwargs):
        super().__init__(agent_id=agent_id, role="ciso", **kwargs)
        self.risk_tolerance = risk_tolerance  # 0.0 = zero tolerance, 1.0 = very high tolerance
        self.approved_actions: List[Dict[str, Any]] = []
        self.rejected_actions: List[Dict[str, Any]] = []
        self.risk_assessments: List[Dict[str, Any]] = []
        self.total_estimated_loss: float = 0.0
        logger.info(f"CISOAgent {agent_id} initialized (risk_tolerance={risk_tolerance})")

    def reason(
        self, sim: SimulationEngine, topo: NetworkTopology
    ) -> Optional[DecisionExplanation]:
        """Assess business impact of current threat landscape and approve mitigations."""
        self.reasoning_engine.begin_reasoning()

        # Step 1: Calculate current financial exposure
        exposure = self._calculate_exposure(topo)

        self.reasoning_engine.add_step(
            observation=f"Financial exposure assessment: ${exposure['total_hourly_loss']:,.0f}/hour, "
                        f"{exposure['compromised_count']} active compromises",
            hypothesis="Need to evaluate whether current risk exceeds tolerance threshold",
            evidence=[
                Evidence(
                    evidence_type=EvidenceType.HEURISTIC,
                    description=f"Asset at risk: {a['host_id']} ({a['role']}) — "
                                f"${a['hourly_value']:,.0f}/hr",
                    data=a,
                    weight=a["hourly_value"] / 10000.0,
                )
                for a in exposure["at_risk_assets"][:5]
            ],
            confidence=0.90,
        )

        # Step 2: Compute risk score
        risk_score = self._compute_risk_score(exposure, topo)

        self.reasoning_engine.add_step(
            observation=f"Organization risk score: {risk_score:.2f}/10.0 "
                        f"(tolerance threshold: {self.risk_tolerance * 10:.1f})",
            hypothesis="Risk may require executive-level intervention" if risk_score > 5.0 else
                       "Risk is within acceptable bounds",
            confidence=0.85,
        )

        # Step 3: Generate mitigation recommendations
        if risk_score >= 7.0:
            # Critical risk — approve aggressive mitigations
            recommendations = self._generate_critical_recommendations(exposure, topo)
            decision = "approve_aggressive_mitigation"
            reason = (
                f"CRITICAL RISK (score={risk_score:.1f}/10). "
                f"Financial exposure: ${exposure['total_hourly_loss']:,.0f}/hr. "
                f"{exposure['compromised_count']} hosts compromised including "
                f"{exposure['critical_asset_count']} critical assets. "
                f"Approving aggressive containment measures."
            )
        elif risk_score >= 4.0:
            # Elevated risk — approve targeted mitigations
            recommendations = self._generate_elevated_recommendations(exposure, topo)
            decision = "approve_targeted_mitigation"
            reason = (
                f"ELEVATED RISK (score={risk_score:.1f}/10). "
                f"Financial exposure: ${exposure['total_hourly_loss']:,.0f}/hr. "
                f"Approving targeted mitigation for highest-value assets."
            )
        else:
            # Acceptable risk — continue monitoring
            decision = "accept_risk"
            reason = (
                f"ACCEPTABLE RISK (score={risk_score:.1f}/10). "
                f"Financial exposure: ${exposure['total_hourly_loss']:,.0f}/hr. "
                f"Current defensive posture is adequate."
            )
            recommendations = ["Continue standard security monitoring", "Review risk posture in next cycle"]

        # Record assessment
        assessment = {
            "risk_score": risk_score,
            "exposure": exposure,
            "decision": decision,
            "recommendations": recommendations,
        }
        self.risk_assessments.append(assessment)
        self.total_estimated_loss += exposure["total_hourly_loss"]

        return self.reasoning_engine.generate_explanation(
            decision=decision,
            reason=reason,
            affected_assets=[a["host_id"] for a in exposure["at_risk_assets"][:5]],
            recommended_actions=recommendations,
        )

    def explain(self) -> str:
        if self.last_explanation:
            return self.last_explanation.to_summary()
        return "No risk assessment performed yet."

    def approve_mitigation(
        self, action: str, target: str, estimated_cost: float
    ) -> Dict[str, Any]:
        """
        Evaluate and approve/reject a proposed mitigation action.

        Returns a decision dict with approval status, rationale, and conditions.
        """
        remediation_info = REMEDIATION_COSTS.get(action, {
            "cost_usd": estimated_cost, "downtime_hours": 4, "risk": "medium"
        })

        # Approve if cost is justified by risk reduction
        cost_benefit_ratio = estimated_cost / max(
            ASSET_VALUE_MAP.get(target, 5000.0), 1.0
        )

        approved = cost_benefit_ratio < (1.0 + self.risk_tolerance)

        decision = {
            "action": action,
            "target": target,
            "approved": approved,
            "estimated_cost": remediation_info["cost_usd"],
            "estimated_downtime_hours": remediation_info["downtime_hours"],
            "cost_benefit_ratio": round(cost_benefit_ratio, 3),
            "risk_level": remediation_info["risk"],
            "rationale": (
                f"Approved: cost-benefit ratio {cost_benefit_ratio:.2f} is within tolerance"
                if approved
                else f"Rejected: cost-benefit ratio {cost_benefit_ratio:.2f} exceeds tolerance threshold"
            ),
        }

        if approved:
            self.approved_actions.append(decision)
        else:
            self.rejected_actions.append(decision)

        return decision

    # ------------------------------------------------------------------ #
    #  Financial Analysis
    # ------------------------------------------------------------------ #

    def _calculate_exposure(
        self, topo: NetworkTopology
    ) -> Dict[str, Any]:
        """Calculate current financial exposure from active compromises."""
        at_risk = []
        total_loss = 0.0
        critical_count = 0

        for host in topo.hosts.values():
            if host.compromised and not host.isolated:
                hourly_value = ASSET_VALUE_MAP.get(host.role, 500.0)
                total_loss += hourly_value
                if host.role in ("domain_controller", "db_server"):
                    critical_count += 1
                at_risk.append({
                    "host_id": host.id,
                    "role": host.role,
                    "ip": host.ip,
                    "hourly_value": hourly_value,
                    "credentials_dumped": host.credentials_dumped,
                })

        # Sort by value descending
        at_risk.sort(key=lambda a: a["hourly_value"], reverse=True)

        return {
            "total_hourly_loss": total_loss,
            "compromised_count": len(at_risk),
            "critical_asset_count": critical_count,
            "at_risk_assets": at_risk,
            "total_hosts": len(topo.hosts),
            "compromise_percentage": len(at_risk) / max(len(topo.hosts), 1) * 100,
        }

    def _compute_risk_score(
        self, exposure: Dict[str, Any], topo: NetworkTopology
    ) -> float:
        """
        Compute organization-wide risk score (0-10 scale).

        Factors:
        - Compromise percentage
        - Critical asset exposure
        - Credential dump status
        - Financial exposure magnitude
        """
        score = 0.0

        # Factor 1: Compromise percentage (0-3 points)
        score += min(exposure["compromise_percentage"] / 10.0, 3.0)

        # Factor 2: Critical assets at risk (0-3 points)
        score += min(exposure["critical_asset_count"] * 1.5, 3.0)

        # Factor 3: Financial exposure (0-2 points)
        if exposure["total_hourly_loss"] >= 100000:
            score += 2.0
        elif exposure["total_hourly_loss"] >= 50000:
            score += 1.5
        elif exposure["total_hourly_loss"] >= 10000:
            score += 1.0
        elif exposure["total_hourly_loss"] > 0:
            score += 0.5

        # Factor 4: Credential exposure (0-2 points)
        cred_dumps = sum(1 for a in exposure["at_risk_assets"] if a.get("credentials_dumped"))
        score += min(cred_dumps * 0.5, 2.0)

        return min(score, 10.0)

    def _generate_critical_recommendations(
        self, exposure: Dict[str, Any], topo: NetworkTopology
    ) -> List[str]:
        """Generate recommendations for critical risk situations."""
        recs = [
            "IMMEDIATE: Isolate all compromised hosts to prevent further lateral movement",
            "IMMEDIATE: Initiate organization-wide credential rotation",
            "Activate incident response team and engage forensic investigators",
        ]
        for asset in exposure["at_risk_assets"][:3]:
            recs.append(
                f"Priority: Contain {asset['host_id']} ({asset['role']}) — "
                f"${asset['hourly_value']:,.0f}/hr exposure"
            )
        recs.append("Notify legal and compliance teams")
        recs.append(f"Estimated total exposure: ${exposure['total_hourly_loss']:,.0f}/hr")
        return recs

    def _generate_elevated_recommendations(
        self, exposure: Dict[str, Any], topo: NetworkTopology
    ) -> List[str]:
        """Generate recommendations for elevated risk situations."""
        recs = [
            "Isolate compromised critical assets as priority",
            "Increase monitoring on adjacent network segments",
        ]
        for asset in exposure["at_risk_assets"][:2]:
            recs.append(
                f"Patch/isolate {asset['host_id']} ({asset['role']}) — "
                f"${asset['hourly_value']:,.0f}/hr exposure"
            )
        recs.append("Schedule emergency patching window")
        return recs

    def get_executive_summary(self) -> Dict[str, Any]:
        """Generate an executive-level risk summary."""
        return {
            "agent_id": self.agent_id,
            "total_assessments": len(self.risk_assessments),
            "approved_mitigations": len(self.approved_actions),
            "rejected_mitigations": len(self.rejected_actions),
            "total_estimated_loss_usd": round(self.total_estimated_loss, 2),
            "current_risk_tolerance": self.risk_tolerance,
            "last_risk_score": (
                self.risk_assessments[-1]["risk_score"]
                if self.risk_assessments else 0.0
            ),
        }
