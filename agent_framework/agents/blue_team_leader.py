"""
Blue Team Leader — Defensive coordination and mitigation strategy selection.

Coordinates defender agents, assigns defensive tasks based on threat analysis,
and selects optimal mitigation strategies using attack graph intelligence
and resource-aware decision-making.

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


class BlueTeamLeader(CognitiveAgent):
    """
    Blue Team Leader — coordinates defensive operations.

    Responsibilities:
    - Coordinate multiple defender agents
    - Assign defensive tasks to appropriate responders
    - Choose best mitigation strategy per threat context
    - Balance security posture vs. business continuity
    - Track defensive resource allocation
    """

    def __init__(self, agent_id: str = "BlueTeam-Lead-01", **kwargs):
        super().__init__(agent_id=agent_id, role="blue_team_leader", **kwargs)
        self.task_assignments: List[Dict[str, Any]] = []
        self.mitigation_history: List[Dict[str, Any]] = []
        self.active_incidents: List[Dict[str, Any]] = []
        self.defensive_posture: str = "normal"  # normal, elevated, critical
        logger.info(f"BlueTeamLeader {agent_id} initialized")

    def reason(
        self, sim: SimulationEngine, topo: NetworkTopology
    ) -> Optional[DecisionExplanation]:
        """Assess the threat landscape and coordinate defensive response."""
        self.reasoning_engine.begin_reasoning()

        # Step 1: Assess current threat level
        compromised_hosts = [h for h in topo.hosts.values() if h.compromised and not h.isolated]
        isolated_hosts = [h for h in topo.hosts.values() if h.isolated]
        total_hosts = len(topo.hosts)

        compromise_rate = len(compromised_hosts) / max(total_hosts, 1)

        if compromise_rate >= 0.3:
            self.defensive_posture = "critical"
        elif compromise_rate >= 0.1:
            self.defensive_posture = "elevated"
        else:
            self.defensive_posture = "normal"

        self.reasoning_engine.add_step(
            observation=f"Threat assessment: {len(compromised_hosts)} active compromises, "
                        f"{len(isolated_hosts)} isolated, posture={self.defensive_posture}",
            hypothesis=f"Defensive posture should be {self.defensive_posture}",
            confidence=0.90,
        )

        if not compromised_hosts:
            # No active threats — focus on preventive measures
            vuln_hosts = self._get_vulnerable_hosts(topo)
            if vuln_hosts:
                top_vuln = vuln_hosts[0]
                return self.reasoning_engine.generate_explanation(
                    decision="patch_service",
                    reason=f"No active threats. Preventive patching recommended for "
                           f"{top_vuln['host_id']} ({top_vuln['vuln_count']} vulnerabilities)",
                    affected_assets=[v["host_id"] for v in vuln_hosts[:3]],
                    recommended_actions=[
                        f"Patch {top_vuln['host_id']}: {top_vuln['vuln_count']} known vulnerabilities",
                        "Conduct vulnerability scanning on remaining assets",
                    ],
                )
            return self.reasoning_engine.generate_explanation(
                decision="no_action",
                reason="No active threats and no unpatched vulnerabilities detected",
                affected_assets=[],
                recommended_actions=["Maintain monitoring posture"],
            )

        # Step 2: Prioritize compromised hosts for response
        prioritized = self._prioritize_response(compromised_hosts, topo)

        self.reasoning_engine.add_step(
            observation=f"Prioritized {len(prioritized)} hosts for defensive response",
            evidence=[
                Evidence(
                    evidence_type=EvidenceType.GRAPH_STRUCTURE,
                    description=f"{p['host_id']} ({p['host_role']}) — priority={p['priority']:.2f}",
                    data=p,
                    weight=p["priority"],
                )
                for p in prioritized[:5]
            ],
            confidence=0.85,
        )

        # Step 3: Select mitigation strategy for top priority
        top_target = prioritized[0]
        strategy = self._select_mitigation_strategy(top_target, topo)

        self.reasoning_engine.add_step(
            observation=f"Selected strategy '{strategy['action']}' for {top_target['host_id']}",
            hypothesis=f"Strategy '{strategy['action']}' minimizes blast radius while preserving operations",
            confidence=strategy.get("confidence", 0.80),
            conclusion=f"Execute {strategy['action']} on {top_target['host_id']}",
        )

        # Record task assignment
        assignment = {
            "target": top_target["host_id"],
            "action": strategy["action"],
            "priority": top_target["priority"],
            "posture": self.defensive_posture,
            "strategy": strategy,
        }
        self.task_assignments.append(assignment)
        self.active_incidents.append(assignment)

        return self.reasoning_engine.generate_explanation(
            decision=strategy["action"],
            reason=strategy["reason"],
            affected_assets=[p["host_id"] for p in prioritized[:5]],
            recommended_actions=strategy.get("follow_up", []),
        )

    def explain(self) -> str:
        if self.last_explanation:
            return self.last_explanation.to_summary()
        return "No defensive coordination performed yet."

    # ------------------------------------------------------------------ #
    #  Strategy Methods
    # ------------------------------------------------------------------ #

    def _prioritize_response(
        self, compromised_hosts: list, topo: NetworkTopology
    ) -> List[Dict[str, Any]]:
        """Prioritize compromised hosts based on role criticality and blast radius."""
        role_priority = {
            "domain_controller": 10.0,
            "db_server": 8.0,
            "web_server": 6.0,
            "file_server": 5.0,
            "workstation": 2.0,
        }

        prioritized = []
        for host in compromised_hosts:
            # Count connections (blast radius proxy)
            connection_count = sum(
                1 for h1, h2 in topo.connections
                if h1 == host.id or h2 == host.id
            )

            # Count adjacent uncompromised hosts at risk
            at_risk_neighbors = 0
            for h1, h2 in topo.connections:
                neighbor_id = h2 if h1 == host.id else h1 if h2 == host.id else None
                if neighbor_id:
                    neighbor = topo.hosts.get(neighbor_id)
                    if neighbor and not neighbor.compromised and not neighbor.isolated:
                        at_risk_neighbors += 1

            priority = (
                role_priority.get(host.role, 2.0)
                + connection_count * 0.5
                + at_risk_neighbors * 1.0
            )

            prioritized.append({
                "host_id": host.id,
                "host_role": host.role,
                "host_ip": host.ip,
                "priority": priority,
                "connections": connection_count,
                "at_risk_neighbors": at_risk_neighbors,
                "credentials_dumped": host.credentials_dumped,
            })

        prioritized.sort(key=lambda p: p["priority"], reverse=True)
        return prioritized

    def _select_mitigation_strategy(
        self, target: Dict[str, Any], topo: NetworkTopology
    ) -> Dict[str, Any]:
        """Select optimal mitigation strategy based on threat context and posture."""
        host_id = target["host_id"]
        host = topo.hosts.get(host_id)

        if self.defensive_posture == "critical":
            # Aggressive containment
            return {
                "action": "isolate_host",
                "reason": f"CRITICAL posture: Immediately isolating {host_id} "
                          f"({target['host_role']}) to contain lateral movement. "
                          f"{target['at_risk_neighbors']} uncompromised neighbors at risk.",
                "confidence": 0.92,
                "follow_up": [
                    "Scan all connected hosts for indicators of compromise",
                    "Initiate credential rotation for affected domain",
                    "Block associated network segments at firewall",
                ],
            }

        if target["credentials_dumped"]:
            # Credential compromise requires isolation + credential rotation
            return {
                "action": "isolate_host",
                "reason": f"Credentials dumped on {host_id}: isolating to prevent "
                          f"Pass-the-Hash and lateral movement attacks",
                "confidence": 0.88,
                "follow_up": [
                    "Rotate all credentials associated with this host",
                    "Audit authentication logs for credential reuse",
                    f"Check {target['at_risk_neighbors']} adjacent hosts",
                ],
            }

        if target["at_risk_neighbors"] >= 3:
            # High blast radius — isolate
            return {
                "action": "isolate_host",
                "reason": f"Host {host_id} has {target['at_risk_neighbors']} "
                          f"uncompromised neighbors at risk. Isolating to prevent spread.",
                "confidence": 0.85,
                "follow_up": [
                    "Patch vulnerable services on adjacent hosts",
                    "Assess whether backup restoration is needed",
                ],
            }

        # Lower-risk scenario: block port or patch
        if host and host.services:
            vuln_services = [s for s in host.services if s.vulnerabilities]
            if vuln_services:
                return {
                    "action": "patch_service",
                    "reason": f"Patching vulnerable services on {host_id} "
                              f"({len(vuln_services)} services with known CVEs)",
                    "confidence": 0.75,
                    "follow_up": [
                        "Monitor host for continued compromise indicators",
                        "Consider isolation if patching doesn't contain threat",
                    ],
                }

        # Default: isolate
        return {
            "action": "isolate_host",
            "reason": f"Default containment for compromised host {host_id}",
            "confidence": 0.70,
            "follow_up": ["Investigate root cause", "Plan remediation"],
        }

    def _get_vulnerable_hosts(
        self, topo: NetworkTopology
    ) -> List[Dict[str, Any]]:
        """Find hosts with unpatched vulnerabilities for preventive action."""
        vuln_hosts = []
        for host_id, host in topo.hosts.items():
            if host.compromised or host.isolated:
                continue
            vuln_count = sum(len(s.vulnerabilities) for s in host.services)
            if vuln_count > 0:
                vuln_hosts.append({
                    "host_id": host_id,
                    "host_role": host.role,
                    "vuln_count": vuln_count,
                })
        vuln_hosts.sort(key=lambda v: v["vuln_count"], reverse=True)
        return vuln_hosts
