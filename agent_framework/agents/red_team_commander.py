"""
Red Team Commander — Attack campaign orchestration and multi-agent coordination.

Builds multi-step attack campaigns using MITRE ATT&CK kill chain,
coordinates attacker agents, selects optimal attack chains based on
vulnerability analysis and graph topology, and adapts strategy based
on defender responses.

Part of Phase 1: Multi-Agent Society.
"""

import logging
import random
from typing import Any, Dict, List, Optional, Set

from agent_framework.cognitive import CognitiveAgent
from agent_framework.reasoning import (
    DecisionExplanation,
    Evidence,
    EvidenceType,
)
from attack_engine.mitre import MITRE_ATTACK_MAP
from simulation_engine.core import SimulationEngine
from simulation_engine.network import NetworkTopology

logger = logging.getLogger(__name__)

# MITRE ATT&CK Kill Chain phases for campaign planning
KILL_CHAIN_PHASES = [
    "reconnaissance",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "exfiltration",
    "impact",
]


class RedTeamCommander(CognitiveAgent):
    """
    Red Team Commander — orchestrates complete attack campaigns.

    Responsibilities:
    - Build multi-step attack campaigns using MITRE ATT&CK
    - Coordinate multiple attacker agents toward objectives
    - Select attack chains based on vulnerability and topology analysis
    - Adapt strategy in response to defender actions
    - Track campaign progress and objective completion
    """

    def __init__(self, agent_id: str = "RedTeam-Cmd-01", sophistication: float = 0.85, **kwargs):
        super().__init__(agent_id=agent_id, role="red_team_commander", **kwargs)
        self.sophistication = sophistication
        self.current_phase_index: int = 0
        self.campaign_objective: str = "domain_controller"  # Default: compromise DC
        self.campaign_log: List[Dict[str, Any]] = []
        self.compromised_hosts: Set[str] = set()
        self.discovered_hosts: Set[str] = set()
        self.captured_credentials: List[Dict[str, Any]] = []
        self.blocked_targets: Set[str] = set()  # Hosts known to be isolated
        logger.info(f"RedTeamCommander {agent_id} initialized (sophistication={sophistication})")

    def set_objective(self, objective: str) -> None:
        """Set the campaign objective (e.g., 'domain_controller', 'data_exfiltration')."""
        self.campaign_objective = objective
        logger.info(f"Campaign objective set to: {objective}")

    @property
    def current_phase(self) -> str:
        """Current kill chain phase."""
        if self.current_phase_index < len(KILL_CHAIN_PHASES):
            return KILL_CHAIN_PHASES[self.current_phase_index]
        return "complete"

    def reason(
        self, sim: SimulationEngine, topo: NetworkTopology
    ) -> Optional[DecisionExplanation]:
        """Execute one cycle of attack campaign planning."""
        self.reasoning_engine.begin_reasoning()

        # Step 1: Update situational awareness
        self._update_awareness(topo)

        self.reasoning_engine.add_step(
            observation=f"Campaign phase: {self.current_phase}. "
                        f"Compromised: {len(self.compromised_hosts)}/{len(topo.hosts)}. "
                        f"Blocked: {len(self.blocked_targets)} targets isolated.",
            hypothesis="Need to advance the kill chain toward the objective",
            confidence=0.85,
        )

        # Step 2: Check if objective is already achieved
        objective_host = self._find_objective_host(topo)
        if objective_host and objective_host.id in self.compromised_hosts:
            self.reasoning_engine.add_step(
                observation=f"Objective achieved: {objective_host.id} is compromised",
                confidence=0.99,
                conclusion="Campaign objective complete",
            )
            return self.reasoning_engine.generate_explanation(
                decision="campaign_complete",
                reason=f"Campaign objective achieved: {self.campaign_objective} "
                       f"({objective_host.id}) has been compromised",
                affected_assets=list(self.compromised_hosts),
                recommended_actions=["Begin data collection", "Establish persistence"],
            )

        # Step 3: Plan next action based on current phase
        action_plan = self._plan_next_action(topo)

        if action_plan is None:
            # Adapt — try to advance to next phase
            self.current_phase_index = min(
                self.current_phase_index + 1, len(KILL_CHAIN_PHASES) - 1
            )
            return self.reasoning_engine.generate_explanation(
                decision="phase_advance",
                reason=f"No viable actions in current phase. Advancing to {self.current_phase}",
                affected_assets=[],
                recommended_actions=[f"Reassess options in {self.current_phase} phase"],
            )

        # Step 4: Record campaign action
        self.campaign_log.append(action_plan)

        self.reasoning_engine.add_step(
            observation=f"Selected action: {action_plan['action']} on {action_plan['target']}",
            evidence=[
                Evidence(
                    evidence_type=EvidenceType.GRAPH_STRUCTURE,
                    description=f"Attack path via {action_plan.get('attack_path', 'direct')}",
                    data=action_plan,
                    weight=action_plan.get("success_probability", 0.5),
                )
            ],
            confidence=action_plan.get("success_probability", 0.7),
            conclusion=f"Execute {action_plan['action']} targeting {action_plan['target']}",
        )

        mitre_info = MITRE_ATTACK_MAP.get(action_plan["action"], {})

        return self.reasoning_engine.generate_explanation(
            decision=action_plan["action"],
            reason=action_plan["reason"],
            affected_assets=[action_plan["target"]],
            recommended_actions=[
                f"Execute {action_plan['action']} on {action_plan['target']}",
                f"Prepare fallback: {action_plan.get('fallback', 'retry with alternative technique')}",
            ],
            mitre_techniques=[mitre_info.get("technique_id", "")] if mitre_info else [],
        )

    def explain(self) -> str:
        if self.last_explanation:
            return self.last_explanation.to_summary()
        return "No attack campaign planning performed yet."

    # ------------------------------------------------------------------ #
    #  Planning Methods
    # ------------------------------------------------------------------ #

    def _update_awareness(self, topo: NetworkTopology) -> None:
        """Update situational awareness from topology state."""
        self.compromised_hosts = {
            h.id for h in topo.hosts.values() if h.compromised
        }
        self.blocked_targets = {
            h.id for h in topo.hosts.values() if h.isolated
        }

    def _find_objective_host(self, topo: NetworkTopology):
        """Find the host matching the campaign objective."""
        for host in topo.hosts.values():
            if self.campaign_objective == "domain_controller" and host.role == "domain_controller":
                return host
            elif self.campaign_objective == "db_server" and host.role == "db_server":
                return host
            elif self.campaign_objective == host.id:
                return host
        return None

    def _plan_next_action(
        self, topo: NetworkTopology
    ) -> Optional[Dict[str, Any]]:
        """Plan the next attack action based on kill chain phase and available targets."""
        phase = self.current_phase

        if phase == "reconnaissance" or not self.discovered_hosts:
            return self._plan_reconnaissance(topo)
        elif phase == "initial_access" and not self.compromised_hosts:
            return self._plan_initial_access(topo)
        elif phase in ("execution", "credential_access"):
            return self._plan_credential_access(topo)
        elif phase in ("lateral_movement", "discovery"):
            return self._plan_lateral_movement(topo)
        elif phase == "exfiltration":
            return self._plan_exfiltration(topo)
        else:
            # Auto-select best available action
            return self._plan_auto(topo)

    def _plan_reconnaissance(
        self, topo: NetworkTopology
    ) -> Optional[Dict[str, Any]]:
        """Plan reconnaissance actions."""
        undiscovered = [
            h_id for h_id in topo.hosts
            if h_id not in self.discovered_hosts and h_id not in self.blocked_targets
        ]
        if undiscovered:
            target = undiscovered[0]
            self.discovered_hosts.add(target)
            self.current_phase_index = max(self.current_phase_index, 1)
            return {
                "action": "network_scan",
                "target": target,
                "reason": f"Reconnaissance: scanning {target} to discover services and vulnerabilities",
                "success_probability": 0.95,
                "fallback": "Try passive OSINT gathering",
            }
        return None

    def _plan_initial_access(
        self, topo: NetworkTopology
    ) -> Optional[Dict[str, Any]]:
        """Plan initial access via vulnerability exploitation."""
        for host_id in self.discovered_hosts:
            if host_id in self.compromised_hosts or host_id in self.blocked_targets:
                continue
            host = topo.hosts.get(host_id)
            if not host:
                continue
            for service in host.services:
                if service.vulnerabilities:
                    self.current_phase_index = max(self.current_phase_index, 2)
                    return {
                        "action": "exploit_service",
                        "target": host_id,
                        "service": service.name,
                        "cves": service.vulnerabilities,
                        "reason": f"Initial access: exploiting {service.name} on {host_id} "
                                  f"via {service.vulnerabilities[0]}",
                        "success_probability": min(0.7 + self.sophistication * 0.2, 0.95),
                        "fallback": "Attempt phishing against logged-in users",
                    }
        return None

    def _plan_credential_access(
        self, topo: NetworkTopology
    ) -> Optional[Dict[str, Any]]:
        """Plan credential dumping on compromised hosts."""
        for host_id in self.compromised_hosts:
            host = topo.hosts.get(host_id)
            if host and not host.credentials_dumped and not host.isolated:
                self.current_phase_index = max(self.current_phase_index, 6)
                return {
                    "action": "credentials_dump",
                    "target": host_id,
                    "reason": f"Credential access: dumping credentials from {host_id} "
                              f"for lateral movement",
                    "success_probability": 0.85,
                    "fallback": "Use Kerberoasting on domain accounts",
                }
        return None

    def _plan_lateral_movement(
        self, topo: NetworkTopology
    ) -> Optional[Dict[str, Any]]:
        """Plan lateral movement from compromised hosts to new targets."""
        for source_id in self.compromised_hosts:
            source = topo.hosts.get(source_id)
            if not source or source.isolated:
                continue

            for h1, h2 in topo.connections:
                neighbor_id = h2 if h1 == source_id else h1 if h2 == source_id else None
                if not neighbor_id:
                    continue
                if neighbor_id in self.compromised_hosts or neighbor_id in self.blocked_targets:
                    continue

                neighbor = topo.hosts.get(neighbor_id)
                if neighbor and not neighbor.isolated:
                    self.current_phase_index = max(self.current_phase_index, 8)
                    return {
                        "action": "lateral_movement_smb",
                        "target": neighbor_id,
                        "source": source_id,
                        "attack_path": f"{source_id} → {neighbor_id}",
                        "reason": f"Lateral movement: pivoting from {source_id} to "
                                  f"{neighbor_id} ({neighbor.role}) via SMB",
                        "success_probability": 0.75,
                        "fallback": "Attempt RDP or WinRM lateral movement",
                    }
        return None

    def _plan_exfiltration(
        self, topo: NetworkTopology
    ) -> Optional[Dict[str, Any]]:
        """Plan data exfiltration from compromised high-value targets."""
        for host_id in self.compromised_hosts:
            host = topo.hosts.get(host_id)
            if host and host.role in ("db_server", "file_server", "domain_controller"):
                return {
                    "action": "data_exfiltration",
                    "target": host_id,
                    "reason": f"Exfiltration: extracting data from {host_id} "
                              f"({host.role}) via covert channel",
                    "success_probability": 0.80,
                    "fallback": "Use DNS tunneling for exfiltration",
                }
        return None

    def _plan_auto(
        self, topo: NetworkTopology
    ) -> Optional[Dict[str, Any]]:
        """Automatically select the best available action."""
        # Priority: lateral movement > credential dump > exploit > recon
        plan = self._plan_lateral_movement(topo)
        if plan:
            return plan
        plan = self._plan_credential_access(topo)
        if plan:
            return plan
        plan = self._plan_initial_access(topo)
        if plan:
            return plan
        plan = self._plan_reconnaissance(topo)
        if plan:
            return plan
        plan = self._plan_exfiltration(topo)
        return plan

    def get_campaign_status(self) -> Dict[str, Any]:
        """Return current campaign status summary."""
        return {
            "agent_id": self.agent_id,
            "objective": self.campaign_objective,
            "current_phase": self.current_phase,
            "phase_index": self.current_phase_index,
            "compromised_hosts": sorted(self.compromised_hosts),
            "discovered_hosts": sorted(self.discovered_hosts),
            "blocked_targets": sorted(self.blocked_targets),
            "actions_taken": len(self.campaign_log),
            "confidence": self.confidence_score,
        }
