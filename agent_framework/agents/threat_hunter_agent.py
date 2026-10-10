"""
Threat Hunter Agent — Proactive threat hunting across the network topology.

Searches for hidden persistence, lateral movement trails, C2 beaconing
patterns, and stealthy attacker behaviors that evade standard detection.
Uses graph-based analysis and telemetry correlation.

Part of Phase 1: Multi-Agent Society.
"""

import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from agent_framework.cognitive import CognitiveAgent
from agent_framework.reasoning import (
    DecisionExplanation,
    Evidence,
    EvidenceType,
)
from simulation_engine.core import SimulationEngine
from simulation_engine.network import NetworkTopology

logger = logging.getLogger(__name__)


class ThreatHunterAgent(CognitiveAgent):
    """
    Proactive threat hunting agent.

    Responsibilities:
    - Search for hidden persistence mechanisms
    - Detect lateral movement chains via graph traversal
    - Identify beaconing patterns in network connections
    - Hunt for compromised hosts missed by reactive detection
    - Generate hunt hypotheses based on MITRE ATT&CK TTPs
    """

    def __init__(self, agent_id: str = "ThreatHunter-01", **kwargs):
        super().__init__(agent_id=agent_id, role="threat_hunter", **kwargs)
        self.hunt_findings: List[Dict[str, Any]] = []
        self.lateral_movement_chains: List[List[str]] = []
        self.hunts_completed: int = 0
        logger.info(f"ThreatHunterAgent {agent_id} initialized")

    def reason(
        self, sim: SimulationEngine, topo: NetworkTopology
    ) -> Optional[DecisionExplanation]:
        """Execute a threat hunting cycle across the topology."""
        self.reasoning_engine.begin_reasoning()
        findings: List[Dict[str, Any]] = []

        # Hunt 1: Lateral Movement Detection
        lateral_chains = self._detect_lateral_movement(topo)
        if lateral_chains:
            self.reasoning_engine.add_step(
                observation=f"Detected {len(lateral_chains)} lateral movement chain(s)",
                hypothesis="Attacker is moving through the network via compromised hosts",
                evidence=[
                    Evidence(
                        evidence_type=EvidenceType.GRAPH_STRUCTURE,
                        description=f"Lateral chain: {' → '.join(chain)}",
                        data={"chain": chain, "length": len(chain)},
                        weight=len(chain) * 0.5,
                    )
                    for chain in lateral_chains[:5]
                ],
                confidence=0.85,
                conclusion=f"Lateral movement detected across {len(lateral_chains)} paths",
            )
            for chain in lateral_chains:
                findings.append({
                    "type": "lateral_movement",
                    "severity": "HIGH",
                    "description": f"Lateral movement chain: {' → '.join(chain)}",
                    "hosts": chain,
                })
            self.lateral_movement_chains.extend(lateral_chains)

        # Hunt 2: Hidden Persistence (compromised but no services patched)
        persistence_hosts = self._detect_hidden_persistence(topo)
        if persistence_hosts:
            self.reasoning_engine.add_step(
                observation=f"Found {len(persistence_hosts)} hosts with suspected persistence",
                hypothesis="Attacker has established persistence on these hosts",
                evidence=[
                    Evidence(
                        evidence_type=EvidenceType.HEURISTIC,
                        description=f"Host {h} shows persistence indicators",
                        data={"host_id": h},
                        weight=2.0,
                    )
                    for h in persistence_hosts
                ],
                confidence=0.75,
            )
            for host_id in persistence_hosts:
                findings.append({
                    "type": "hidden_persistence",
                    "severity": "HIGH",
                    "description": f"Suspected hidden persistence on {host_id}",
                    "hosts": [host_id],
                })

        # Hunt 3: Credential Exposure Risk
        cred_risk_hosts = self._detect_credential_exposure(topo)
        if cred_risk_hosts:
            self.reasoning_engine.add_step(
                observation=f"Found {len(cred_risk_hosts)} hosts with credential exposure risk",
                hypothesis="Credential harvesting may enable further attacks",
                evidence=[
                    Evidence(
                        evidence_type=EvidenceType.HEURISTIC,
                        description=f"Credentials at risk on {h['host_id']}",
                        data=h,
                        weight=1.5,
                    )
                    for h in cred_risk_hosts
                ],
                confidence=0.80,
            )
            for entry in cred_risk_hosts:
                findings.append({
                    "type": "credential_exposure",
                    "severity": "MEDIUM",
                    "description": f"Credential exposure risk on {entry['host_id']}: "
                                   f"{entry['reason']}",
                    "hosts": [entry["host_id"]],
                })

        # Hunt 4: Beaconing Detection (adjacent compromised-to-uncompromised patterns)
        beacon_suspects = self._detect_beaconing(topo)
        if beacon_suspects:
            self.reasoning_engine.add_step(
                observation=f"Found {len(beacon_suspects)} suspected beaconing patterns",
                hypothesis="Compromised hosts may be calling back to C2 or pivoting",
                confidence=0.70,
            )
            for suspect in beacon_suspects:
                findings.append({
                    "type": "beaconing",
                    "severity": "MEDIUM",
                    "description": f"Suspected C2 beaconing from {suspect['source']} toward {suspect['target']}",
                    "hosts": [suspect["source"], suspect["target"]],
                })

        self.hunt_findings.extend(findings)
        self.hunts_completed += 1

        if not findings:
            return self.reasoning_engine.generate_explanation(
                decision="hunt_complete_clean",
                reason="No threat indicators found during proactive hunt",
                affected_assets=[],
                recommended_actions=["Schedule next hunt cycle", "Update hunt hypotheses"],
            )

        # Prioritize findings
        findings.sort(
            key=lambda f: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(
                f["severity"], 0
            ),
            reverse=True,
        )
        top = findings[0]
        all_affected = set()
        for f in findings:
            all_affected.update(f["hosts"])

        return self.reasoning_engine.generate_explanation(
            decision="hunt_finding",
            reason=f"Threat hunt found {len(findings)} indicators. "
                   f"Top finding: {top['description']}",
            affected_assets=list(all_affected),
            recommended_actions=[
                f"Investigate {top['type']} on hosts: {', '.join(top['hosts'])}",
                "Isolate compromised hosts in lateral movement chains",
                "Check for data exfiltration from credential-exposed hosts",
            ],
            mitre_techniques=self._findings_to_mitre(findings),
        )

    def explain(self) -> str:
        if self.last_explanation:
            return self.last_explanation.to_summary()
        return "No threat hunt performed yet."

    # ------------------------------------------------------------------ #
    #  Hunt Methods
    # ------------------------------------------------------------------ #

    def _detect_lateral_movement(
        self, topo: NetworkTopology
    ) -> List[List[str]]:
        """
        Detect lateral movement chains by finding connected sequences
        of compromised hosts via BFS.
        """
        compromised = {h.id for h in topo.hosts.values() if h.compromised}
        if len(compromised) < 2:
            return []

        # Build adjacency for compromised hosts only
        adj: Dict[str, List[str]] = {}
        for h1, h2 in topo.connections:
            if h1 in compromised and h2 in compromised:
                adj.setdefault(h1, []).append(h2)
                adj.setdefault(h2, []).append(h1)

        # Find connected components (each is a lateral movement chain)
        visited: Set[str] = set()
        chains: List[List[str]] = []

        for host_id in compromised:
            if host_id not in visited:
                chain: List[str] = []
                queue = [host_id]
                while queue:
                    current = queue.pop(0)
                    if current in visited:
                        continue
                    visited.add(current)
                    chain.append(current)
                    for neighbor in adj.get(current, []):
                        if neighbor not in visited:
                            queue.append(neighbor)
                if len(chain) >= 2:
                    chains.append(chain)

        return chains

    def _detect_hidden_persistence(
        self, topo: NetworkTopology
    ) -> List[str]:
        """
        Find hosts that were compromised but show no obvious indicators
        (not yet isolated, credentials not dumped — suggesting stealthy persistence).
        """
        suspects = []
        for host_id, host in topo.hosts.items():
            if host.compromised and not host.isolated and not host.credentials_dumped:
                # Compromised but attacker hasn't dumped creds — may be
                # maintaining stealth persistence
                suspects.append(host_id)
        return suspects

    def _detect_credential_exposure(
        self, topo: NetworkTopology
    ) -> List[Dict[str, Any]]:
        """Find hosts where credentials are at risk due to adjacency to compromised hosts."""
        at_risk = []
        compromised_ids = {h.id for h in topo.hosts.values() if h.compromised}

        for host_id, host in topo.hosts.items():
            if host.compromised or host.isolated:
                continue
            # Check if any neighbor is compromised
            for h1, h2 in topo.connections:
                neighbor = h2 if h1 == host_id else h1 if h2 == host_id else None
                if neighbor and neighbor in compromised_ids:
                    at_risk.append({
                        "host_id": host_id,
                        "reason": f"Adjacent to compromised host {neighbor}",
                        "neighbor": neighbor,
                    })
                    break  # One adjacent compromised host is enough

        return at_risk

    def _detect_beaconing(
        self, topo: NetworkTopology
    ) -> List[Dict[str, str]]:
        """Detect potential C2 beaconing by finding compromised hosts with external connections."""
        suspects = []
        compromised_ids = {h.id for h in topo.hosts.values() if h.compromised}

        for h1, h2 in topo.connections:
            # Pattern: compromised host connected to non-compromised host
            # with web services (potential C2 relay)
            if h1 in compromised_ids and h2 not in compromised_ids:
                target_host = topo.hosts.get(h2)
                if target_host and any(
                    s.name in ("HTTP", "HTTPS", "DNS") for s in target_host.services
                ):
                    suspects.append({"source": h1, "target": h2})
            elif h2 in compromised_ids and h1 not in compromised_ids:
                target_host = topo.hosts.get(h1)
                if target_host and any(
                    s.name in ("HTTP", "HTTPS", "DNS") for s in target_host.services
                ):
                    suspects.append({"source": h2, "target": h1})

        return suspects

    def _findings_to_mitre(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Map hunt findings to MITRE ATT&CK technique IDs."""
        mitre = set()
        for f in findings:
            if f["type"] == "lateral_movement":
                mitre.update(["T1021.002", "T1550.002"])
            elif f["type"] == "hidden_persistence":
                mitre.update(["T1053.005", "T1547.001"])
            elif f["type"] == "credential_exposure":
                mitre.update(["T1003", "T1003.001"])
            elif f["type"] == "beaconing":
                mitre.update(["T1071.001", "T1071.004"])
        return sorted(mitre)
