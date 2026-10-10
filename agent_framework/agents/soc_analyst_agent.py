"""
SOC Analyst Agent — Analyzes alerts, classifies threats, prioritizes incidents.

Performs alert triage, false positive reduction, severity classification,
and incident prioritization using memory-driven pattern recognition and
structured reasoning chains.

Part of Phase 1: Multi-Agent Society.
"""

import logging
from collections import Counter
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

# Alert severity weights for prioritization
SEVERITY_WEIGHTS = {
    "CRITICAL": 4.0,
    "HIGH": 3.0,
    "WARNING": 2.0,
    "INFO": 1.0,
    "LOW": 0.5,
}

# Known false-positive patterns (offline heuristic database)
FALSE_POSITIVE_PATTERNS = [
    {"event_type": "Auth_Log", "message_contains": "PREAUTH", "severity": "INFO"},
    {"event_type": "Firewall_Log", "message_contains": "broadcast", "severity": "INFO"},
    {"event_type": "Sysmon_ProcessCreation", "message_contains": "svchost.exe", "severity": "INFO"},
    {"event_type": "Sysmon_NetworkConnection", "message_contains": "windowsupdate", "severity": "INFO"},
]


class SOCAnalystAgent(CognitiveAgent):
    """
    SOC Analyst agent for alert triage and incident prioritization.

    Responsibilities:
    - Analyze incoming security alerts from telemetry
    - Classify alerts by severity and threat category
    - Reduce false positives using heuristic patterns and historical context
    - Prioritize incidents based on asset criticality and attack chain position
    - Generate triage reports with confidence-scored recommendations
    """

    def __init__(self, agent_id: str = "SOC-Analyst-01", **kwargs):
        super().__init__(agent_id=agent_id, role="soc_analyst", **kwargs)
        self.alerts_processed: int = 0
        self.false_positives_filtered: int = 0
        self.incidents_created: List[Dict[str, Any]] = []
        self.triage_queue: List[Dict[str, Any]] = []
        logger.info(f"SOCAnalystAgent {agent_id} initialized")

    def reason(
        self, sim: SimulationEngine, topo: NetworkTopology
    ) -> Optional[DecisionExplanation]:
        """Analyze network state for suspicious activity and triage alerts."""
        self.reasoning_engine.begin_reasoning()

        # Step 1: Gather current threat indicators from topology
        compromised_hosts = []
        suspicious_hosts = []
        all_alerts: List[Dict[str, Any]] = []

        for host_id, host in topo.hosts.items():
            if host.compromised and not host.isolated:
                compromised_hosts.append(host_id)
                all_alerts.append({
                    "host_id": host_id,
                    "severity": "CRITICAL",
                    "event_type": "Compromise_Detected",
                    "message": f"Host {host_id} ({host.role}) is actively compromised",
                    "host_role": host.role,
                    "host_ip": host.ip,
                })
            elif host.compromised and host.isolated:
                # Already contained — lower priority
                all_alerts.append({
                    "host_id": host_id,
                    "severity": "INFO",
                    "event_type": "Contained_Host",
                    "message": f"Host {host_id} compromised but isolated",
                    "host_role": host.role,
                    "host_ip": host.ip,
                })

            # Check for credential dumps (indicator of lateral movement)
            if host.credentials_dumped and not host.isolated:
                suspicious_hosts.append(host_id)
                all_alerts.append({
                    "host_id": host_id,
                    "severity": "HIGH",
                    "event_type": "Credential_Dump",
                    "message": f"Credentials dumped on {host_id} — lateral movement risk",
                    "host_role": host.role,
                    "host_ip": host.ip,
                })

            # Check for high vulnerability exposure on uncompromised hosts
            total_vulns = sum(len(s.vulnerabilities) for s in host.services)
            if total_vulns > 0 and not host.compromised:
                all_alerts.append({
                    "host_id": host_id,
                    "severity": "WARNING",
                    "event_type": "Vulnerability_Exposure",
                    "message": f"Host {host_id} has {total_vulns} unpatched vulnerabilities",
                    "host_role": host.role,
                    "host_ip": host.ip,
                })

        self.reasoning_engine.add_step(
            observation=f"Scanned {len(topo.hosts)} hosts: {len(compromised_hosts)} compromised, "
                        f"{len(suspicious_hosts)} suspicious",
            hypothesis="Active compromises require immediate response",
            confidence=0.90,
        )

        if not all_alerts:
            return self.reasoning_engine.generate_explanation(
                decision="no_action",
                reason="No security alerts detected in current network state",
                affected_assets=[],
                recommended_actions=["Continue monitoring"],
            )

        # Step 2: Filter false positives
        filtered_alerts = self._filter_false_positives(all_alerts)
        fp_count = len(all_alerts) - len(filtered_alerts)
        self.false_positives_filtered += fp_count

        self.reasoning_engine.add_step(
            observation=f"Filtered {fp_count} false positives from {len(all_alerts)} total alerts",
            hypothesis="Remaining alerts represent genuine security concerns",
            confidence=0.85,
        )

        # Step 3: Prioritize alerts
        prioritized = self._prioritize_alerts(filtered_alerts, topo)

        if not prioritized:
            return self.reasoning_engine.generate_explanation(
                decision="no_action",
                reason="All alerts classified as false positives",
                affected_assets=[],
                recommended_actions=["Review false positive rules"],
            )

        top_alert = prioritized[0]

        # Step 4: Generate triage recommendation
        self.reasoning_engine.add_step(
            observation=f"Top priority: {top_alert['event_type']} on {top_alert['host_id']} "
                        f"(priority_score={top_alert.get('priority_score', 0):.2f})",
            hypothesis=f"Host {top_alert['host_id']} requires immediate defensive action",
            evidence=[
                Evidence(
                    evidence_type=EvidenceType.TELEMETRY,
                    description=alert["message"],
                    data=alert,
                    weight=SEVERITY_WEIGHTS.get(alert["severity"], 1.0),
                )
                for alert in prioritized[:5]
            ],
            confidence=0.88,
            conclusion=f"Recommend {'isolate_host' if top_alert['severity'] == 'CRITICAL' else 'investigate'} for {top_alert['host_id']}",
        )

        # Determine recommended action
        if top_alert["severity"] == "CRITICAL":
            action = "isolate_host"
            rec_actions = [
                f"Immediately isolate {top_alert['host_id']}",
                "Initiate incident response procedure",
                "Collect forensic artifacts before remediation",
            ]
        elif top_alert["severity"] == "HIGH":
            action = "investigate"
            rec_actions = [
                f"Investigate credential dump on {top_alert['host_id']}",
                "Check for lateral movement to connected hosts",
                "Consider preventive isolation",
            ]
        else:
            action = "monitor"
            rec_actions = [
                f"Monitor {top_alert['host_id']} for escalation",
                "Schedule vulnerability patching",
            ]

        # Record incident
        incident = {
            "alert": top_alert,
            "action": action,
            "all_alerts": len(filtered_alerts),
            "critical_count": sum(1 for a in filtered_alerts if a["severity"] == "CRITICAL"),
        }
        self.incidents_created.append(incident)
        self.alerts_processed += len(all_alerts)
        self.triage_queue = prioritized

        return self.reasoning_engine.generate_explanation(
            decision=action,
            reason=f"{top_alert['event_type']} detected on {top_alert['host_id']} "
                   f"({top_alert['host_role']}): {top_alert['message']}",
            affected_assets=[a["host_id"] for a in prioritized[:5]],
            recommended_actions=rec_actions,
        )

    def explain(self) -> str:
        if self.last_explanation:
            return self.last_explanation.to_summary()
        return "No triage analysis performed yet."

    def _filter_false_positives(
        self, alerts: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Apply heuristic false-positive filters and historical patterns."""
        filtered = []
        for alert in alerts:
            is_fp = False
            for pattern in FALSE_POSITIVE_PATTERNS:
                if (
                    alert.get("event_type") == pattern["event_type"]
                    and pattern["message_contains"].lower()
                    in alert.get("message", "").lower()
                    and alert.get("severity") == pattern["severity"]
                ):
                    is_fp = True
                    break

            # Historical false-positive check via memory
            if not is_fp:
                past = self.long_term_memory.query(
                    action=alert.get("event_type"),
                    target=alert.get("host_id"),
                    result="false_positive",
                    limit=5,
                )
                if len(past) >= 3:
                    # Same alert type on same host flagged as FP 3+ times
                    is_fp = True

            if not is_fp:
                filtered.append(alert)

        return filtered

    def _prioritize_alerts(
        self, alerts: List[Dict[str, Any]], topo: NetworkTopology
    ) -> List[Dict[str, Any]]:
        """Score and sort alerts by composite priority."""
        role_criticality = {
            "domain_controller": 5.0,
            "db_server": 4.0,
            "web_server": 3.0,
            "file_server": 2.5,
            "workstation": 1.0,
        }

        for alert in alerts:
            severity_score = SEVERITY_WEIGHTS.get(alert["severity"], 1.0)
            role_score = role_criticality.get(alert.get("host_role", "workstation"), 1.0)

            # Connectivity bonus: more connections = higher blast radius
            host = topo.hosts.get(alert["host_id"])
            connection_count = 0
            if host:
                for h1, h2 in topo.connections:
                    if h1 == alert["host_id"] or h2 == alert["host_id"]:
                        connection_count += 1

            connectivity_score = 1.0 + (connection_count * 0.2)

            alert["priority_score"] = severity_score * role_score * connectivity_score

        alerts.sort(key=lambda a: a["priority_score"], reverse=True)
        return alerts

    def get_triage_summary(self) -> Dict[str, Any]:
        """Return a summary of the current triage state."""
        return {
            "total_alerts_processed": self.alerts_processed,
            "false_positives_filtered": self.false_positives_filtered,
            "incidents_created": len(self.incidents_created),
            "pending_triage": len(self.triage_queue),
            "confidence": self.confidence_score,
        }
