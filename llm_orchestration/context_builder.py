"""
Context Builder — Constructs rich context windows from topology and telemetry.

Formats graph data, host states, vulnerability information, and telemetry
events into structured context suitable for LLM prompt construction.
Token-aware truncation ensures context fits within model limits.

Part of Phase 3: Graph RAG.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from simulation_engine.network import NetworkTopology

logger = logging.getLogger(__name__)

# Default token budget for context windows
DEFAULT_MAX_TOKENS = 3000
AVG_CHARS_PER_TOKEN = 4  # Approximate for English text


class ContextBuilder:
    """
    Constructs rich context windows from topology + telemetry data.

    Formats graph data as structured context for LLM prompts,
    with token-aware truncation to prevent exceeding model limits.
    """

    def __init__(self, max_tokens: int = DEFAULT_MAX_TOKENS):
        self.max_tokens = max_tokens
        self.max_chars = max_tokens * AVG_CHARS_PER_TOKEN

    def build_topology_context(
        self, topo: NetworkTopology, include_services: bool = True
    ) -> str:
        """
        Build a structured text representation of the network topology.

        Includes host states, services, vulnerabilities, and connections.
        """
        sections = []

        # Header
        sections.append(f"=== NETWORK TOPOLOGY ({len(topo.hosts)} hosts, {len(topo.connections)} connections) ===\n")

        # Hosts
        sections.append("## Hosts:")
        for host_id, host in topo.hosts.items():
            status_flags = []
            if host.compromised:
                status_flags.append("COMPROMISED")
            if host.isolated:
                status_flags.append("ISOLATED")
            if host.credentials_dumped:
                status_flags.append("CREDS_DUMPED")
            status_str = f" [{', '.join(status_flags)}]" if status_flags else ""

            line = f"- {host_id}: {host.name} | IP={host.ip} | OS={host.os} | Role={host.role}{status_str}"

            if include_services and host.services:
                svc_parts = []
                for svc in host.services:
                    vuln_str = f" VULNS=[{', '.join(svc.vulnerabilities)}]" if svc.vulnerabilities else ""
                    svc_parts.append(f"{svc.name}:{svc.port}{vuln_str}")
                line += f"\n  Services: {', '.join(svc_parts)}"

            sections.append(line)

        # Connections
        sections.append("\n## Network Connections:")
        for h1, h2 in topo.connections:
            sections.append(f"  {h1} <-> {h2}")

        # Users
        if topo.users:
            sections.append(f"\n## Users ({len(topo.users)}):")
            for username, user in topo.users.items():
                sections.append(
                    f"  - {username}: domain={user.domain}, "
                    f"roles={user.roles}, phish_susceptibility={user.phishing_susceptibility:.2f}"
                )

        context = "\n".join(sections)
        return self._truncate(context)

    def build_threat_context(self, topo: NetworkTopology) -> str:
        """Build a threat-focused context highlighting compromised and vulnerable hosts."""
        sections = ["=== THREAT ASSESSMENT ===\n"]

        # Compromised hosts
        compromised = [h for h in topo.hosts.values() if h.compromised]
        sections.append(f"## Active Compromises ({len(compromised)}):")
        for host in compromised:
            isolated_str = " (ISOLATED)" if host.isolated else " (ACTIVE THREAT)"
            sections.append(
                f"  - {host.id}: {host.name} ({host.role}){isolated_str}"
            )
            if host.compromised_by:
                sections.append(f"    Compromised by: {host.compromised_by}")

        # Vulnerable hosts (not yet compromised)
        vulnerable = []
        for host in topo.hosts.values():
            if not host.compromised:
                vulns = []
                for svc in host.services:
                    vulns.extend(svc.vulnerabilities)
                if vulns:
                    vulnerable.append((host, vulns))

        sections.append(f"\n## Vulnerable Hosts ({len(vulnerable)}):")
        for host, vulns in vulnerable:
            sections.append(
                f"  - {host.id}: {host.role} — CVEs: {', '.join(vulns[:5])}"
            )

        # Attack surface
        entry_points = []
        for host in topo.hosts.values():
            if host.role == "web_server" or any(
                s.name in ("HTTP", "HTTPS") for s in host.services
            ):
                entry_points.append(host.id)
        sections.append(f"\n## External Attack Surface: {', '.join(entry_points) or 'None'}")

        # Network statistics
        total = len(topo.hosts)
        comp_count = len(compromised)
        isolated_count = sum(1 for h in topo.hosts.values() if h.isolated)
        sections.append(
            f"\n## Network Stats: {total} total hosts, {comp_count} compromised, "
            f"{isolated_count} isolated, {total - comp_count} clean"
        )

        return self._truncate("\n".join(sections))

    def build_host_context(self, host_id: str, topo: NetworkTopology) -> str:
        """Build detailed context for a specific host including neighbors."""
        host = topo.hosts.get(host_id)
        if not host:
            return f"Host {host_id} not found in topology."

        sections = [f"=== HOST DETAIL: {host_id} ===\n"]
        sections.append(f"Name: {host.name}")
        sections.append(f"IP: {host.ip}")
        sections.append(f"OS: {host.os}")
        sections.append(f"Role: {host.role}")
        sections.append(f"Domain: {host.domain}")
        sections.append(f"Compromised: {host.compromised}")
        sections.append(f"Isolated: {host.isolated}")
        sections.append(f"Credentials Dumped: {host.credentials_dumped}")

        if host.services:
            sections.append("\nServices:")
            for svc in host.services:
                sections.append(f"  - {svc.name} (port {svc.port}, version {svc.version})")
                if svc.vulnerabilities:
                    sections.append(f"    Vulnerabilities: {', '.join(svc.vulnerabilities)}")

        # Neighbors
        neighbors = []
        for h1, h2 in topo.connections:
            if h1 == host_id:
                neighbors.append(h2)
            elif h2 == host_id:
                neighbors.append(h1)

        sections.append(f"\nConnected Hosts ({len(neighbors)}):")
        for n_id in neighbors:
            n_host = topo.hosts.get(n_id)
            if n_host:
                status = "compromised" if n_host.compromised else "clean"
                sections.append(f"  - {n_id}: {n_host.role} ({status})")

        # Logged-in users
        if host.logged_in_users:
            sections.append(f"\nLogged-in Users: {', '.join(host.logged_in_users)}")

        return self._truncate("\n".join(sections))

    def build_attack_context(
        self,
        topo: NetworkTopology,
        risk_scores: Optional[Dict[str, float]] = None,
        attack_paths: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """Build context for attack planning, including risk scores and paths."""
        sections = ["=== ATTACK INTELLIGENCE ===\n"]

        if risk_scores:
            sections.append("## GNN Risk Scores:")
            sorted_scores = sorted(risk_scores.items(), key=lambda x: x[1], reverse=True)
            for host_id, score in sorted_scores[:10]:
                host = topo.hosts.get(host_id)
                role = host.role if host else "unknown"
                sections.append(f"  - {host_id} ({role}): {score:.4f}")

        if attack_paths:
            sections.append(f"\n## Attack Paths ({len(attack_paths)}):")
            for i, path in enumerate(attack_paths[:5], 1):
                nodes = " → ".join(path.get("nodes", []))
                risk = path.get("risk_score", 0.0)
                sections.append(f"  Path {i}: {nodes} (risk={risk:.4f})")

        # Topology summary
        sections.append(f"\n## Topology Summary:")
        sections.append(self.build_threat_context(topo))

        return self._truncate("\n".join(sections))

    def build_defense_context(
        self,
        topo: NetworkTopology,
        recent_alerts: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """Build context for defensive decision-making."""
        sections = ["=== DEFENSE INTELLIGENCE ===\n"]

        if recent_alerts:
            sections.append(f"## Recent Alerts ({len(recent_alerts)}):")
            for alert in recent_alerts[:10]:
                sections.append(
                    f"  [{alert.get('severity', 'INFO')}] {alert.get('host_id', '?')}: "
                    f"{alert.get('message', 'No message')}"
                )

        sections.append(self.build_threat_context(topo))

        return self._truncate("\n".join(sections))

    def _truncate(self, text: str) -> str:
        """Truncate text to fit within the token budget."""
        if len(text) <= self.max_chars:
            return text
        truncated = text[:self.max_chars]
        # Try to cut at last newline for cleaner output
        last_newline = truncated.rfind("\n")
        if last_newline > self.max_chars * 0.8:
            truncated = truncated[:last_newline]
        return truncated + "\n\n[... context truncated to fit token budget ...]"
