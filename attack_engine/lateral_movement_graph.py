"""
Lateral Movement Graph Module — Analyzes network topologies and session states
to discover potential lateral movement pathways across hosts.
"""

import logging
from typing import Dict, List, Tuple, Set, Optional, Any
import networkx as nx
from shared.models import Host
from simulation_engine.network import NetworkTopology

logger = logging.getLogger(__name__)

class LateralMovementGraph:
    """
    Constructs a graph representing lateral movement vectors between network hosts.
    Nodes are hosts. Edges represent specific lateral movement techniques available (e.g. SMB, RDP, SSH, WMI).
    """

    def __init__(self, topo: NetworkTopology):
        self.topo = topo
        self.graph = nx.DiGraph()
        self._build_graph()

    def _build_graph(self):
        """Constructs the lateral movement connectivity and capabilities graph."""
        self.graph.clear()
        
        # Add all hosts as nodes
        for host_id, host in self.topo.hosts.items():
            self.graph.add_node(
                host_id,
                role=host.role,
                compromised=host.compromised,
                isolated=host.isolated,
                os=host.os
            )

        # Build movement edges based on network connections and running services
        for src_id, dst_id in self.topo.connections:
            src_host = self.topo.hosts.get(src_id)
            dst_host = self.topo.hosts.get(dst_id)
            if not src_host or not dst_host:
                continue

            # Cannot move to/from isolated hosts
            if src_host.isolated or dst_host.isolated:
                continue

            # Check directional capabilities from src -> dst
            capabilities = self._get_movement_capabilities(src_host, dst_host)
            if capabilities:
                # Add edge with capabilities list
                self.graph.add_edge(src_id, dst_id, techniques=capabilities, weight=self._calculate_weight(capabilities, dst_host))

            # Check directional capabilities from dst -> src
            capabilities_rev = self._get_movement_capabilities(dst_host, src_host)
            if capabilities_rev:
                self.graph.add_edge(dst_id, src_id, techniques=capabilities_rev, weight=self._calculate_weight(capabilities_rev, src_host))

        logger.info(
            f"Lateral Movement Graph built: {self.graph.number_of_nodes()} hosts, "
            f"{self.graph.number_of_edges()} valid lateral pathways."
        )

    def _get_movement_capabilities(self, src: Host, dst: Host) -> List[str]:
        """Detects lateral movement vectors based on destination OS and active services."""
        vectors = []
        
        # Destination service mapping
        ports = {s.port: s.name for s in dst.services}
        
        # Windows Lateral Movement Techniques
        if "windows" in dst.os.lower() or dst.role in ("domain_controller", "workstation"):
            if 445 in ports:  # SMB
                vectors.append("T1021.002 (SMB/Windows Admin Shares)")
                vectors.append("T1047 (WMI)")
            if 3389 in ports:  # RDP
                vectors.append("T1021.001 (Remote Desktop Protocol)")
            if 5985 in ports or 5986 in ports:  # WinRM
                vectors.append("T1021.006 (Windows Remote Management)")
                
        # Linux/Unix Lateral Movement Techniques
        else:
            if 22 in ports:  # SSH
                vectors.append("T1021.004 (SSH)")
                
        # Generic HTTP-based lateral actions (e.g. pivoting via APIs)
        if 80 in ports or 443 in ports:
            vectors.append("T1210 (Exploitation of Remote Services)")
            
        return vectors

    def _calculate_weight(self, capabilities: List[str], dst: Host) -> float:
        """Computes traversal cost. Lower weight = easier/higher probability of success."""
        # Baseline cost
        base = 10.0
        
        # More capabilities reduce cost (easier to find a working vector)
        cap_factor = len(capabilities) * 1.5
        
        # Vulnerabilities present makes it significantly easier
        vuln_count = sum(len(s.vulnerabilities) for s in dst.services)
        vuln_factor = vuln_count * 3.0
        
        weight = max(1.0, base - cap_factor - vuln_factor)
        
        # High value targets have naturally higher defense/sophistication barriers
        if dst.role == "domain_controller":
            weight += 5.0
            
        return round(weight, 2)

    def rebuild(self):
        """Rebuilds lateral movement pathways after topology modifications."""
        self._build_graph()

    def get_shortest_lateral_path(self, start_host: str, target_host: str) -> Optional[List[str]]:
        """Computes shortest lateral path weighting network connection weights."""
        if not self.graph.has_node(start_host) or not self.graph.has_node(target_host):
            return None
        try:
            return nx.shortest_path(self.graph, start_host, target_host, weight="weight")
        except nx.NetworkXNoPath:
            return None
