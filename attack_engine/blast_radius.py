"""
Blast Radius Module — Calculates transitive reachability, impact scoring,
and risk exposure from any compromised host in the network topology.
"""

import logging
from typing import Dict, List, Set, Tuple, Any, Optional
import networkx as nx
from shared.models import Host
from simulation_engine.network import NetworkTopology
from attack_engine.lateral_movement_graph import LateralMovementGraph

logger = logging.getLogger(__name__)

class BlastRadiusCalculator:
    """
    Computes blast radius of host compromises, evaluating asset sensitivity,
    economic value, and potential lateral expansion hops.
    """

    def __init__(self, topo: NetworkTopology, lateral_graph: Optional[LateralMovementGraph] = None):
        self.topo = topo
        self.lateral_graph = lateral_graph or LateralMovementGraph(topo)

    def calculate_blast_radius(self, compromised_host_id: str, max_hops: int = 3) -> Dict[str, Any]:
        """
        Computes reachable hosts within a specified hop limit from a starting compromise node,
        weighing the asset value and sensitivity level of all affected assets.
        """
        self.lateral_graph.rebuild()
        g = self.lateral_graph.graph
        
        if compromised_host_id not in g:
            logger.warning(f"Host {compromised_host_id} not found in lateral movement graph.")
            return {
                "compromised_node": compromised_host_id,
                "reachable_nodes": [],
                "total_impact_value": 0.0,
                "max_sensitivity": "low",
                "hops_details": {}
            }

        reachable_nodes: Set[str] = set()
        hops_details: Dict[int, List[str]] = {}
        total_impact = 0.0
        max_sensitivity_val = 0
        sensitivity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        inv_sensitivity_map = {1: "low", 2: "medium", 3: "high", 4: "critical"}

        # BFS expansion up to max_hops
        queue = [(compromised_host_id, 0)]
        visited = {compromised_host_id}

        while queue:
            current, hop = queue.pop(0)
            
            if hop > 0:
                reachable_nodes.add(current)
                if hop not in hops_details:
                    hops_details[hop] = []
                hops_details[hop].append(current)
                
                host = self.topo.hosts.get(current)
                if host:
                    total_impact += host.asset_value
                    sens = (host.sensitivity_level or "low").lower()
                    max_sensitivity_val = max(max_sensitivity_val, sensitivity_map.get(sens, 1))

            if hop < max_hops:
                for neighbor in g.successors(current):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append((neighbor, hop + 1))

        return {
            "compromised_node": compromised_host_id,
            "reachable_nodes": list(reachable_nodes),
            "total_impact_value": round(total_impact, 2),
            "max_sensitivity": inv_sensitivity_map.get(max_sensitivity_val, "low"),
            "hops_details": hops_details,
            "reachability_count": len(reachable_nodes)
        }

    def get_highest_exposure_nodes(self, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Finds the network nodes with the largest potential blast radius
        if they were to be compromised.
        """
        results = []
        for host_id in self.topo.hosts:
            analysis = self.calculate_blast_radius(host_id, max_hops=3)
            results.append({
                "host_id": host_id,
                "reachable_count": analysis["reachability_count"],
                "potential_impact_value": analysis["total_impact_value"],
                "max_sensitivity": analysis["max_sensitivity"]
            })
            
        results.sort(key=lambda x: (x["potential_impact_value"], x["reachable_count"]), reverse=True)
        return results[:top_k]
