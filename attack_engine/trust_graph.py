"""
Trust Graph Module — Models and analyzes Active Directory and Forest Trust relationships.
Helps map cross-domain lateral movement paths and trust abuse chains.
"""

import logging
from typing import Dict, List, Set, Optional, Tuple, Any
import networkx as nx
from simulation_engine.network import NetworkTopology

logger = logging.getLogger(__name__)

class TrustGraph:
    """
    Constructs and analyzes Active Directory domain trusts.
    Nodes are domains, edges are trust relationships with direction and transitivity.
    """

    def __init__(self, topo: NetworkTopology):
        self.topo = topo
        self.graph = nx.DiGraph()
        self._trusts: List[Dict[str, Any]] = []
        self._build_graph()

    def add_trust(self, source_domain: str, target_domain: str, trust_type: str = "parent_child", transitive: bool = True, bidirectional: bool = True):
        """
        Adds a trust relationship.
        If domain A trusts domain B (bidirectional or one-way B -> A access),
        then security principals in B can authenticate to A.
        So directional flow of security principal access is from B to A (target_domain to source_domain).
        """
        self._trusts.append({
            "source": source_domain,
            "target": target_domain,
            "type": trust_type,
            "transitive": transitive,
            "bidirectional": bidirectional
        })
        self._build_graph()

    def _build_graph(self):
        """Reconstructs the trust graph from registered trust definitions and topology domains."""
        self.graph.clear()
        
        # Collect all unique domains in topology
        domains = set()
        for host in self.topo.hosts.values():
            if host.domain:
                domains.add(host.domain)
        for user in self.topo.users.values():
            if user.domain:
                domains.add(user.domain)
                
        for domain in domains:
            self.graph.add_node(domain, type="domain")

        # Add trust edges
        for trust in self._trusts:
            src = trust["source"]
            tgt = trust["target"]
            transitive = trust["transitive"]
            
            # Ensure nodes exist
            self.graph.add_node(src, type="domain")
            self.graph.add_node(tgt, type="domain")
            
            # Flow of compromise/authentication:
            # If A trusts B (direction: A -> B), users from B can access A.
            # Edge flow direction: from B (tgt) to A (src) to indicate principal movement.
            self.graph.add_edge(tgt, src, relation="trusted_by", type=trust["type"], transitive=transitive)
            
            if trust["bidirectional"]:
                self.graph.add_edge(src, tgt, relation="trusted_by", type=trust["type"], transitive=transitive)

        logger.info(
            f"Trust Graph built: {self.graph.number_of_nodes()} domains, "
            f"{self.graph.number_of_edges()} trust paths."
        )

    def rebuild(self):
        """Rebuilds the trust relationships based on current topology state."""
        self._build_graph()

    def is_trust_reachable(self, principal_domain: str, resource_domain: str) -> bool:
        """
        Checks if a principal from principal_domain can authenticate to resource_domain
        by traversing transitive trust relationships.
        """
        if principal_domain == resource_domain:
            return True
            
        if not self.graph.has_node(principal_domain) or not self.graph.has_node(resource_domain):
            return False

        try:
            # Check if there is a path from principal_domain to resource_domain in our graph
            # Since edges point in authentication flow direction: principal_domain -> resource_domain
            path = nx.shortest_path(self.graph, principal_domain, resource_domain)
            
            # Check transitivity along the path
            for i in range(len(path) - 1):
                edge_data = self.graph.get_edge_data(path[i], path[i+1])
                if not edge_data.get("transitive", True):
                    # Non-transitive trust cannot be traversed past 1 hop
                    if len(path) > 2:
                        return False
            return True
        except nx.NetworkXNoPath:
            return False
        except Exception as e:
            logger.error(f"Error checking trust reachability: {e}", exc_info=True)
            return False

    def find_trust_abuse_path(self, principal_domain: str, resource_domain: str) -> Optional[List[str]]:
        """
        Returns the domain path to compromise resource_domain starting from principal_domain.
        """
        if not self.is_trust_reachable(principal_domain, resource_domain):
            return None
        try:
            return nx.shortest_path(self.graph, principal_domain, resource_domain)
        except Exception:
            return None
