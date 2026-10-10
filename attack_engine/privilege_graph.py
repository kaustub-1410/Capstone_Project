"""
Privilege Graph Module — Models and analyzes privilege escalation paths.
Tracks user sessions, credentials, host administrative relationships, and Active Directory roles
to compute shortest compromise pathways to Domain Admin or target hosts.
"""

import logging
from typing import Dict, List, Tuple, Set, Optional, Any
import networkx as nx
from shared.models import Host, User, Credential
from simulation_engine.network import NetworkTopology

logger = logging.getLogger(__name__)

class PrivilegeGraph:
    """
    Constructs and analyzes a directed privilege escalation graph.
    Nodes can represent Users, Hosts, or Credentials.
    Edges represent access/privilege relationships (e.g. Session, AdminTo, MemberOf).
    """

    def __init__(self, topo: NetworkTopology):
        self.topo = topo
        self.graph = nx.DiGraph()
        self._build_graph()

    def _build_graph(self):
        """Constructs the directed privilege graph from network topology."""
        self.graph.clear()
        
        # 1. Add User nodes and link to Credentials
        for username, user in self.topo.users.items():
            user_node = f"user:{username}"
            self.graph.add_node(user_node, type="user", username=username, domain=user.domain)
            
            for cred in user.credentials:
                cred_node = f"cred:{cred.id}"
                self.graph.add_node(
                    cred_node, 
                    type="credential", 
                    username=cred.username, 
                    privilege_level=cred.privilege_level,
                    cred_type=cred.cred_type
                )
                # User possesses credential
                self.graph.add_edge(user_node, cred_node, relation="owns_cred")
                self.graph.add_edge(cred_node, user_node, relation="belongs_to")

                # Credential to administrative target mapping
                if cred.privilege_level in ("administrator", "domain_admin"):
                    # Admin credential yields administrative access to hosts in its scope
                    # For simplicity, if it's domain_admin, it's admin on everything.
                    # If it's administrator, we map it to hosts (e.g., local admin)
                    for host_id, host in self.topo.hosts.items():
                        if cred.privilege_level == "domain_admin" or host.domain == user.domain:
                            host_node = f"host:{host_id}"
                            self.graph.add_edge(cred_node, host_node, relation="admin_access")

        # 2. Add Host nodes and sessions
        for host_id, host in self.topo.hosts.items():
            host_node = f"host:{host_id}"
            self.graph.add_node(
                host_node, 
                type="host", 
                host_id=host_id, 
                role=host.role, 
                domain=host.domain,
                compromised=host.compromised
            )
            
            # Active user sessions logged into the host
            for username in host.logged_in_users:
                user_node = f"user:{username}"
                if self.graph.has_node(user_node):
                    # Compromising the host allows stealing the session of the logged-in user
                    self.graph.add_edge(host_node, user_node, relation="has_session")
                    # User has interactive session / local credentials on host
                    self.graph.add_edge(user_node, host_node, relation="active_session")

        logger.info(
            f"Privilege Graph built: {self.graph.number_of_nodes()} nodes, "
            f"{self.graph.number_of_edges()} edges."
        )

    def rebuild(self):
        """Rebuilds the graph with the latest topology state."""
        self._build_graph()

    def find_escalation_path(self, start_node: str, target_node: str) -> Optional[List[Dict[str, Any]]]:
        """
        Finds the shortest privilege escalation path from start_node to target_node.
        Returns a list of edge details or None if no path exists.
        """
        if not self.graph.has_node(start_node) or not self.graph.has_node(target_node):
            return None
        
        try:
            path = nx.shortest_path(self.graph, start_node, target_node)
            path_details = []
            for i in range(len(path) - 1):
                u, v = path[i], path[i+1]
                edge_data = self.graph.get_edge_data(u, v)
                u_data = self.graph.nodes[u]
                v_data = self.graph.nodes[v]
                path_details.append({
                    "from_node": u,
                    "from_type": u_data.get("type"),
                    "to_node": v,
                    "to_type": v_data.get("type"),
                    "relation": edge_data.get("relation")
                })
            return path_details
        except nx.NetworkXNoPath:
            return None
        except Exception as e:
            logger.error(f"Error finding escalation path: {e}", exc_info=True)
            return None

    def get_high_risk_credentials(self) -> List[Dict[str, Any]]:
        """
        Identifies credentials that can lead directly or indirectly to domain compromise.
        Uses out-degree centrality on credential nodes targeting domain controllers or domain admin users.
        """
        high_risk = []
        # Find domain controllers
        dcs = [n for n, d in self.graph.nodes(data=True) if d.get("type") == "host" and d.get("role") == "domain_controller"]
        
        for cred_node, d in self.graph.nodes(data=True):
            if d.get("type") == "credential":
                reachable_dcs = 0
                for dc in dcs:
                    if nx.has_path(self.graph, cred_node, dc):
                        reachable_dcs += 1
                
                if reachable_dcs > 0:
                    high_risk.append({
                        "cred_id": cred_node.split(":")[-1],
                        "username": d.get("username"),
                        "privilege_level": d.get("privilege_level"),
                        "reachable_dcs": reachable_dcs
                    })
        
        return sorted(high_risk, key=lambda x: x["reachable_dcs"], reverse=True)
