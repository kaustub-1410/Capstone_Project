"""
Attack Graph Module — Computes all viable attack paths, scores them,
identifies critical chokepoints, and exports graph data for visualization.
"""

import heapq
import logging
from typing import Dict, List, Tuple, Optional, Set, Any
from collections import defaultdict
from simulation_engine.network import NetworkTopology
from shared.models import Host

logger = logging.getLogger(__name__)


class AttackPath:
    """Represents a single attack path through the network."""
    def __init__(self, nodes: List[str], total_weight: float, hops: int):
        self.nodes = nodes
        self.total_weight = total_weight
        self.hops = hops
        self.escalation_points: List[str] = []  # Nodes where privilege escalation occurs
        self.vulnerability_chain: List[Dict[str, Any]] = []  # CVEs exploited along the path

    @property
    def risk_score(self) -> float:
        """Composite risk score: lower weight + fewer hops + more escalation = higher risk."""
        base = 1.0 / (self.total_weight + 0.01)
        hop_penalty = max(0.5, 1.0 - (self.hops * 0.05))
        escalation_bonus = 1.0 + (len(self.escalation_points) * 0.3)
        return round(base * hop_penalty * escalation_bonus, 4)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": self.nodes,
            "total_weight": round(self.total_weight, 4),
            "hops": self.hops,
            "risk_score": self.risk_score,
            "escalation_points": self.escalation_points,
            "vulnerability_chain": self.vulnerability_chain
        }


class AttackGraph:
    """
    Builds and analyzes a weighted directed attack graph from the network topology.
    
    Nodes = hosts. Edges = network connections weighted by exploitability.
    Lower edge weight = easier to traverse (more vulnerabilities, weaker defenses).
    """

    def __init__(self, topo: NetworkTopology):
        self.topo = topo
        self.adjacency: Dict[str, List[Tuple[str, float]]] = defaultdict(list)
        self.edge_metadata: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._build_graph()

    # ------------------------------------------------------------------ #
    #  Graph Construction
    # ------------------------------------------------------------------ #

    def _compute_edge_weight(self, source: Host, target: Host) -> float:
        """
        Compute traversal difficulty from source → target.
        Lower weight = easier to compromise (higher risk).
        
        Factors:
        - Number of vulnerabilities on target (more vulns → lower weight)
        - Target role importance (DCs are higher value but harder to reach)
        - Isolation status (isolated hosts → very high weight)
        - Already compromised (compromised → near-zero weight)
        """
        if target.isolated:
            return 100.0  # Effectively unreachable

        if target.compromised:
            return 0.01  # Already owned, trivial to traverse

        total_vulns = sum(len(s.vulnerabilities) for s in target.services)
        num_services = len(target.services)

        # Base weight inversely proportional to vulnerability exposure
        vuln_factor = 1.0 / (total_vulns + 0.1)

        # Service exposure factor: more services = more attack surface
        service_factor = 1.0 / (num_services + 0.5)

        # Role-based difficulty multiplier
        role_difficulty = {
            "workstation": 0.8,
            "web_server": 1.0,
            "db_server": 1.5,
            "file_server": 1.2,
            "domain_controller": 2.0
        }
        role_mult = role_difficulty.get(target.role, 1.0)

        weight = (vuln_factor + service_factor) * role_mult
        return max(0.01, round(weight, 4))

    def _build_graph(self):
        """Construct the weighted adjacency list from topology connections."""
        self.adjacency.clear()
        self.edge_metadata.clear()

        for h1_id, h2_id in self.topo.connections:
            h1 = self.topo.hosts.get(h1_id)
            h2 = self.topo.hosts.get(h2_id)
            if not h1 or not h2:
                continue

            # Bidirectional edges with potentially different weights
            w_forward = self._compute_edge_weight(h1, h2)
            w_backward = self._compute_edge_weight(h2, h1)

            self.adjacency[h1_id].append((h2_id, w_forward))
            self.adjacency[h2_id].append((h1_id, w_backward))

            # Store metadata for each edge
            target_vulns = []
            for s in h2.services:
                target_vulns.extend(s.vulnerabilities)
            self.edge_metadata[(h1_id, h2_id)] = {
                "weight": w_forward,
                "target_vulnerabilities": target_vulns,
                "target_services": [s.name for s in h2.services]
            }

            source_vulns = []
            for s in h1.services:
                source_vulns.extend(s.vulnerabilities)
            self.edge_metadata[(h2_id, h1_id)] = {
                "weight": w_backward,
                "target_vulnerabilities": source_vulns,
                "target_services": [s.name for s in h1.services]
            }

        logger.info(f"Attack graph built: {len(self.topo.hosts)} nodes, "
                     f"{sum(len(v) for v in self.adjacency.values())} directed edges")

    def rebuild(self):
        """Rebuild graph after topology state changes (compromises, isolations, patches)."""
        self._build_graph()

    # ------------------------------------------------------------------ #
    #  Path Finding Algorithms
    # ------------------------------------------------------------------ #

    def find_optimal_path(self, source_id: str, target_id: str) -> Optional[AttackPath]:
        """
        Dijkstra's algorithm to find the lowest-weight (easiest) path
        from source to target.
        """
        if source_id not in self.topo.hosts or target_id not in self.topo.hosts:
            return None

        distances: Dict[str, float] = {h_id: float('inf') for h_id in self.topo.hosts}
        distances[source_id] = 0.0
        predecessors: Dict[str, Optional[str]] = {h_id: None for h_id in self.topo.hosts}
        visited: Set[str] = set()

        heap = [(0.0, source_id)]

        while heap:
            dist, current = heapq.heappop(heap)

            if current in visited:
                continue
            visited.add(current)

            if current == target_id:
                break

            for neighbor, weight in self.adjacency.get(current, []):
                if neighbor in visited:
                    continue
                new_dist = dist + weight
                if new_dist < distances[neighbor]:
                    distances[neighbor] = new_dist
                    predecessors[neighbor] = current
                    heapq.heappush(heap, (new_dist, neighbor))

        # Reconstruct path
        if distances[target_id] == float('inf'):
            return None

        path_nodes = []
        current = target_id
        while current is not None:
            path_nodes.append(current)
            current = predecessors[current]
        path_nodes.reverse()

        attack_path = AttackPath(
            nodes=path_nodes,
            total_weight=distances[target_id],
            hops=len(path_nodes) - 1
        )

        # Annotate with vulnerability chain and escalation points
        for i in range(len(path_nodes) - 1):
            src, tgt = path_nodes[i], path_nodes[i + 1]
            edge_data = self.edge_metadata.get((src, tgt), {})
            target_host = self.topo.hosts.get(tgt)

            if edge_data.get("target_vulnerabilities"):
                attack_path.vulnerability_chain.append({
                    "from": src,
                    "to": tgt,
                    "cves": edge_data["target_vulnerabilities"],
                    "services": edge_data.get("target_services", [])
                })

            if target_host and target_host.role in ("domain_controller", "db_server"):
                attack_path.escalation_points.append(tgt)

        return attack_path

    def find_all_attack_paths(self, source_id: str, target_id: str,
                               max_depth: int = 10) -> List[AttackPath]:
        """
        DFS enumeration of all simple paths from source to target,
        with depth cutoff to prevent combinatorial explosion.
        """
        if source_id not in self.topo.hosts or target_id not in self.topo.hosts:
            return []

        all_paths: List[AttackPath] = []
        self._dfs_paths(source_id, target_id, set(), [source_id], 0.0, max_depth, all_paths)

        # Sort by risk score (highest risk first)
        all_paths.sort(key=lambda p: p.risk_score, reverse=True)
        return all_paths

    def _dfs_paths(self, current: str, target: str, visited: Set[str],
                    path: List[str], weight: float, max_depth: int,
                    results: List[AttackPath]):
        """Recursive DFS helper for path enumeration."""
        if len(path) - 1 >= max_depth:
            return

        if current == target:
            attack_path = AttackPath(
                nodes=list(path),
                total_weight=weight,
                hops=len(path) - 1
            )
            # Annotate escalation points
            for node in path:
                host = self.topo.hosts.get(node)
                if host and host.role in ("domain_controller", "db_server"):
                    attack_path.escalation_points.append(node)
            results.append(attack_path)
            return

        visited.add(current)
        for neighbor, edge_weight in self.adjacency.get(current, []):
            if neighbor not in visited:
                path.append(neighbor)
                self._dfs_paths(neighbor, target, visited, path,
                               weight + edge_weight, max_depth, results)
                path.pop()
        visited.discard(current)

    # ------------------------------------------------------------------ #
    #  Strategic Analysis
    # ------------------------------------------------------------------ #

    def get_attack_surface(self) -> List[str]:
        """
        Returns all hosts reachable from external-facing services
        (web servers and any host with HTTP/HTTPS services).
        """
        entry_points = []
        for host in self.topo.hosts.values():
            if host.role == "web_server":
                entry_points.append(host.id)
            elif any(s.name in ("HTTP", "HTTPS") for s in host.services):
                entry_points.append(host.id)

        reachable: Set[str] = set()
        for entry in entry_points:
            self._bfs_reachable(entry, reachable)

        return sorted(reachable)

    def _bfs_reachable(self, start: str, visited: Set[str]):
        """BFS to find all hosts reachable from a starting node."""
        queue = [start]
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            for neighbor, _ in self.adjacency.get(current, []):
                if neighbor not in visited:
                    queue.append(neighbor)

    def get_critical_chokepoints(self, target_id: str = "DC-01") -> List[Dict[str, Any]]:
        """
        Identifies hosts that appear on more than 50% of all attack paths
        to the target (typically the Domain Controller).
        These are high-value isolation targets for defenders.
        """
        # Find all paths from every entry point to the target
        entry_points = self.get_attack_surface()
        all_paths: List[AttackPath] = []

        for entry in entry_points:
            if entry != target_id:
                paths = self.find_all_attack_paths(entry, target_id, max_depth=8)
                all_paths.extend(paths)

        if not all_paths:
            return []

        # Count how many paths each intermediate host appears on
        appearance_count: Dict[str, int] = defaultdict(int)
        for path in all_paths:
            # Exclude source and target from chokepoint analysis
            for node in path.nodes[1:-1]:
                appearance_count[node] += 1

        total_paths = len(all_paths)
        chokepoints = []
        for host_id, count in appearance_count.items():
            ratio = count / total_paths
            if ratio >= 0.3:  # 30% threshold for chokepoint status
                host = self.topo.hosts.get(host_id)
                chokepoints.append({
                    "host_id": host_id,
                    "host_role": host.role if host else "unknown",
                    "path_coverage": round(ratio * 100, 1),
                    "total_paths_through": count,
                    "criticality": "CRITICAL" if ratio >= 0.7 else "HIGH" if ratio >= 0.5 else "MEDIUM"
                })

        # Sort by coverage percentage descending
        chokepoints.sort(key=lambda c: c["path_coverage"], reverse=True)
        return chokepoints

    def get_host_risk_summary(self) -> List[Dict[str, Any]]:
        """
        For each host, compute aggregate attack graph metrics:
        - Number of paths through this host
        - Average edge weight to neighbors
        - Whether it's an entry point
        - Whether it's a chokepoint
        """
        summary = []
        entry_points = set(self.get_attack_surface())
        chokepoints = {c["host_id"] for c in self.get_critical_chokepoints()}

        for host_id, host in self.topo.hosts.items():
            neighbors = self.adjacency.get(host_id, [])
            avg_weight = sum(w for _, w in neighbors) / max(len(neighbors), 1)
            total_vulns = sum(len(s.vulnerabilities) for s in host.services)

            summary.append({
                "host_id": host_id,
                "role": host.role,
                "compromised": host.compromised,
                "isolated": host.isolated,
                "total_vulnerabilities": total_vulns,
                "num_connections": len(neighbors),
                "avg_edge_weight": round(avg_weight, 4),
                "is_entry_point": host_id in entry_points,
                "is_chokepoint": host_id in chokepoints
            })

        return summary

    def compute_critical_nodes(self) -> List[Tuple[str, float]]:
        """
        Computes betweenness centrality of nodes in the attack graph.
        Returns a list of (host_id, centrality_score) sorted descending by score.
        """
        import networkx as nx
        g = nx.DiGraph()
        for host_id in self.topo.hosts:
            g.add_node(host_id)
        for src, neighbors in self.adjacency.items():
            for dst, weight in neighbors:
                # In betweenness centrality, weight typically represents distance,
                # which aligns with our weight (higher weight = harder to compromise / more distance).
                g.add_edge(src, dst, weight=weight)
        
        centrality = nx.betweenness_centrality(g, weight="weight")
        sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
        return [(str(k), float(v)) for k, v in sorted_nodes]

    def highest_value_assets(self, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Identifies and ranks the highest-value assets in the network topology.
        """
        assets = []
        for host_id, host in self.topo.hosts.items():
            assets.append({
                "host_id": host_id,
                "role": host.role,
                "asset_value": getattr(host, "asset_value", 0.0),
                "sensitivity_level": getattr(host, "sensitivity_level", "low")
            })
        assets.sort(key=lambda x: x["asset_value"], reverse=True)
        return assets[:limit]

    # ------------------------------------------------------------------ #
    #  Export
    # ------------------------------------------------------------------ #

    def export_to_json(self) -> Dict[str, Any]:
        """Serialize the full attack graph for frontend visualization."""
        nodes = []
        for host_id, host in self.topo.hosts.items():
            total_vulns = sum(len(s.vulnerabilities) for s in host.services)
            nodes.append({
                "id": host_id,
                "name": host.name,
                "ip": host.ip,
                "role": host.role,
                "compromised": host.compromised,
                "isolated": host.isolated,
                "vulnerability_count": total_vulns,
                "services": [{"name": s.name, "port": s.port} for s in host.services]
            })

        edges = []
        for (src, tgt), metadata in self.edge_metadata.items():
            edges.append({
                "source": src,
                "target": tgt,
                "weight": metadata["weight"],
                "target_vulnerabilities": metadata.get("target_vulnerabilities", []),
                "target_services": metadata.get("target_services", [])
            })

        # Find DC for default target
        dc_ids = [h.id for h in self.topo.hosts.values() if h.role == "domain_controller"]
        target_id = dc_ids[0] if dc_ids else None

        # Compute top-5 optimal paths from each entry point
        top_paths = []
        if target_id:
            for entry in self.get_attack_surface():
                if entry != target_id:
                    path = self.find_optimal_path(entry, target_id)
                    if path:
                        top_paths.append(path.to_dict())
            # Sort by risk score, take top 5
            top_paths.sort(key=lambda p: p["risk_score"], reverse=True)
            top_paths = top_paths[:5]

        chokepoints = self.get_critical_chokepoints(target_id) if target_id else []

        return {
            "nodes": nodes,
            "edges": edges,
            "attack_paths": top_paths,
            "chokepoints": chokepoints,
            "attack_surface": self.get_attack_surface(),
            "target": target_id
        }
