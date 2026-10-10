"""
Datasets Module — Cyber security graph dataset loaders.
Converts simulator NetworkTopology snapshots into PyTorch and PyTorch Geometric data structures
for GNN model training and validation.
"""

import logging
from typing import List, Tuple, Dict, Any, Optional
import torch
from torch.utils.data import Dataset
from shared.models import Host
from simulation_engine.network import NetworkTopology

logger = logging.getLogger(__name__)

class CyberSecurityDataset(Dataset):
    """
    Dataset representing security snapshots of network graphs.
    Enables training GNNs for risk propagation and classification tasks.
    """

    def __init__(self, snapshots: List[NetworkTopology], num_classes: int = 1):
        self.snapshots = snapshots
        self.num_classes = num_classes
        self.in_dim = 4 # [compromised, isolated, num_services, role_id]

    def _role_to_id(self, role: str) -> float:
        roles = {"workstation": 0.1, "web_server": 0.5, "db_server": 0.7, "domain_controller": 1.0}
        return roles.get(role, 0.0)

    def topology_to_tensors(self, topo: NetworkTopology) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Converts a single NetworkTopology to node features, edge_index (COO format), and labels.
        """
        host_ids = list(topo.hosts.keys())
        N = len(host_ids)
        
        if N == 0:
            return torch.zeros((0, self.in_dim)), torch.zeros((2, 0), dtype=torch.long), torch.zeros((0, 1))

        # Node Features X
        x_data = []
        for h_id in host_ids:
            host = topo.hosts[h_id]
            x_data.append([
                1.0 if host.compromised else 0.0,
                1.0 if host.isolated else 0.0,
                float(len(host.services)),
                self._role_to_id(host.role)
            ])
        X = torch.tensor(x_data, dtype=torch.float32)

        # Labels Y: we define risk as whether a node is compromised or directly connected to a compromised node
        y_data = []
        compromised_ids = {h_id for h_id, h in topo.hosts.items() if h.compromised}
        for h_id in host_ids:
            host = topo.hosts[h_id]
            is_risk = 0.0
            if host.compromised:
                is_risk = 1.0
            else:
                # Check direct neighbors
                for h1, h2 in topo.connections:
                    if (h1 == h_id and h2 in compromised_ids) or (h2 == h_id and h1 in compromised_ids):
                        is_risk = 0.8
                        break
            y_data.append([is_risk])
        Y = torch.tensor(y_data, dtype=torch.float32)

        # Edge Index in COO format for PyTorch Geometric
        host_index = {h_id: idx for idx, h_id in enumerate(host_ids)}
        edge_list = []
        for h1, h2 in topo.connections:
            if h1 in host_index and h2 in host_index:
                idx1, idx2 = host_index[h1], host_index[h2]
                # Undirected graph: add both directions
                edge_list.append([idx1, idx2])
                edge_list.append([idx2, idx1])

        # Self-loops
        for i in range(N):
            edge_list.append([i, i])

        if edge_list:
            edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous()
        else:
            edge_index = torch.zeros((2, 0), dtype=torch.long)

        return X, edge_index, Y

    def __len__(self) -> int:
        return len(self.snapshots)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        topo = self.snapshots[idx]
        X, edge_index, Y = self.topology_to_tensors(topo)
        
        # Format as adjacency matrix for existing models, and COO for PyG models
        N = X.size(0)
        adj = torch.zeros((N, N), dtype=torch.float32)
        if edge_index.size(1) > 0:
            adj[edge_index[0], edge_index[1]] = 1.0

        return {
            "x": X,
            "edge_index": edge_index,
            "adj": adj,
            "y": Y
        }
