import torch
import numpy as np
import logging
from typing import Dict, List, Tuple
from simulation_engine.network import NetworkTopology
from gnn_layer.models import GCNModel, GraphSAGEModel, GATModel
from gnn_layer.models_advanced import GINModel, GraphTransformerModel

logger = logging.getLogger(__name__)

class NetworkRiskPredictor:
    def __init__(self, model_type: str = "gcn", hidden_dim: int = 16):
        self.model_type = model_type
        
        # Features mapping dimension: [compromised, isolated, num_services, role_id] -> 4 features
        self.in_dim = 4
        self.out_dim = 1 # Probability of attack propagation / exploit risk
        
        if model_type == "sage":
            self.model = GraphSAGEModel(self.in_dim, hidden_dim, self.out_dim)
        elif model_type == "gat":
            self.model = GATModel(self.in_dim, hidden_dim, self.out_dim)
        elif model_type == "gin":
            self.model = GINModel(self.in_dim, hidden_dim, self.out_dim)
        elif model_type == "transformer":
            self.model = GraphTransformerModel(self.in_dim, hidden_dim, self.out_dim)
        else:
            self.model = GCNModel(self.in_dim, hidden_dim, self.out_dim)
            
        self.model.eval()

    def load_trained_model(self, file_path: str):
        """Loads trained weights from file."""
        try:
            self.model.load_state_dict(torch.load(file_path, map_location=torch.device('cpu')))
            self.model.eval()
            logger.info(f"Successfully loaded trained GNN model weights from {file_path}")
        except Exception as e:
            logger.error(f"Failed to load GNN model weights from {file_path}: {e}")

    def _role_to_id(self, role: str) -> float:
        roles = {"workstation": 0.1, "web_server": 0.5, "db_server": 0.7, "domain_controller": 1.0}
        return roles.get(role, 0.0)

    def extract_graph_tensors(self, topo: NetworkTopology) -> Tuple[torch.Tensor, torch.Tensor, List[str]]:
        """Converts simulator topology to nodes feature matrix X and adjacency matrix A."""
        host_ids = list(topo.hosts.keys())
        N = len(host_ids)
        
        if N == 0:
            return torch.zeros((0, self.in_dim)), torch.zeros((0, 0)), []

        # Construct Features Matrix X
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

        # Construct Adjacency Matrix A (with self-loops)
        A = torch.eye(N, dtype=torch.float32)
        host_index = {h_id: idx for idx, h_id in enumerate(host_ids)}
        
        for h1, h2 in topo.connections:
            if h1 in host_index and h2 in host_index:
                idx1, idx2 = host_index[h1], host_index[h2]
                A[idx1, idx2] = 1.0
                A[idx2, idx1] = 1.0 # Undirected graph model

        return X, A, host_ids

    def predict_risk_scores(self, topo: NetworkTopology) -> Dict[str, float]:
        """Runs the network GNN model to calculate security risk ratings for each host."""
        X, A, host_ids = self.extract_graph_tensors(topo)
        
        if len(host_ids) == 0:
            return {}

        with torch.no_grad():
            predictions = self.model(X, A)
            scores = predictions.squeeze(-1).tolist()
            
        if not isinstance(scores, list):
            scores = [scores]

        return {h_id: float(score) for h_id, score in zip(host_ids, scores)}
