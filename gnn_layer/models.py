import torch
import torch.nn as nn
import torch.nn.functional as F

class GCNLayer(nn.Module):
    """Simple GCN layer implementing message-passing propagation."""
    def __init__(self, in_features: int, out_features: int):
        super().__init__()
        self.linear = nn.Linear(in_features, out_features)

    def forward(self, x: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
        is_batched = (x.dim() == 3)
        sum_dim = 2 if is_batched else 1
        
        # Simple symmetric normalized adjacency message aggregation: D^-1/2 * A * D^-1/2 * X * W
        deg = torch.sum(adj, dim=sum_dim, keepdim=True)
        deg_inv_sqrt = torch.pow(deg + 1e-5, -0.5)
        adj_norm = adj * deg_inv_sqrt * deg_inv_sqrt.transpose(-1, -2)
        
        support = self.linear(x)
        if is_batched:
            output = torch.bmm(adj_norm, support)
        else:
            output = torch.mm(adj_norm, support)
        return output

class GCNModel(nn.Module):
    def __init__(self, in_dim: int, hidden_dim: int, out_dim: int, num_layers: int = 2, dropout: float = 0.0):
        super().__init__()
        self.dropout = dropout
        self.layers = nn.ModuleList()
        
        # Input layer
        self.layers.append(GCNLayer(in_dim, hidden_dim))
        
        # Hidden layers
        for _ in range(num_layers - 2):
            self.layers.append(GCNLayer(hidden_dim, hidden_dim))
            
        # Output layer
        self.layers.append(GCNLayer(hidden_dim, out_dim))

    def forward(self, x: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
        for layer in self.layers[:-1]:
            x = F.relu(layer(x, adj))
            if self.dropout > 0:
                x = F.dropout(x, p=self.dropout, training=self.training)
        x = self.layers[-1](x, adj)
        return torch.sigmoid(x)


class GraphSAGELayer(nn.Module):
    """Simple SAGE convolution layer with mean neighbor aggregation."""
    def __init__(self, in_features: int, out_features: int):
        super().__init__()
        self.linear_self = nn.Linear(in_features, out_features)
        self.linear_neigh = nn.Linear(in_features, out_features)

    def forward(self, x: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
        is_batched = (x.dim() == 3)
        sum_dim = 2 if is_batched else 1
        deg = torch.sum(adj, dim=sum_dim, keepdim=True) + 1e-5
        
        if is_batched:
            neigh_agg = torch.bmm(adj, x) / deg
        else:
            neigh_agg = torch.mm(adj, x) / deg
        
        out = self.linear_self(x) + self.linear_neigh(neigh_agg)
        return out

class GraphSAGEModel(nn.Module):
    def __init__(self, in_dim: int, hidden_dim: int, out_dim: int, num_layers: int = 2, dropout: float = 0.0):
        super().__init__()
        self.dropout = dropout
        self.layers = nn.ModuleList()
        
        self.layers.append(GraphSAGELayer(in_dim, hidden_dim))
        for _ in range(num_layers - 2):
            self.layers.append(GraphSAGELayer(hidden_dim, hidden_dim))
        self.layers.append(GraphSAGELayer(hidden_dim, out_dim))

    def forward(self, x: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
        for layer in self.layers[:-1]:
            x = F.relu(layer(x, adj))
            if self.dropout > 0:
                x = F.dropout(x, p=self.dropout, training=self.training)
        x = self.layers[-1](x, adj)
        return torch.sigmoid(x)


class GATLayer(nn.Module):
    """Basic Graph Attention Layer (single head)."""
    def __init__(self, in_features: int, out_features: int, alpha: float = 0.2):
        super().__init__()
        self.in_features = in_features
        self.out_features = out_features
        self.alpha = alpha
        
        self.W = nn.Linear(in_features, out_features, bias=False)
        self.a = nn.Linear(2 * out_features, 1, bias=False)

    def forward(self, x: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
        is_batched = (x.dim() == 3)
        if not is_batched:
            x = x.unsqueeze(0)
            adj = adj.unsqueeze(0)
            
        B, N, F_in = x.size()
        h = self.W(x) # [B, N, F_out]
        
        h_i = h.unsqueeze(2).repeat(1, 1, N, 1)
        h_j = h.unsqueeze(1).repeat(1, N, 1, 1)
        combinations = torch.cat([h_i, h_j], dim=-1)
        
        e = F.leaky_relu(self.a(combinations).squeeze(-1), negative_slope=self.alpha)
        
        zero_vec = -9e15 * torch.ones_like(e)
        attention = torch.where(adj > 0, e, zero_vec)
        attention = F.softmax(attention, dim=-1)
        
        h_prime = torch.matmul(attention, h)
        
        if not is_batched:
            h_prime = h_prime.squeeze(0)
            
        return h_prime

class GATModel(nn.Module):
    def __init__(self, in_dim: int, hidden_dim: int, out_dim: int, num_layers: int = 2, dropout: float = 0.0):
        super().__init__()
        self.dropout = dropout
        self.layers = nn.ModuleList()
        
        self.layers.append(GATLayer(in_dim, hidden_dim))
        for _ in range(num_layers - 2):
            self.layers.append(GATLayer(hidden_dim, hidden_dim))
        self.layers.append(GATLayer(hidden_dim, out_dim))

    def forward(self, x: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
        for layer in self.layers[:-1]:
            x = F.relu(layer(x, adj))
            if self.dropout > 0:
                x = F.dropout(x, p=self.dropout, training=self.training)
        x = self.layers[-1](x, adj)
        return torch.sigmoid(x)
