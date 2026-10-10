"""
Advanced GNN Models — Implementations of Graph Isomorphism Network (GIN)
and Graph Transformer models.
Implemented in pure PyTorch to ensure cross-platform compatibility and zero dependencies on pre-compiled PyG binaries.
Supports both batched and unbatched inputs.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F

class GINLayer(nn.Module):
    """
    Graph Isomorphism Network (GIN) Layer.
    Uses an MLP to process the aggregated neighbor features.
    """
    def __init__(self, in_features: int, out_features: int, eps: float = 0.0):
        super().__init__()
        self.eps = nn.Parameter(torch.tensor([eps]))
        self.mlp = nn.Sequential(
            nn.Linear(in_features, out_features),
            nn.ReLU(),
            nn.Linear(out_features, out_features)
        )

    def forward(self, x: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
        is_batched = (x.dim() == 3)
        if is_batched:
            neighbor_sum = torch.bmm(adj, x)
        else:
            neighbor_sum = torch.mm(adj, x)
        
        out = (1.0 + self.eps) * x + neighbor_sum
        return self.mlp(out)

class GINModel(nn.Module):
    def __init__(self, in_dim: int, hidden_dim: int, out_dim: int, num_layers: int = 2):
        super().__init__()
        self.layers = nn.ModuleList()
        self.layers.append(GINLayer(in_dim, hidden_dim))
        for _ in range(num_layers - 2):
            self.layers.append(GINLayer(hidden_dim, hidden_dim))
        self.layers.append(GINLayer(hidden_dim, out_dim))
        
    def forward(self, x: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
        for layer in self.layers[:-1]:
            x = F.relu(layer(x, adj))
        x = self.layers[-1](x, adj)
        return torch.sigmoid(x)


class GraphTransformerLayer(nn.Module):
    """
    Graph Transformer Layer using Multi-Head Attention over graph neighbors.
    """
    def __init__(self, in_features: int, out_features: int, num_heads: int = 2):
        super().__init__()
        self.in_features = in_features
        self.out_features = out_features
        self.num_heads = num_heads
        self.head_dim = out_features // num_heads
        
        assert out_features % num_heads == 0, "out_features must be divisible by num_heads"
        
        self.q_proj = nn.Linear(in_features, out_features, bias=False)
        self.key_proj = nn.Linear(in_features, out_features, bias=False)
        self.v_proj = nn.Linear(in_features, out_features, bias=False)
        self.out_proj = nn.Linear(out_features, out_features)
        
    def forward(self, x: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
        is_batched = (x.dim() == 3)
        if not is_batched:
            x = x.unsqueeze(0)
            adj = adj.unsqueeze(0)
            
        B, N, F_in = x.size()
        
        # Project queries, keys, values
        q = self.q_proj(x).view(B, N, self.num_heads, self.head_dim).transpose(1, 2) # [B, heads, N, head_dim]
        k = self.key_proj(x).view(B, N, self.num_heads, self.head_dim).transpose(1, 2)
        v = self.v_proj(x).view(B, N, self.num_heads, self.head_dim).transpose(1, 2)
        
        # Scaled dot-product attention
        scores = torch.matmul(q, k.transpose(-2, -1)) / (self.head_dim ** 0.5) # [B, heads, N, N]
        
        # Mask out non-neighbors
        mask = (adj == 0).unsqueeze(1).repeat(1, self.num_heads, 1, 1)
        scores = scores.masked_fill(mask, -9e15)
        
        attn = F.softmax(scores, dim=-1)
        out = torch.matmul(attn, v) # [B, heads, N, head_dim]
        
        # Concatenate heads
        out = out.transpose(1, 2).contiguous().view(B, N, self.out_features)
        out = self.out_proj(out)
        
        if not is_batched:
            out = out.squeeze(0)
            
        return out

class GraphTransformerModel(nn.Module):
    def __init__(self, in_dim: int, hidden_dim: int, out_dim: int, num_layers: int = 2, num_heads: int = 2):
        super().__init__()
        self.layers = nn.ModuleList()
        self.layers.append(GraphTransformerLayer(in_dim, hidden_dim, num_heads))
        for _ in range(num_layers - 2):
            self.layers.append(GraphTransformerLayer(hidden_dim, hidden_dim, num_heads))
        self.layers.append(GraphTransformerLayer(hidden_dim, out_dim, num_heads=1))
        
    def forward(self, x: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
        for layer in self.layers[:-1]:
            x = F.relu(layer(x, adj))
        x = self.layers[-1](x, adj)
        return torch.sigmoid(x)
