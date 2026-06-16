# inference/src/model.py
#
# Spatiotemporal Graph Autoencoder (ST-GAE)
#
# Architecture:
#   Encoder:  3× GATv2Conv (spatial) → GRU (temporal) → node embeddings [N, H]
#   Decoder:  MLP (feature reconstruction) + inner-product (edge reconstruction)
#
# Variable node counts across time steps are handled by padding to MAX_NODES
# with a validity mask, keeping the GRU state shape fixed.
#
# Dimensions (default config):
#   NODE_FEATURE_DIM  = 7
#   GAT_HEADS_L1      = 4   →  hidden = 4*16 = 64
#   GAT_HEADS_L2      = 4   →  hidden = 4*8  = 32
#   EMBEDDING_DIM     = 16  (post-GAT L3, single head)
#   GRU_HIDDEN        = 32
#   SEQ_LEN           = 10  (number of consecutive snapshots fed to GRU)

from __future__ import annotations
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATv2Conv
from torch_geometric.data import Data
from typing import List, Tuple

NODE_FEATURE_DIM = 7
GAT_HIDDEN_L1    = 64   # 4 heads × 16
GAT_HIDDEN_L2    = 32   # 4 heads × 8
EMBEDDING_DIM    = 16
GRU_HIDDEN       = 32
SEQ_LEN          = 10
MAX_NODES        = 256  # must match aggregator config

# ─────────────────────────────────────────────────────────────────────────────
# Spatial Encoder: GATv2Conv × 3
# ─────────────────────────────────────────────────────────────────────────────

class SpatialEncoder(nn.Module):
    """Encodes a single graph snapshot into per-node embeddings."""

    def __init__(self):
        super().__init__()
        self.conv1 = GATv2Conv(
            NODE_FEATURE_DIM, 16,
            heads=4, concat=True, add_self_loops=True,
        )  # → [N, 64]
        self.conv2 = GATv2Conv(
            64, 8,
            heads=4, concat=True, add_self_loops=True,
        )  # → [N, 32]
        self.conv3 = GATv2Conv(
            32, EMBEDDING_DIM,
            heads=1, concat=False, add_self_loops=True,
        )  # → [N, 16]
        self.norm1 = nn.LayerNorm(64)
        self.norm2 = nn.LayerNorm(32)
        self.dropout = nn.Dropout(0.1)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x:          Node feature matrix  [N, NODE_FEATURE_DIM]
            edge_index: COO edge list         [2, E]
        Returns:
            z:          Node embeddings       [N, EMBEDDING_DIM]
        """
        x = F.elu(self.norm1(self.conv1(x, edge_index)))
        x = self.dropout(x)
        x = F.elu(self.norm2(self.conv2(x, edge_index)))
        z = self.conv3(x, edge_index)         # no activation — raw embedding
        return z

# ─────────────────────────────────────────────────────────────────────────────
# Temporal Encoder: per-node GRU over SEQ_LEN snapshots
# ─────────────────────────────────────────────────────────────────────────────

class TemporalEncoder(nn.Module):
    """Encodes a sequence of spatial embeddings into a single temporal state."""

    def __init__(self):
        super().__init__()
        # Input:  [SEQ_LEN, MAX_NODES, EMBEDDING_DIM]  (batch_first=False)
        # Output: [MAX_NODES, GRU_HIDDEN]
        self.gru = nn.GRU(
            input_size=EMBEDDING_DIM,
            hidden_size=GRU_HIDDEN,
            num_layers=2,
            batch_first=False,
            dropout=0.1,
        )

    def forward(self, z_seq: torch.Tensor) -> torch.Tensor:
        """
        Args:
            z_seq: [SEQ_LEN, MAX_NODES, EMBEDDING_DIM]
        Returns:
            h:     [MAX_NODES, GRU_HIDDEN]
        """
        # GRU treats dimension 1 as batch (each node is independent in time)
        output, hidden = self.gru(z_seq)  # hidden: [num_layers, MAX_NODES, GRU_HIDDEN]
        return hidden[-1]  # last layer: [MAX_NODES, GRU_HIDDEN]

# ─────────────────────────────────────────────────────────────────────────────
# Feature Decoder: MLP from temporal embedding back to node features
# ─────────────────────────────────────────────────────────────────────────────

class FeatureDecoder(nn.Module):
    def __init__(self):
        super().__init__()
        self.mlp = nn.Sequential(
            nn.Linear(GRU_HIDDEN, 64),
            nn.ELU(),
            nn.Linear(64, 32),
            nn.ELU(),
            nn.Linear(32, NODE_FEATURE_DIM),
        )

    def forward(self, h: torch.Tensor) -> torch.Tensor:
        """
        Args:  h:  [N, GRU_HIDDEN]
        Returns:   [N, NODE_FEATURE_DIM]
        """
        return self.mlp(h)

# ─────────────────────────────────────────────────────────────────────────────
# Edge Decoder: inner-product decoder for adjacency reconstruction
# ─────────────────────────────────────────────────────────────────────────────

class EdgeDecoder(nn.Module):
    """
    Reconstructs edge probabilities from node embeddings.
    For efficiency, only reconstructs the edges present in edge_index
    (sparse evaluation) rather than the full N×N matrix.
    """

    def forward(
        self,
        h: torch.Tensor,
        edge_index: torch.Tensor,
    ) -> torch.Tensor:
        """
        Args:
            h:          [N, GRU_HIDDEN]
            edge_index: [2, E]
        Returns:
            edge_probs: [E]  sigmoid(h_src · h_dst)
        """
        if edge_index.shape[1] == 0:
            return torch.zeros(0, device=h.device)
        src, dst = edge_index
        dot = (h[src] * h[dst]).sum(dim=-1)
        return torch.sigmoid(dot)

# ─────────────────────────────────────────────────────────────────────────────
# Full ST-GAE
# ─────────────────────────────────────────────────────────────────────────────

class SpatiotemporalAutoencoder(nn.Module):
    """
    End-to-end Spatiotemporal Graph Autoencoder.

    Usage (inference):
        model = SpatiotemporalAutoencoder().eval()
        x_recon, edge_probs, node_errors = model.reconstruct(graph_sequence)
    """

    def __init__(self):
        super().__init__()
        self.spatial_enc  = SpatialEncoder()
        self.temporal_enc = TemporalEncoder()
        self.feat_dec     = FeatureDecoder()
        self.edge_dec     = EdgeDecoder()

    # ─── Internal: encode a list of PyG Data objects into temporal state ───

    def _encode_sequence(
        self,
        graphs: List[Data],
        device: torch.device,
    ) -> Tuple[torch.Tensor, Data]:
        """
        Encodes SEQ_LEN graphs spatially, pads to MAX_NODES, runs GRU.

        Returns:
            h:            [MAX_NODES, GRU_HIDDEN] temporal state
            current_graph: the last graph in the sequence (for reconstruction targets)
        """
        assert len(graphs) == SEQ_LEN, f"Expected {SEQ_LEN} graphs, got {len(graphs)}"

        spatial_seq = []
        for g in graphs:
            g = g.to(device)
            if g.num_nodes == 0:
                z = torch.zeros(1, EMBEDDING_DIM, device=device)
            else:
                z = self.spatial_enc(g.x, g.edge_index)  # [N_t, EMBEDDING_DIM]

            # Pad/truncate to MAX_NODES
            padded = torch.zeros(MAX_NODES, EMBEDDING_DIM, device=device)
            n = min(z.shape[0], MAX_NODES)
            padded[:n] = z[:n]
            spatial_seq.append(padded)

        # Stack to [SEQ_LEN, MAX_NODES, EMBEDDING_DIM]
        z_seq = torch.stack(spatial_seq, dim=0)

        # Temporal encoding → [MAX_NODES, GRU_HIDDEN]
        h = self.temporal_enc(z_seq)

        return h, graphs[-1].to(device)

    # ─── Forward pass (training) ───────────────────────────────────────────

    def forward(
        self,
        graphs: List[Data],
        device: torch.device,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Returns:
            x_recon:    [N_current, NODE_FEATURE_DIM]  reconstructed features
            edge_probs: [E_current]                     reconstructed edge probabilities
        """
        h, g_curr = self._encode_sequence(graphs, device)
        n = min(g_curr.num_nodes, MAX_NODES)

        x_recon    = self.feat_dec(h[:n])
        edge_probs = self.edge_dec(h[:n], g_curr.edge_index)
        return x_recon, edge_probs

    # ─── Inference mode: compute per-node reconstruction errors ────────────

    @torch.no_grad()
    def reconstruct(
        self,
        graphs: List[Data],
        device: torch.device,
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Returns:
            x_recon:     [N, NODE_FEATURE_DIM]
            edge_probs:  [E]
            node_errors: [N]  per-node MSE reconstruction error
        """
        h, g_curr = self._encode_sequence(graphs, device)
        n = min(g_curr.num_nodes, MAX_NODES)
        x_recon    = self.feat_dec(h[:n])
        edge_probs = self.edge_dec(h[:n], g_curr.edge_index)

        x_target   = g_curr.x[:n]
        node_errors = F.mse_loss(x_recon, x_target, reduction='none').mean(dim=1)

        return x_recon, edge_probs, node_errors

# ─────────────────────────────────────────────────────────────────────────────
# Loss function
# ─────────────────────────────────────────────────────────────────────────────

def compute_loss(
    x_recon:    torch.Tensor,  # [N, F]
    x_target:   torch.Tensor,  # [N, F]
    edge_probs: torch.Tensor,  # [E]
    edge_index: torch.Tensor,  # [2, E]
    num_nodes:  int,
    alpha:      float = 0.7,   # weight for feature loss
    beta:       float = 0.3,   # weight for structure loss
) -> torch.Tensor:
    feat_loss = F.mse_loss(x_recon, x_target)

    # Edge targets: 1 for observed edges (all entries in edge_index are real)
    edge_targets = torch.ones(edge_probs.shape[0], device=edge_probs.device)
    if edge_probs.shape[0] > 0:
        struct_loss  = F.binary_cross_entropy(edge_probs, edge_targets)
    else:
        struct_loss = torch.tensor(0.0, device=edge_probs.device)

    return alpha * feat_loss + beta * struct_loss
