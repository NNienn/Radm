import sys
from pathlib import Path
# Add the inference/src directory to sys.path so model can be imported
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "inference" / "src"))

import torch
import pytest
from torch_geometric.data import Data
from model import (
    SpatiotemporalAutoencoder, compute_loss,
    NODE_FEATURE_DIM, MAX_NODES, SEQ_LEN, GRU_HIDDEN, EMBEDDING_DIM
)

def make_random_graph(n_nodes=10, n_edges=15):
    x = torch.rand(n_nodes, NODE_FEATURE_DIM)
    src = torch.randint(0, n_nodes, (n_edges,))
    dst = torch.randint(0, n_nodes, (n_edges,))
    return Data(x=x, edge_index=torch.stack([src, dst]), num_nodes=n_nodes)

def make_sequence(T=SEQ_LEN, n_nodes=10):
    return [make_random_graph(n_nodes) for _ in range(T)]

def test_spatial_encoder_output_shape():
    from model import SpatialEncoder
    enc = SpatialEncoder()
    g = make_random_graph()
    z = enc(g.x, g.edge_index)
    assert z.shape == (g.num_nodes, EMBEDDING_DIM)

def test_temporal_encoder_output_shape():
    from model import TemporalEncoder
    enc = TemporalEncoder()
    z_seq = torch.rand(SEQ_LEN, MAX_NODES, EMBEDDING_DIM)
    h = enc(z_seq)
    assert h.shape == (MAX_NODES, GRU_HIDDEN)

def test_full_forward_pass():
    model = SpatiotemporalAutoencoder()
    seq = make_sequence()
    x_recon, edge_probs = model(seq, torch.device("cpu"))
    assert x_recon.shape[1] == NODE_FEATURE_DIM
    assert edge_probs.shape[0] == seq[-1].num_edges

def test_loss_backward():
    model = SpatiotemporalAutoencoder()
    seq = make_sequence()
    x_recon, edge_probs = model(seq, torch.device("cpu"))
    g = seq[-1]
    loss = compute_loss(x_recon, g.x, edge_probs, g.edge_index, g.num_nodes)
    loss.backward()
    # Verify gradients exist
    for p in model.parameters():
        assert p.grad is not None

def test_reconstruct_no_grad():
    model = SpatiotemporalAutoencoder().eval()
    seq = make_sequence()
    x_recon, edge_probs, node_errors = model.reconstruct(seq, torch.device("cpu"))
    assert node_errors.shape[0] <= MAX_NODES
    assert (node_errors >= 0).all()

def test_variable_node_counts():
    """Ensure model handles sequences with different node counts per snapshot."""
    model = SpatiotemporalAutoencoder().eval()
    seq = [make_random_graph(n_nodes=n) for n in [5, 8, 12, 7, 10, 15, 9, 11, 6, 13]]
    assert len(seq) == SEQ_LEN
    x_recon, _, _ = model.reconstruct(seq, torch.device("cpu"))
    assert x_recon.shape[1] == NODE_FEATURE_DIM
