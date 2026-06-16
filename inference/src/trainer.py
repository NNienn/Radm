"""Offline training loop for the RADM anomaly detector."""

from __future__ import annotations

import argparse
import logging
import pathlib
import pickle

import numpy as np
import torch
import torch.optim as optim
from sklearn.ensemble import IsolationForest

from model import MAX_NODES, SEQ_LEN, SpatiotemporalAutoencoder, compute_loss

log = logging.getLogger(__name__)


def load_baseline_sequences(data_dir: pathlib.Path, seq_len: int = SEQ_LEN):
    files = sorted(data_dir.glob("snapshot_*.pkl"))
    log.info("Loaded %s baseline snapshots from %s", len(files), data_dir)
    graphs = [pickle.loads(file.read_bytes()) for file in files]

    sequences = []
    for index in range(max(len(graphs) - seq_len + 1, 0)):
        sequences.append(graphs[index : index + seq_len])
    return sequences


def train(config: dict, device: torch.device):
    data_dir = pathlib.Path(config["baseline_data_dir"])
    checkpoint = pathlib.Path(config["checkpoint_path"])
    epochs = int(config.get("epochs", 50))
    learning_rate = float(config.get("learning_rate", 1e-3))

    sequences = load_baseline_sequences(data_dir)
    if not sequences:
        raise RuntimeError(f"No baseline sequences found in {data_dir}")

    model = SpatiotemporalAutoencoder().to(device)
    optimizer = optim.Adam(model.parameters(), lr=learning_rate, weight_decay=1e-5)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=max(epochs, 1))

    model.train()
    for epoch in range(1, epochs + 1):
        epoch_loss = 0.0
        for sequence in sequences:
            optimizer.zero_grad()
            x_recon, edge_probs = model(sequence, device)
            current_graph = sequence[-1].to(device)
            node_count = min(current_graph.num_nodes, MAX_NODES)
            loss = compute_loss(x_recon, current_graph.x[:node_count], edge_probs, current_graph.edge_index, node_count)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            epoch_loss += float(loss.item())

        scheduler.step()
        average_loss = epoch_loss / max(len(sequences), 1)
        log.info(
            "Epoch %3d/%d | loss=%.6f | lr=%.2e",
            epoch,
            epochs,
            average_loss,
            scheduler.get_last_lr()[0],
        )

    log.info("Fitting Isolation Forest anomaly classifier on training data")
    model.eval()
    embeddings = []
    errors = []
    with torch.no_grad():
        for sequence in sequences:
            _, _, node_errors = model.reconstruct(sequence, device)
            current_graph = sequence[-1].to(device)
            node_count = min(current_graph.num_nodes, MAX_NODES)
            spatial = model.spatial_enc(current_graph.x[:node_count], current_graph.edge_index)
            embeddings.append(spatial.cpu().numpy())
            errors.append(node_errors.cpu().numpy())

    if embeddings:
        embedding_matrix = np.vstack(embeddings)
        error_matrix = np.concatenate(errors).reshape(-1, 1)
        features = np.hstack([embedding_matrix, error_matrix])
    else:
        features = np.zeros((32, 17), dtype=np.float32)

    classifier = IsolationForest(contamination=0.01, n_estimators=200, random_state=42)
    classifier.fit(features)

    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    torch.save(
        {
            "model_state": model.state_dict(),
            "iforest": classifier,
            "config": config,
        },
        checkpoint,
    )
    log.info("Checkpoint saved to %s", checkpoint)
    return model, classifier


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, help="Path to config YAML")
    parser.add_argument("--data-dir", required=True, help="Path to baseline snapshots")
    args = parser.parse_args()

    import yaml

    with open(args.config, "r", encoding="utf-8") as file:
        config = yaml.safe_load(file)
    config["baseline_data_dir"] = args.data_dir

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    train(config, device)
