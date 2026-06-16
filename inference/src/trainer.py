# inference/src/trainer.py
#
# Offline training loop.
# Usage:
#   python -m radm.trainer --config radm.yaml --data-dir /var/radm/baseline
#
# Baseline data is collected by running the system in OBSERVE mode (no quarantine)
# for a minimum of 2 hours.  Graph snapshots are saved as pickled PyG Data objects.

import argparse
import pathlib
import pickle
import torch
import torch.optim as optim
from torch_geometric.data import Data
from model import SpatiotemporalAutoencoder, compute_loss, SEQ_LEN
from sklearn.ensemble import IsolationForest
import numpy as np
import logging

log = logging.getLogger(__name__)


def load_baseline_sequences(data_dir: pathlib.Path, seq_len: int = SEQ_LEN):
    """Load consecutive graph snapshots from disk and group into sequences."""
    files = sorted(data_dir.glob("snapshot_*.pkl"))
    log.info(f"Loaded {len(files)} baseline snapshots from {data_dir}")
    graphs = [pickle.loads(f.read_bytes()) for f in files]

    sequences = []
    for i in range(len(graphs) - seq_len):
        seq = graphs[i : i + seq_len]
        sequences.append(seq)
    return sequences


def train(config: dict, device: torch.device):
    data_dir   = pathlib.Path(config["baseline_data_dir"])
    checkpoint = pathlib.Path(config["checkpoint_path"])
    epochs     = config.get("epochs", 50)
    lr         = config.get("lr", 1e-3)

    sequences = load_baseline_sequences(data_dir)
    log.info(f"Training on {len(sequences)} sequences, device={device}")

    model     = SpatiotemporalAutoencoder().to(device)
    optimizer = optim.Adam(model.parameters(), lr=lr, weight_decay=1e-5)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    model.train()
    for epoch in range(1, epochs + 1):
        epoch_loss = 0.0
        for seq in sequences:
            optimizer.zero_grad()
            x_recon, edge_probs = model(seq, device)

            g_curr     = seq[-1].to(device)
            n          = min(g_curr.num_nodes, 256)
            x_target   = g_curr.x[:n]
            edge_index = g_curr.edge_index

            loss = compute_loss(x_recon, x_target, edge_probs, edge_index, n)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            epoch_loss += loss.item()

        scheduler.step()
        avg = epoch_loss / max(len(sequences), 1)
        log.info(f"Epoch {epoch:3d}/{epochs} | loss={avg:.6f} | lr={scheduler.get_last_lr()[0]:.2e}")

    # ── Fit Isolation Forest on training embeddings ─────────────────────────
    log.info("Fitting Isolation Forest anomaly classifier on training data…")
    model.eval()
    all_embeddings, all_errors = [], []

    with torch.no_grad():
        for seq in sequences:
            _, _, node_errors = model.reconstruct(seq, device)
            # Use final-snapshot GATv2 embeddings (from spatial encoder only)
            g = seq[-1].to(device)
            n = min(g.num_nodes, 256)
            z = model.spatial_enc(g.x[:n], g.edge_index)
            all_embeddings.append(z.cpu().numpy())
            all_errors.append(node_errors.cpu().numpy())

    emb_flat = np.vstack(all_embeddings)
    err_flat = np.concatenate(all_errors).reshape(-1, 1)
    features = np.hstack([emb_flat, err_flat])

    clf = IsolationForest(contamination=0.01, n_estimators=200, random_state=42)
    clf.fit(features)

    # ── Save checkpoint ──────────────────────────────────────────────────────
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    torch.save({
        "model_state":   model.state_dict(),
        "iforest":       clf,
        "config":        config,
    }, checkpoint)
    log.info(f"Checkpoint saved → {checkpoint}")
    return model, clf

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, help="Path to config YAML")
    parser.add_argument("--data-dir", required=True, help="Path to baseline snapshots")
    args = parser.parse_args()

    import yaml
    with open(args.config) as f:
        cfg = yaml.safe_load(f)
    cfg["baseline_data_dir"] = args.data_dir

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    train(cfg, device)
