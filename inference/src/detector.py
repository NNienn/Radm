# inference/src/detector.py
#
# Online anomaly detection loop.
# Consumes GraphSnapshot protobufs from UDS, runs ST-GAE inference,
# classifies anomalies via Isolation Forest, and emits AnomalyAlert protobufs.

import asyncio
import socket
import struct
import time
import logging
import numpy as np
import torch
import torch.nn.functional as F
from collections import deque
from pathlib import Path
from sklearn.ensemble import IsolationForest

from model import SpatiotemporalAutoencoder, SEQ_LEN, MAX_NODES
from proto import radm_pb2 as pb
from torch_geometric.data import Data

log = logging.getLogger(__name__)

ALERT_THRESHOLD = -0.2   # Isolation Forest score below this triggers alert


def proto_to_pyg(snapshot: pb.GraphSnapshot) -> Data:
    """Convert a GraphSnapshot protobuf into a PyTorch Geometric Data object."""
    n = len(snapshot.nodes)
    if n == 0:
        return Data(
            x=torch.zeros(1, 7), edge_index=torch.zeros(2, 0, dtype=torch.long)
        )

    x = torch.tensor([list(node.features) for node in snapshot.nodes], dtype=torch.float)

    if snapshot.edges:
        src = [e.src_index for e in snapshot.edges]
        dst = [e.dst_index for e in snapshot.edges]
        edge_index = torch.tensor([src, dst], dtype=torch.long)
    else:
        edge_index = torch.zeros(2, 0, dtype=torch.long)

    return Data(
        x=x,
        edge_index=edge_index,
        num_nodes=n,
        node_ids=[node.node_id for node in snapshot.nodes],
    )


class AnomalyDetector:
    def __init__(self, checkpoint_path: str, device: str = "cpu"):
        self.device = torch.device(device)
        ckpt = torch.load(checkpoint_path, map_location=self.device, weights_only=False)

        self.model = SpatiotemporalAutoencoder().to(self.device)
        self.model.load_state_dict(ckpt["model_state"])
        self.model.eval()

        # torch.compile for ~2× CPU speedup (requires PyTorch 2.0+)
        # Wrapped in try-except in case of compilation issues on some hosts
        try:
            self.model = torch.compile(self.model, mode="reduce-overhead")
        except Exception as e:
            log.warning(f"torch.compile failed: {e}. Falling back to standard inference.")

        self.clf: IsolationForest = ckpt["iforest"]
        self.seq_buffer = deque(maxlen=SEQ_LEN)
        self.alert_id_counter = 0

        log.info(f"Loaded checkpoint from {checkpoint_path}, device={device}")

    def feed(self, snapshot: pb.GraphSnapshot) -> list[pb.AnomalyAlert]:
        """
        Feed one snapshot into the sequence buffer.
        Returns a list of AnomalyAlert protobufs (may be empty).
        """
        graph = proto_to_pyg(snapshot)
        self.seq_buffer.append(graph)

        if len(self.seq_buffer) < SEQ_LEN:
            return []  # not enough history yet

        graphs = list(self.seq_buffer)
        with torch.no_grad():
            x_recon, edge_probs, node_errors = self.model.reconstruct(graphs, self.device)

        # Compute Isolation Forest features (embedding + reconstruction error)
        g_curr = graphs[-1].to(self.device)
        n = min(g_curr.num_nodes, MAX_NODES)
        z = self.model.spatial_enc(g_curr.x[:n], g_curr.edge_index)

        emb = z.cpu().numpy()
        err = node_errors.cpu().numpy().reshape(-1, 1)
        features = np.hstack([emb, err])

        scores = self.clf.score_samples(features)  # lower = more anomalous

        # Identify anomalous nodes
        anomalous_mask = scores < ALERT_THRESHOLD
        if not anomalous_mask.any():
            return []

        alerts = []
        for node_idx in np.where(anomalous_mask)[0]:
            if node_idx >= len(snapshot.nodes):
                continue
            node = snapshot.nodes[node_idx]
            if node.node_type != pb.NodeType.CONTAINER:
                continue  # only alert on containers

            # Normalise score to [0,1] — lower IF score = higher anomaly
            raw_score = float(scores[node_idx])
            anomaly_score = 1.0 - (raw_score - self.clf.offset_) / abs(self.clf.offset_)
            anomaly_score = max(0.0, min(1.0, anomaly_score))

            threat = self._classify_threat(graphs, node_errors, node_idx)

            self.alert_id_counter += 1
            alert = pb.AnomalyAlert(
                alert_id=self.alert_id_counter,
                timestamp_ns=int(time.time_ns()),
                cgroup_id=node.node_id,
                target_pid=0,  # resolved by aggregator from cgroup_id
                container_id=node.label,
                container_name=node.label,
                anomaly_score=anomaly_score,
                node_errors=node_errors.tolist(),
                threat_class=threat,
                raw_graph_snapshot=snapshot.SerializeToString(),
            )
            alerts.append(alert)
            log.warning(
                f"ANOMALY: container={node.label} score={anomaly_score:.4f} "
                f"threat={pb.ThreatClass.Name(threat)}"
            )

        return alerts

    def _classify_threat(
        self,
        graphs: list,
        node_errors: torch.Tensor,
        node_idx: int,
    ) -> pb.ThreatClass:
        """
        Heuristic threat classification based on which feature dimensions
        contribute most to the reconstruction error.
        Feature layout: [type_oh(3), mprotect_freq(1), iat_var(1), port_delta(1), event_freq(1)]
        """
        g_curr = graphs[-1]
        n = min(g_curr.num_nodes, MAX_NODES)
        with torch.no_grad():
            z = self.model.spatial_enc(g_curr.x[:n], g_curr.edge_index)
            x_recon = self.model.feat_dec(z)
        feat_errors = F.mse_loss(
            x_recon[node_idx], g_curr.x[node_idx], reduction='none'
        ).cpu().numpy()

        mprotect_err = feat_errors[3]
        iat_err      = feat_errors[4]
        port_err     = feat_errors[5]
        event_err    = feat_errors[6]

        if mprotect_err > 0.5:
            return pb.ThreatClass.MEMORY_INJECTION
        if port_err > 0.5 and event_err > 0.5:
            return pb.ThreatClass.DATA_EXFILTRATION
        if iat_err > 0.5:
            return pb.ThreatClass.LATERAL_MOVEMENT
        return pb.ThreatClass.UNKNOWN


# ─────────────────────────────────────────────────────────────────────────────
# Async I/O wrappers for UDS communication
# ─────────────────────────────────────────────────────────────────────────────

async def read_length_prefixed(reader: asyncio.StreamReader) -> bytes:
    """Read a 4-byte big-endian length prefix then that many bytes."""
    header = await reader.readexactly(4)
    length = struct.unpack(">I", header)[0]
    return await reader.readexactly(length)


async def write_length_prefixed(writer: asyncio.StreamWriter, data: bytes):
    """Write a 4-byte big-endian length prefix then the data."""
    header = struct.pack(">I", len(data))
    writer.write(header + data)
    await writer.drain()


async def run_detector(config: dict):
    graph_socket_path = config["graph_socket_path"]
    alert_socket_path = config["alert_socket_path"]
    checkpoint_path   = config["checkpoint_path"]

    detector = AnomalyDetector(checkpoint_path, config.get("device", "cpu"))

    # Connect to aggregator graph stream
    reader, _ = await asyncio.open_unix_connection(graph_socket_path)
    log.info(f"Connected to graph stream: {graph_socket_path}")

    # Open alert socket (connect to mitigation plane)
    alert_reader, alert_writer = await asyncio.open_unix_connection(alert_socket_path)
    log.info(f"Connected to alert socket: {alert_socket_path}")

    while True:
        try:
            raw = await read_length_prefixed(reader)
            snapshot = pb.GraphSnapshot()
            snapshot.ParseFromString(raw)
            log.info(f"got an event: sequence_id={snapshot.sequence_id}, nodes={len(snapshot.nodes)}")

            alerts = detector.feed(snapshot)
            for alert in alerts:
                await write_length_prefixed(alert_writer, alert.SerializeToString())

        except asyncio.IncompleteReadError:
            log.warning("Graph stream closed — reconnecting in 2s")
            await asyncio.sleep(2)
        except Exception as e:
            log.error(f"Detector error: {e}", exc_info=True)
