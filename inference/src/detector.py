"""Online anomaly detection loop."""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
import time
from collections import deque

import numpy as np
import torch
import torch.nn.functional as F
from sklearn.ensemble import IsolationForest

from model import EMBEDDING_DIM, MAX_NODES, SEQ_LEN, SpatiotemporalAutoencoder
from proto import radm_pb2 as pb
from torch_geometric.data import Data

log = logging.getLogger(__name__)


def proto_to_pyg(snapshot: pb.GraphSnapshot) -> Data:
    """Convert a GraphSnapshot protobuf into a PyG-style data object."""
    node_count = len(snapshot.nodes)
    if node_count == 0:
        return Data(
            x=torch.zeros(1, 7),
            edge_index=torch.zeros(2, 0, dtype=torch.long),
            num_nodes=1,
            node_ids=[],
        )

    x = torch.tensor([list(node.features) for node in snapshot.nodes], dtype=torch.float32)
    if snapshot.edges:
        src = [edge.src_index for edge in snapshot.edges]
        dst = [edge.dst_index for edge in snapshot.edges]
        edge_index = torch.tensor([src, dst], dtype=torch.long)
    else:
        edge_index = torch.zeros(2, 0, dtype=torch.long)

    return Data(
        x=x,
        edge_index=edge_index,
        num_nodes=node_count,
        node_ids=[node.node_id for node in snapshot.nodes],
    )


class AnomalyDetector:
    def __init__(self, checkpoint_path: str, device: str = "cpu", alert_threshold: float = -0.2):
        self.device = torch.device(device)
        self.alert_threshold = float(alert_threshold)
        self.model = SpatiotemporalAutoencoder().to(self.device)

        try:
            checkpoint = torch.load(checkpoint_path, map_location=self.device, weights_only=False)
            self.model.load_state_dict(checkpoint["model_state"])
            self.clf: IsolationForest = checkpoint["iforest"]
            log.info("Loaded checkpoint from %s", checkpoint_path)
        except FileNotFoundError:
            log.warning("Checkpoint %s not found. Using an untrained fallback classifier.", checkpoint_path)
            self.clf = IsolationForest(contamination=0.01, n_estimators=32, random_state=42)
            self.clf.fit(np.zeros((32, EMBEDDING_DIM + 1), dtype=np.float32))
        except Exception as exc:
            log.warning("Could not load checkpoint %s: %s", checkpoint_path, exc)
            self.clf = IsolationForest(contamination=0.01, n_estimators=32, random_state=42)
            self.clf.fit(np.zeros((32, EMBEDDING_DIM + 1), dtype=np.float32))

        self.model.eval()
        try:
            self.model = torch.compile(self.model, mode="reduce-overhead")
        except Exception as exc:
            log.warning("torch.compile failed: %s", exc)

        self.seq_buffer = deque(maxlen=SEQ_LEN)
        self.alert_id_counter = 0

    def feed(self, snapshot: pb.GraphSnapshot) -> list[pb.AnomalyAlert]:
        graph = proto_to_pyg(snapshot)
        self.seq_buffer.append(graph)

        if len(self.seq_buffer) < SEQ_LEN:
            return []

        graphs = list(self.seq_buffer)
        with torch.no_grad():
            x_recon, _, node_errors = self.model.reconstruct(graphs, self.device)

        current_graph = graphs[-1].to(self.device)
        node_count = min(current_graph.num_nodes, MAX_NODES)
        spatial_embeddings = self.model.spatial_enc(current_graph.x[:node_count], current_graph.edge_index)
        features = np.hstack([
            spatial_embeddings.detach().cpu().numpy(),
            node_errors.detach().cpu().numpy().reshape(-1, 1),
        ])
        scores = self.clf.score_samples(features)

        anomalous_nodes = np.where(scores < self.alert_threshold)[0]
        if len(anomalous_nodes) == 0:
            return []

        alerts: list[pb.AnomalyAlert] = []
        for node_idx in anomalous_nodes:
            if node_idx >= len(snapshot.nodes):
                continue
            node = snapshot.nodes[node_idx]
            if node.node_type != pb.NodeType.CONTAINER:
                continue

            raw_score = float(scores[node_idx])
            anomaly_score = 1.0 - (raw_score - self.clf.offset_) / abs(self.clf.offset_)
            anomaly_score = max(0.0, min(1.0, anomaly_score))

            threat = self._classify_threat(current_graph, x_recon, node_idx)

            self.alert_id_counter += 1
            alert = pb.AnomalyAlert(
                alert_id=self.alert_id_counter,
                timestamp_ns=int(time.time_ns()),
                cgroup_id=node.node_id,
                target_pid=0,
                container_id=node.label,
                container_name=node.label,
                anomaly_score=anomaly_score,
                node_errors=node_errors.detach().cpu().tolist(),
                threat_class=threat,
                raw_graph_snapshot=snapshot.SerializeToString(),
            )
            alerts.append(alert)
            log.warning(
                "ANOMALY container=%s score=%.4f threat=%s",
                node.label,
                anomaly_score,
                pb.ThreatClass.Name(threat),
            )

        return alerts

    def _classify_threat(self, current_graph: Data, x_recon: torch.Tensor, node_idx: int) -> pb.ThreatClass:
        feature_errors = F.mse_loss(x_recon[node_idx], current_graph.x[node_idx], reduction="none").detach().cpu().numpy()

        mprotect_error = feature_errors[3]
        iat_error = feature_errors[4]
        port_error = feature_errors[5]
        event_error = feature_errors[6]

        if mprotect_error > 0.5:
            return pb.ThreatClass.MEMORY_INJECTION
        if port_error > 0.5 and event_error > 0.5:
            return pb.ThreatClass.DATA_EXFILTRATION
        if iat_error > 0.5:
            return pb.ThreatClass.LATERAL_MOVEMENT
        return pb.ThreatClass.UNKNOWN


async def read_length_prefixed(reader: asyncio.StreamReader) -> bytes:
    header = await reader.readexactly(4)
    length = struct.unpack(">I", header)[0]
    return await reader.readexactly(length)


async def write_length_prefixed(writer: asyncio.StreamWriter, data: bytes) -> None:
    writer.write(struct.pack(">I", len(data)) + data)
    await writer.drain()


async def run_detector(config: dict) -> None:
    detector = AnomalyDetector(
        config["checkpoint_path"],
        config.get("device", "cpu"),
        config.get("alert_threshold", -0.2),
    )

    graph_socket_path = config["graph_socket_path"]
    alert_socket_path = config["alert_socket_path"]

    reader, _ = await asyncio.open_unix_connection(graph_socket_path)
    log.info("Connected to graph stream: %s", graph_socket_path)

    alert_reader, alert_writer = await asyncio.open_unix_connection(alert_socket_path)
    log.info("Connected to alert socket: %s", alert_socket_path)

    while True:
        try:
            raw = await read_length_prefixed(reader)
            snapshot = pb.GraphSnapshot()
            snapshot.ParseFromString(raw)
            log.info(
                "received snapshot sequence_id=%s nodes=%s",
                snapshot.sequence_id,
                len(snapshot.nodes),
            )

            for alert in detector.feed(snapshot):
                await write_length_prefixed(alert_writer, alert.SerializeToString())
        except asyncio.IncompleteReadError:
            log.warning("Graph stream closed, reconnecting in 2 seconds")
            await asyncio.sleep(2)
        except Exception as exc:
            log.error("Detector error: %s", exc, exc_info=True)
