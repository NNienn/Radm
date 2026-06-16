from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass
class Data:
    x: Any
    edge_index: Any
    num_nodes: int | None = None
    node_ids: list[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.num_nodes is None:
            self.num_nodes = int(self.x.shape[0])

    @property
    def num_edges(self) -> int:
        if self.edge_index is None:
            return 0
        return int(self.edge_index.shape[1])

    def to(self, device: Any) -> "Data":
        return Data(
            x=self.x.to(device),
            edge_index=self.edge_index.to(device),
            num_nodes=self.num_nodes,
            node_ids=list(self.node_ids),
        )

