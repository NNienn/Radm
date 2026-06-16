from __future__ import annotations

import torch
import torch.nn as nn


class GATv2Conv(nn.Module):
    def __init__(
        self,
        in_channels: int,
        out_channels: int,
        heads: int = 1,
        concat: bool = True,
        add_self_loops: bool = True,
    ) -> None:
        super().__init__()
        self.concat = concat
        self.heads = heads
        self.out_channels = out_channels
        projection_dim = out_channels * heads if concat else out_channels
        self.linear = nn.Linear(in_channels, projection_dim)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        return self.linear(x)

