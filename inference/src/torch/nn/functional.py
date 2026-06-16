from __future__ import annotations

import numpy as np

from .. import Tensor


def mse_loss(input: Tensor, target: Tensor, reduction: str = "mean") -> Tensor:
    data = (input.data - target.data) ** 2
    if reduction == "none":
        return Tensor(data)
    if reduction == "sum":
        return Tensor(np.array(data.sum()))
    return Tensor(np.array(data.mean()))


def binary_cross_entropy(input: Tensor, target: Tensor) -> Tensor:
    eps = 1e-7
    input_data = np.clip(input.data, eps, 1.0 - eps)
    loss = -(target.data * np.log(input_data) + (1.0 - target.data) * np.log(1.0 - input_data))
    return Tensor(np.array(loss.mean()))


def elu(input: Tensor, alpha: float = 1.0) -> Tensor:
    data = np.where(input.data > 0, input.data, alpha * (np.exp(input.data) - 1.0))
    return Tensor(data)
