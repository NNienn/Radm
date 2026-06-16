from __future__ import annotations

import math
import pickle
from contextlib import contextmanager
from typing import Any, Iterable, Iterator, Sequence

import numpy as np

float32 = np.float32
float = np.float32
long = np.int64

_REGISTERED_PARAMETERS: list["Parameter"] = []


class device(str):
    pass


class Tensor:
    __array_priority__ = 1000

    def __init__(self, data: Any, dtype: Any | None = None, device: str = "cpu", requires_grad: bool = False):
        self.data = np.array(data, dtype=dtype)
        self.device = device
        self.requires_grad = requires_grad
        self.grad: np.ndarray | None = None

    @property
    def shape(self):
        return self.data.shape

    @property
    def ndim(self):
        return self.data.ndim

    @property
    def dtype(self):
        return self.data.dtype

    def to(self, device: str | device):
        self.device = str(device)
        return self

    def cpu(self):
        return self.to("cpu")

    def detach(self):
        return Tensor(self.data.copy(), device=self.device)

    def numpy(self):
        return np.array(self.data)

    def reshape(self, *shape):
        return Tensor(self.data.reshape(*shape), device=self.device)

    def sum(self, dim=None):
        return Tensor(self.data.sum(axis=dim), device=self.device)

    def mean(self, dim=None):
        return Tensor(self.data.mean(axis=dim), device=self.device)

    def all(self):
        return bool(np.all(self.data))

    def item(self):
        return self.data.item()

    def tolist(self):
        return self.data.tolist()

    def clone(self):
        return Tensor(self.data.copy(), device=self.device, requires_grad=self.requires_grad)

    def backward(self):
        for parameter in _REGISTERED_PARAMETERS:
            if parameter.requires_grad:
                parameter.grad = np.ones_like(parameter.data)

    def __len__(self):
        return len(self.data)

    def __iter__(self):
        for index in range(len(self.data)):
            yield Tensor(self.data[index], device=self.device)

    def __getitem__(self, item):
        if isinstance(item, Tensor):
            item = item.data
        return Tensor(self.data[item], device=self.device)

    def __setitem__(self, key, value):
        if isinstance(key, Tensor):
            key = key.data
        value_data = value.data if isinstance(value, Tensor) else value
        self.data[key] = value_data

    def _binary(self, other, op):
        other_data = other.data if isinstance(other, Tensor) else other
        return Tensor(op(self.data, other_data), device=self.device)

    def __add__(self, other):
        return self._binary(other, np.add)

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        return self._binary(other, np.subtract)

    def __rsub__(self, other):
        other_data = other.data if isinstance(other, Tensor) else other
        return Tensor(np.subtract(other_data, self.data), device=self.device)

    def __mul__(self, other):
        return self._binary(other, np.multiply)

    def __rmul__(self, other):
        return self.__mul__(other)

    def __truediv__(self, other):
        return self._binary(other, np.divide)

    def __matmul__(self, other):
        other_data = other.data if isinstance(other, Tensor) else other
        return Tensor(self.data @ other_data, device=self.device)

    def __neg__(self):
        return Tensor(-self.data, device=self.device)

    def __ge__(self, other):
        other_data = other.data if isinstance(other, Tensor) else other
        return self.data >= other_data

    def __lt__(self, other):
        other_data = other.data if isinstance(other, Tensor) else other
        return self.data < other_data

    def __array__(self, dtype=None):
        return np.asarray(self.data, dtype=dtype)


class Parameter(Tensor):
    def __init__(self, data: Any, dtype: Any | None = None, device: str = "cpu"):
        super().__init__(data, dtype=dtype, device=device, requires_grad=True)
        _REGISTERED_PARAMETERS.append(self)


def _as_tensor(value: Any, dtype: Any | None = None, device: str = "cpu") -> Tensor:
    if isinstance(value, Tensor):
        return value
    return Tensor(value, dtype=dtype, device=device)


def manual_seed(seed: int) -> None:
    np.random.seed(seed)


def rand(*shape, device: str = "cpu") -> Tensor:
    return Tensor(np.random.rand(*shape), device=device)


def randint(low: int, high: int, size, device: str = "cpu") -> Tensor:
    return Tensor(np.random.randint(low, high, size=size), device=device)


def zeros(*shape, dtype=float32, device: str = "cpu") -> Tensor:
    if len(shape) == 1 and isinstance(shape[0], (tuple, list)):
        shape = tuple(shape[0])
    return Tensor(np.zeros(shape, dtype=dtype), device=device)


def ones(*shape, dtype=float32, device: str = "cpu") -> Tensor:
    if len(shape) == 1 and isinstance(shape[0], (tuple, list)):
        shape = tuple(shape[0])
    return Tensor(np.ones(shape, dtype=dtype), device=device)


def tensor(data, dtype=None, device: str = "cpu") -> Tensor:
    return Tensor(data, dtype=dtype, device=device)


def stack(tensors: Sequence[Tensor], dim: int = 0) -> Tensor:
    return Tensor(np.stack([tensor.data for tensor in tensors], axis=dim))


def hstack(tensors: Sequence[Tensor]) -> Tensor:
    return Tensor(np.hstack([tensor.data for tensor in tensors]))


def sigmoid(x):
    x_data = x.data if isinstance(x, Tensor) else x
    return Tensor(1.0 / (1.0 + np.exp(-x_data)))


def tanh(x):
    x_data = x.data if isinstance(x, Tensor) else x
    return Tensor(np.tanh(x_data))


def save(obj, path):
    with open(path, "wb") as file:
        pickle.dump(obj, file)


def load(path, map_location=None, weights_only=False):
    with open(path, "rb") as file:
        return pickle.load(file)


def compile(model, mode=None):
    return model


class _Cuda:
    @staticmethod
    def is_available() -> bool:
        return False


cuda = _Cuda()


class no_grad:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def __call__(self, func):
        def wrapper(*args, **kwargs):
            with self:
                return func(*args, **kwargs)

        return wrapper


def device_count() -> int:
    return 0


from . import nn, optim  # noqa: E402
