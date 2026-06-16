from __future__ import annotations

import math
from typing import Iterable, Sequence

import numpy as np

from .. import Parameter, Tensor, stack, tanh


class Module:
    def __init__(self):
        self.training = True

    def forward(self, *args, **kwargs):
        raise NotImplementedError

    def __call__(self, *args, **kwargs):
        return self.forward(*args, **kwargs)

    def parameters(self):
        for _, parameter in self.named_parameters():
            yield parameter

    def named_parameters(self, prefix: str = ""):
        for name, value in self.__dict__.items():
            if name == "training":
                continue
            yield from _named_parameters(value, f"{prefix}{name}")

    def state_dict(self):
        return {name: parameter.data.copy() for name, parameter in self.named_parameters()}

    def load_state_dict(self, state):
        parameters = dict(self.named_parameters())
        for name, array in state.items():
            if name in parameters:
                parameters[name].data = np.array(array)

    def train(self, mode: bool = True):
        self.training = mode
        for child in _child_modules(self):
            child.train(mode)
        return self

    def eval(self):
        return self.train(False)

    def to(self, device):
        for parameter in self.parameters():
            parameter.to(device)
        return self


def _child_modules(module):
    for value in module.__dict__.values():
        if isinstance(value, Module):
            yield value
        elif isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, Module):
                    yield item


def _named_parameters(value, prefix: str):
    if isinstance(value, Parameter):
        yield prefix, value
    elif isinstance(value, Module):
        for name, parameter in value.named_parameters():
            yield f"{prefix}.{name}", parameter
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _named_parameters(item, f"{prefix}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            yield from _named_parameters(item, f"{prefix}.{index}")


class Linear(Module):
    def __init__(self, in_features: int, out_features: int):
        super().__init__()
        self.weight = Parameter(np.random.randn(out_features, in_features) * 0.02)
        self.bias = Parameter(np.zeros(out_features))

    def forward(self, x: Tensor) -> Tensor:
        return Tensor(x.data @ self.weight.data.T + self.bias.data)


class ELU(Module):
    def forward(self, x: Tensor) -> Tensor:
        data = np.where(x.data > 0, x.data, np.exp(x.data) - 1.0)
        return Tensor(data)


class Dropout(Module):
    def __init__(self, p: float = 0.5):
        super().__init__()
        self.p = p

    def forward(self, x: Tensor) -> Tensor:
        if self.training and self.p > 0:
            return Tensor(x.data * (1.0 - self.p))
        return x


class LayerNorm(Module):
    def __init__(self, normalized_shape: int, eps: float = 1e-5):
        super().__init__()
        self.weight = Parameter(np.ones(normalized_shape))
        self.bias = Parameter(np.zeros(normalized_shape))
        self.eps = eps

    def forward(self, x: Tensor) -> Tensor:
        mean = x.data.mean(axis=-1, keepdims=True)
        variance = x.data.var(axis=-1, keepdims=True)
        normalized = (x.data - mean) / np.sqrt(variance + self.eps)
        return Tensor(normalized * self.weight.data + self.bias.data)


class Sequential(Module):
    def __init__(self, *modules):
        super().__init__()
        self.modules_list = list(modules)

    def forward(self, x: Tensor) -> Tensor:
        for module in self.modules_list:
            x = module(x)
        return x


class GRU(Module):
    def __init__(self, input_size: int, hidden_size: int, num_layers: int = 1, batch_first: bool = False, dropout: float = 0.0):
        super().__init__()
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.batch_first = batch_first
        self.dropout = dropout
        self.weight_ih = []
        self.weight_hh = []
        self.bias = []
        for layer_index in range(num_layers):
            in_size = input_size if layer_index == 0 else hidden_size
            self.weight_ih.append(Parameter(np.random.randn(hidden_size, in_size) * 0.02))
            self.weight_hh.append(Parameter(np.random.randn(hidden_size, hidden_size) * 0.02))
            self.bias.append(Parameter(np.zeros(hidden_size)))

    def forward(self, z_seq: Tensor):
        sequence = z_seq.data
        if self.batch_first:
            sequence = np.swapaxes(sequence, 0, 1)
        outputs = sequence
        hidden_states = []
        for layer_index in range(self.num_layers):
            weight_ih = self.weight_ih[layer_index].data
            weight_hh = self.weight_hh[layer_index].data
            bias = self.bias[layer_index].data
            batch_size = outputs.shape[1]
            hidden = np.zeros((batch_size, self.hidden_size))
            layer_outputs = []
            for timestep in range(outputs.shape[0]):
                current = outputs[timestep]
                hidden = np.tanh(current @ weight_ih.T + hidden @ weight_hh.T + bias)
                layer_outputs.append(hidden)
            outputs = np.stack(layer_outputs, axis=0)
            hidden_states.append(hidden)
        hidden_stack = np.stack(hidden_states, axis=0)
        return Tensor(outputs), Tensor(hidden_stack)


def _stack_to_tensor(values):
    return Tensor(np.stack([value.data for value in values], axis=0))


from . import functional, utils  # noqa: E402
