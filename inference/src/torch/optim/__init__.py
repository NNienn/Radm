from __future__ import annotations

import math

import numpy as np


class Adam:
    def __init__(self, params, lr: float = 1e-3, weight_decay: float = 0.0):
        self.params = list(params)
        self.lr = lr
        self.weight_decay = weight_decay

    def zero_grad(self):
        for param in self.params:
            param.grad = np.zeros_like(param.data)

    def step(self):
        for param in self.params:
            if param.grad is None:
                continue
            update = param.grad
            if self.weight_decay:
                update = update + self.weight_decay * param.data
            param.data = param.data - self.lr * update


class lr_scheduler:
    class CosineAnnealingLR:
        def __init__(self, optimizer: Adam, T_max: int, eta_min: float = 0.0):
            self.optimizer = optimizer
            self.T_max = max(int(T_max), 1)
            self.eta_min = eta_min
            self.base_lr = optimizer.lr
            self.last_epoch = -1

        def step(self):
            self.last_epoch += 1
            cosine = (1 + math.cos(math.pi * self.last_epoch / self.T_max)) / 2.0
            self.optimizer.lr = self.eta_min + (self.base_lr - self.eta_min) * cosine

        def get_last_lr(self):
            return [self.optimizer.lr]

