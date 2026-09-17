"""HyperLogLog (HLL) mergeable reachability sketches.
Implements mergeable cardinality estimation per Section 1.5.4(a) and Section 3.A.3.
"""

from __future__ import annotations

import hashlib
import math
import struct
from typing import Optional, Set


class HyperLogLog:
    """HyperLogLog sketch with sparse-to-dense representation and merge support."""

    def __init__(self, p: int = 10, sparse_threshold: int = 128):
        self.p = p
        self.m = 1 << p
        self.sparse_threshold = sparse_threshold
        self.is_sparse = True
        self.sparse_elements: Set[str] = set()
        self.registers = bytearray(self.m)

        # Alpha constant calculation
        if self.m == 16:
            self.alpha = 0.673
        elif self.m == 32:
            self.alpha = 0.697
        elif self.m == 64:
            self.alpha = 0.709
        else:
            self.alpha = 0.7213 / (1.0 + 1.079 / self.m)

    def _hash(self, item: str) -> int:
        h = hashlib.sha256(item.encode("utf-8")).digest()
        return struct.unpack(">Q", h[:8])[0]

    def add(self, item: str) -> None:
        if self.is_sparse:
            self.sparse_elements.add(item)
            if len(self.sparse_elements) > self.sparse_threshold:
                self._convert_to_dense()
            return

        x = self._hash(item)
        j = x & (self.m - 1)
        w = x >> self.p
        leading_zeros = (w ^ (w - 1)).bit_length() if w != 0 else (64 - self.p)
        rho = min(64 - self.p, (64 - self.p - w.bit_length() + 1)) if w != 0 else (64 - self.p)
        rho = max(1, rho)
        if rho > self.registers[j]:
            self.registers[j] = rho

    def _convert_to_dense(self) -> None:
        self.is_sparse = False
        for item in self.sparse_elements:
            x = self._hash(item)
            j = x & (self.m - 1)
            w = x >> self.p
            rho = max(1, 64 - self.p - w.bit_length() + 1) if w != 0 else (64 - self.p)
            if rho > self.registers[j]:
                self.registers[j] = rho
        self.sparse_elements.clear()

    def merge(self, other: "HyperLogLog") -> "HyperLogLog":
        """Return a new HLL representing the union of this and other."""
        result = HyperLogLog(p=self.p, sparse_threshold=self.sparse_threshold)
        if self.is_sparse and other.is_sparse:
            result.sparse_elements = self.sparse_elements.union(other.sparse_elements)
            if len(result.sparse_elements) > self.sparse_threshold:
                result._convert_to_dense()
            return result

        result._convert_to_dense()
        # Merge self into result
        if self.is_sparse:
            for item in self.sparse_elements:
                result.add(item)
        else:
            for i in range(self.m):
                result.registers[i] = max(result.registers[i], self.registers[i])

        # Merge other into result
        if other.is_sparse:
            for item in other.sparse_elements:
                result.add(item)
        else:
            for i in range(self.m):
                result.registers[i] = max(result.registers[i], other.registers[i])

        return result

    def cardinality(self) -> int:
        if self.is_sparse:
            return len(self.sparse_elements)

        sum_inv = 0.0
        zeros = 0
        for val in self.registers:
            sum_inv += 2.0 ** (-val)
            if val == 0:
                zeros += 1

        raw_est = self.alpha * (self.m ** 2) / sum_inv

        # Small range correction (linear counting)
        if raw_est <= 2.5 * self.m and zeros > 0:
            return int(round(self.m * math.log(self.m / zeros)))
        # Large range correction
        if raw_est > (1.0 / 30.0) * (2 ** 64):
            return int(round(- (2 ** 64) * math.log(1.0 - raw_est / (2 ** 64))))
        return int(round(raw_est))
