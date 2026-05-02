"""
dvara/bloom.py

Core Bloom Filter implementation for malicious URL detection.
Uses MurmurHash3 (mmh3) with k independent seeds for k bit positions.
Optimal m and k are calculated from capacity (n) and false positive rate (p).
"""

import math
import os
import struct
from bitarray import bitarray
import mmh3


class BloomFilter:
    """
    A space-efficient probabilistic data structure for set membership testing.

    Properties:
        - Zero false negatives: if a URL was added, contains() always returns True
        - Tunable false positive rate: controlled by capacity and error_rate
        - Memory efficient: 3M URLs at 0.1% FPR = ~5.2MB

    Args:
        capacity (int):    Expected number of items to be inserted (n)
        error_rate (float): Desired false positive rate e.g. 0.001 = 0.1%
    """

    def __init__(self, capacity: int, error_rate: float = 0.001):
        if capacity <= 0:
            raise ValueError("capacity must be a positive integer")
        if not (0 < error_rate < 1):
            raise ValueError("error_rate must be between 0 and 1 (exclusive)")

        self.capacity = capacity
        self.error_rate = error_rate

        # Optimal bit array size: m = -(n * ln(p)) / (ln(2))^2
        self.m = self._optimal_m(capacity, error_rate)

        # Optimal number of hash functions: k = (m / n) * ln(2)
        self.k = self._optimal_k(self.m, capacity)

        # Internal bit array, initialised to all zeros
        self._bits = bitarray(self.m)
        self._bits.setall(0)

        # Track how many items have been added
        self._count = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add(self, url: str) -> None:
        """Insert a URL into the filter."""
        for position in self._hash_positions(url):
            self._bits[position] = 1
        self._count += 1

    def contains(self, url: str) -> bool:
        """
        Test whether a URL is in the filter.

        Returns:
            False  → definitely NOT in the set (zero false negatives)
            True   → probably in the set (false positive rate = error_rate)
        """
        return all(self._bits[pos] for pos in self._hash_positions(url))

    # Alias so the filter feels natural as a Python object
    def __contains__(self, url: str) -> bool:
        return self.contains(url)

    # ------------------------------------------------------------------
    # Serialisation — save / load binary
    # ------------------------------------------------------------------

    def to_file(self, path: str) -> None:
        """
        Persist the filter to a compact binary file.

        File format (little-endian):
            [8 bytes] capacity   (uint64)
            [8 bytes] m          (uint64)
            [4 bytes] k          (uint32)
            [8 bytes] error_rate (double)
            [8 bytes] count      (uint64)
            [m bits]  bit array  (packed bytes, padded to byte boundary)
        """
        os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
        with open(path, "wb") as f:
            header = struct.pack(
                "<QQIdQ",          # fmt: uint64, uint64, uint32, double, uint64
                self.capacity,
                self.m,
                self.k,
                self.error_rate,
                self._count,
            )
            f.write(header)
            self._bits.tofile(f)

    @classmethod
    def from_file(cls, path: str) -> "BloomFilter":
        """Load a previously saved filter from disk."""
        with open(path, "rb") as f:
            header_size = struct.calcsize("<QQIdQ")
            header = struct.unpack("<QQIdQ", f.read(header_size))
            capacity, m, k, error_rate, count = header

            instance = cls.__new__(cls)
            instance.capacity = capacity
            instance.m = m
            instance.k = k
            instance.error_rate = error_rate
            instance._count = count

            instance._bits = bitarray()
            instance._bits.fromfile(f)
            # fromfile pads to the nearest byte; trim to exact bit length
            instance._bits = instance._bits[:m]

        return instance

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    @property
    def fill_ratio(self) -> float:
        """Fraction of bits currently set to 1."""
        return self._bits.count(1) / self.m

    @property
    def actual_fpr(self) -> float:
        """
        Empirical false positive rate based on current fill ratio.
        Formula: (fill_ratio) ^ k
        """
        return self.fill_ratio ** self.k

    def __repr__(self) -> str:
        return (
            f"BloomFilter("
            f"capacity={self.capacity:,}, "
            f"m={self.m:,} bits ({self.m / 8 / 1024 / 1024:.2f} MB), "
            f"k={self.k}, "
            f"target_fpr={self.error_rate:.4%}, "
            f"count={self._count:,}, "
            f"fill={self.fill_ratio:.4%}, "
            f"actual_fpr≈{self.actual_fpr:.4%}"
            f")"
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _hash_positions(self, url: str) -> list[int]:
        """
        Generate k bit positions for a given URL using MurmurHash3.
        Each seed i (0 … k-1) produces an independent hash value,
        which is mapped into [0, m) via modulo.
        """
        encoded = url.encode("utf-8")
        return [mmh3.hash(encoded, seed=i, signed=False) % self.m for i in range(self.k)]

    @staticmethod
    def _optimal_m(n: int, p: float) -> int:
        """Bit array size: m = -(n * ln(p)) / (ln(2))^2"""
        m = -(n * math.log(p)) / (math.log(2) ** 2)
        return int(math.ceil(m))

    @staticmethod
    def _optimal_k(m: int, n: int) -> int:
        """Number of hash functions: k = (m / n) * ln(2)"""
        k = (m / n) * math.log(2)
        return max(1, int(round(k)))
