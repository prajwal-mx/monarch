"""Hardware Resource Guardrails & Watchdog.
Enforces memory limits (< 2.0 GiB RSS), traversal recursion/depth caps, and timeout guards
to ensure the platform operates safely without overloading the user's laptop.
"""

from __future__ import annotations

import os
import psutil
import time
from typing import Optional


MAX_RSS_BYTES = 2 * 1024 * 1024 * 1024  # 2.0 GiB
DEFAULT_MAX_TRAVERSAL_NODES = 100_000
DEFAULT_MAX_DEPTH = 30
DEFAULT_TIMEOUT_SECONDS = 30.0


class ResourceLimitExceededError(RuntimeError):
    """Raised when process memory or computation limits are exceeded."""
    pass


class ResourceGuard:
    """Monitors process memory and enforces computation budgets."""

    @staticmethod
    def get_current_rss_bytes() -> int:
        """Return the current resident memory (RSS) in bytes."""
        try:
            return psutil.Process().memory_info().rss
        except Exception:
            return 0

    @staticmethod
    def get_current_rss_mb() -> float:
        """Return current RSS in megabytes."""
        return ResourceGuard.get_current_rss_bytes() / (1024 * 1024)

    @staticmethod
    def check_memory_safe(max_bytes: int = MAX_RSS_BYTES) -> None:
        """Raise error if process RSS exceeds the safety limit."""
        current_rss = ResourceGuard.get_current_rss_bytes()
        if current_rss > max_bytes:
            raise ResourceLimitExceededError(
                f"Memory limit exceeded: {current_rss / (1024*1024):.1f} MB RSS (cap is {max_bytes / (1024*1024):.1f} MB)"
            )

    @staticmethod
    def get_safe_worker_count(max_cap: int = 4) -> int:
        """Return bounded worker thread count to prevent CPU thrashing."""
        cpus = os.cpu_count() or 2
        return max(1, min(max_cap, cpus // 2))


class TraversalBudget:
    """Tracks traversal iterations, depth, and wall-clock execution."""

    def __init__(
        self,
        max_nodes: int = DEFAULT_MAX_TRAVERSAL_NODES,
        max_depth: int = DEFAULT_MAX_DEPTH,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        self.max_nodes = max_nodes
        self.max_depth = max_depth
        self.timeout_seconds = timeout_seconds
        self.start_time = time.monotonic()
        self.nodes_visited = 0
        self.truncated = False

    def step(self, current_depth: int) -> bool:
        """Record visiting a node. Returns False if budget exhausted."""
        self.nodes_visited += 1

        if current_depth > self.max_depth:
            self.truncated = True
            return False

        if self.nodes_visited > self.max_nodes:
            self.truncated = True
            return False

        if (time.monotonic() - self.start_time) > self.timeout_seconds:
            self.truncated = True
            return False

        # Periodically verify memory safety every 5,000 nodes
        if self.nodes_visited % 5000 == 0:
            ResourceGuard.check_memory_safe()

        return True
