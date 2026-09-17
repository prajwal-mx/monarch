"""Compressed Sparse Row (CSR) in-memory graph representation.
Provides sub-millisecond forward and reverse adjacency traversals per Section 1.5.1.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple
import array
from monarch.common.models import DepKind, RangeClass
from monarch.common.resource_guard import TraversalBudget


class CSRGraph:
    """In-memory dual CSR representation (Forward & Reverse) with dense ID mapping."""

    def __init__(
        self,
        node_to_id: Dict[str, int],
        id_to_node: List[str],
        fwd_offsets: array.array,
        fwd_targets: array.array,
        rev_offsets: array.array,
        rev_sources: array.array,
        edge_kinds: Optional[array.array] = None,
        edge_ranges: Optional[array.array] = None,
    ):
        self.node_to_id = node_to_id
        self.id_to_node = id_to_node
        self.num_nodes = len(id_to_node)
        self.fwd_offsets = fwd_offsets
        self.fwd_targets = fwd_targets
        self.rev_offsets = rev_offsets
        self.rev_sources = rev_sources
        self.edge_kinds = edge_kinds or array.array("B", [0] * len(fwd_targets))
        self.edge_ranges = edge_ranges or array.array("B", [0] * len(fwd_targets))

    @classmethod
    def from_edges(
        cls,
        edges: List[Tuple[str, str, DepKind, RangeClass]],
        all_nodes: Optional[Set[str]] = None,
    ) -> "CSRGraph":
        """Build dual CSR arrays from a list of (source_pkg, target_pkg, kind, range_class) tuples."""
        # Collect distinct nodes
        nodes_set: Set[str] = set(all_nodes) if all_nodes else set()
        for src, dst, _, _ in edges:
            nodes_set.add(src)
            nodes_set.add(dst)

        id_to_node = sorted(list(nodes_set))
        node_to_id = {node: i for i, node in enumerate(id_to_node)}
        n = len(id_to_node)

        # Build forward adjacency list
        fwd_adj: List[List[Tuple[int, int, int]]] = [[] for _ in range(n)]
        # Build reverse adjacency list
        rev_adj: List[List[int]] = [[] for _ in range(n)]

        for src, dst, kind, rclass in edges:
            u = node_to_id[src]
            v = node_to_id[dst]
            k_val = 0 if kind == DepKind.RUNTIME else 1
            fwd_adj[u].append((v, k_val, int(rclass)))
            rev_adj[v].append(u)

        # Construct Forward CSR
        fwd_offsets = array.array("q", [0] * (n + 1))
        fwd_targets = array.array("i")
        edge_kinds = array.array("B")
        edge_ranges = array.array("B")

        total_fwd = 0
        for i in range(n):
            fwd_offsets[i] = total_fwd
            for v, k, r in fwd_adj[i]:
                fwd_targets.append(v)
                edge_kinds.append(k)
                edge_ranges.append(r)
                total_fwd += 1
        fwd_offsets[n] = total_fwd

        # Construct Reverse CSR
        rev_offsets = array.array("q", [0] * (n + 1))
        rev_sources = array.array("i")

        total_rev = 0
        for i in range(n):
            rev_offsets[i] = total_rev
            for u in rev_adj[i]:
                rev_sources.append(u)
                total_rev += 1
        rev_offsets[n] = total_rev

        return cls(
            node_to_id=node_to_id,
            id_to_node=id_to_node,
            fwd_offsets=fwd_offsets,
            fwd_targets=fwd_targets,
            rev_offsets=rev_offsets,
            rev_sources=rev_sources,
            edge_kinds=edge_kinds,
            edge_ranges=edge_ranges,
        )

    def get_direct_dependents(self, pkg_name: str) -> List[str]:
        """Return packages directly depending on pkg_name (1-hop reverse)."""
        idx = self.node_to_id.get(pkg_name)
        if idx is None:
            return []
        start = self.rev_offsets[idx]
        end = self.rev_offsets[idx + 1]
        return [self.id_to_node[self.rev_sources[k]] for k in range(start, end)]

    def get_direct_dependencies(self, pkg_name: str) -> List[str]:
        """Return packages directly depended upon by pkg_name (1-hop forward)."""
        idx = self.node_to_id.get(pkg_name)
        if idx is None:
            return []
        start = self.fwd_offsets[idx]
        end = self.fwd_offsets[idx + 1]
        return [self.id_to_node[self.fwd_targets[k]] for k in range(start, end)]

    def reverse_bfs_blast_radius(
        self, pkg_name: str, budget: Optional[TraversalBudget] = None
    ) -> Tuple[Set[str], Dict[str, int], bool]:
        """Perform reverse BFS to find all upstream dependents up to depth cap.
        Returns: (reachable_nodes_set, depth_map, is_truncated)
        """
        idx = self.node_to_id.get(pkg_name)
        if idx is None:
            return set(), {}, False

        if budget is None:
            budget = TraversalBudget()

        visited: Set[int] = {idx}
        depths: Dict[int, int] = {idx: 0}
        queue: List[int] = [idx]

        while queue and not budget.truncated:
            curr = queue.pop(0)
            curr_depth = depths[curr]

            start = self.rev_offsets[curr]
            end = self.rev_offsets[curr + 1]

            for k in range(start, end):
                parent = self.rev_sources[k]
                if parent not in visited:
                    if not budget.step(curr_depth + 1):
                        break
                    visited.add(parent)
                    depths[parent] = curr_depth + 1
                    queue.append(parent)

        name_set = {self.id_to_node[i] for i in visited}
        name_depths = {self.id_to_node[i]: d for i, d in depths.items()}
        return name_set, name_depths, budget.truncated
