"""Lengauer-Tarjan Dominator Tree computation for software dependency DAGs.
Implements Section 3.C.2 (identifies direct dependencies that provably dominate transitive risks).
"""

from __future__ import annotations

from typing import Dict, List, Set, Tuple


class DominatorTree:
    """Computes immediate dominators and dominated subtrees using Lengauer-Tarjan."""

    def __init__(self, root: str, adjacency: Dict[str, List[str]]):
        self.root = root
        self.adj = adjacency
        self.nodes = list(set([root] + list(adjacency.keys()) + [v for vs in adjacency.values() for v in vs]))
        self.node_to_idx = {node: i for i, node in enumerate(self.nodes)}
        self.idx_to_node = self.nodes
        self.n = len(self.nodes)

        # Lengauer-Tarjan data structures
        self.parent = [-1] * self.n
        self.semi = [-1] * self.n
        self.idom = [-1] * self.n
        self.ancestor = [-1] * self.n
        self.best = list(range(self.n))
        self.bucket: List[Set[int]] = [set() for _ in range(self.n)]

        self.dfn = [-1] * self.n
        self.vertex = [-1] * self.n
        self.pred: List[List[int]] = [[] for _ in range(self.n)]
        self.timer = 0

    def _dfs(self, v: int) -> None:
        self.dfn[v] = self.timer
        self.vertex[self.timer] = v
        self.semi[v] = self.timer
        self.timer += 1

        v_name = self.idx_to_node[v]
        for w_name in self.adj.get(v_name, []):
            w = self.node_to_idx[w_name]
            self.pred[w].append(v)
            if self.dfn[w] == -1:
                self.parent[w] = v
                self._dfs(w)

    def _find(self, v: int) -> int:
        if self.ancestor[v] == -1:
            return v
        self._compress(v)
        return self.best[v]

    def _compress(self, v: int) -> None:
        anc = self.ancestor[v]
        if self.ancestor[anc] != -1:
            self._compress(anc)
            if self.semi[self.best[anc]] < self.semi[self.best[v]]:
                self.best[v] = self.best[anc]
            self.ancestor[v] = self.ancestor[anc]

    def _link(self, v: int, w: int) -> None:
        self.ancestor[w] = v

    def compute(self) -> Dict[str, Optional[str]]:
        """Compute immediate dominators (idom). idom[u] dominates u."""
        root_idx = self.node_to_idx[self.root]
        self._dfs(root_idx)

        # Step 2 & 3: Compute semidominators and evaluate buckets
        for i in range(self.timer - 1, 0, -1):
            w = self.vertex[i]
            for v in self.pred[w]:
                if self.dfn[v] != -1:
                    u = self._find(v)
                    if self.semi[u] < self.semi[w]:
                        self.semi[w] = self.semi[u]

            self.bucket[self.vertex[self.semi[w]]].add(w)
            self._link(self.parent[w], w)

            p_w = self.parent[w]
            for v in list(self.bucket[p_w]):
                u = self._find(v)
                self.idom[v] = u if self.semi[u] < self.semi[v] else p_w
            self.bucket[p_w].clear()

        # Step 4: Adjust idom
        for i in range(1, self.timer):
            w = self.vertex[i]
            if self.idom[w] != self.vertex[self.semi[w]]:
                self.idom[w] = self.idom[self.idom[w]]

        result: Dict[str, Optional[str]] = {}
        for i, node in enumerate(self.idx_to_node):
            if i == root_idx:
                result[node] = None
            elif self.idom[i] != -1:
                result[node] = self.idx_to_node[self.idom[i]]
            else:
                result[node] = None

        return result

    def get_dominated_sets(self) -> Dict[str, Set[str]]:
        """For each node d, return the set of all nodes strictly dominated by d."""
        idoms = self.compute()
        # Invert idom: d -> children
        tree: Dict[str, List[str]] = {n: [] for n in self.nodes}
        for node, parent in idoms.items():
            if parent:
                tree[parent].append(node)

        dominated: Dict[str, Set[str]] = {n: set() for n in self.nodes}

        def collect(u: str) -> Set[str]:
            sub: Set[str] = set()
            for child in tree.get(u, []):
                sub.add(child)
                sub.update(collect(child))
            dominated[u] = sub
            return sub

        collect(self.root)
        return dominated
