"""Tarjan's Strongly Connected Components (SCC) algorithm for graph condensation.
Iterative implementation to eliminate recursion limit issues on large graphs.
Guarantees acyclic DAG properties for downstream traversal per Section 3.A.2 and 5.1.
"""

from __future__ import annotations

from typing import Dict, List, Set, Tuple
from monarch.graph.csr import CSRGraph


class TarjanSCC:
    """Computes Strongly Connected Components and condensed DAG using an iterative Tarjan algorithm."""

    def __init__(self, graph: CSRGraph):
        self.graph = graph
        self.n = graph.num_nodes
        self.components: List[List[int]] = []
        self.node_to_scc: Dict[int, int] = {}

    def compute(self) -> Tuple[List[List[int]], Dict[int, int]]:
        """Run iterative Tarjan algorithm to prevent Python RecursionError on large graphs."""
        n = self.n
        indices = [-1] * n
        lowlinks = [-1] * n
        on_stack = [False] * n
        scc_stack: List[int] = []
        current_index = 0

        self.components = []
        self.node_to_scc = {}

        # Iterative call stack: (u, current_edge_idx, end_edge_idx)
        for root in range(n):
            if indices[root] != -1:
                continue

            call_stack = [(root, self.graph.fwd_offsets[root], self.graph.fwd_offsets[root + 1])]
            indices[root] = current_index
            lowlinks[root] = current_index
            current_index += 1
            scc_stack.append(root)
            on_stack[root] = True

            while call_stack:
                u, edge_idx, end_idx = call_stack[-1]

                if edge_idx < end_idx:
                    # Advance edge pointer for current frame
                    call_stack[-1] = (u, edge_idx + 1, end_idx)
                    v = self.graph.fwd_targets[edge_idx]

                    if indices[v] == -1:
                        # Forward tree edge: push v to call stack
                        indices[v] = current_index
                        lowlinks[v] = current_index
                        current_index += 1
                        scc_stack.append(v)
                        on_stack[v] = True
                        call_stack.append((v, self.graph.fwd_offsets[v], self.graph.fwd_offsets[v + 1]))
                    elif on_stack[v]:
                        lowlinks[u] = min(lowlinks[u], indices[v])
                else:
                    # Finished exploring all edges from u
                    call_stack.pop()

                    if lowlinks[u] == indices[u]:
                        component: List[int] = []
                        while True:
                            w = scc_stack.pop()
                            on_stack[w] = False
                            component.append(w)
                            if w == u:
                                break
                        self.components.append(component)

                    if call_stack:
                        parent = call_stack[-1][0]
                        lowlinks[parent] = min(lowlinks[parent], lowlinks[u])

        for scc_id, comp in enumerate(self.components):
            for u in comp:
                self.node_to_scc[u] = scc_id

        return self.components, self.node_to_scc

    def get_condensed_dag(self) -> Dict[int, Set[int]]:
        """Build the condensed DAG adjacency list where nodes are SCC IDs."""
        if not self.components:
            self.compute()

        dag: Dict[int, Set[int]] = {i: set() for i in range(len(self.components))}
        for u in range(self.n):
            u_scc = self.node_to_scc[u]
            start = self.graph.fwd_offsets[u]
            end = self.graph.fwd_offsets[u + 1]
            for k in range(start, end):
                v = self.graph.fwd_targets[k]
                v_scc = self.node_to_scc[v]
                if u_scc != v_scc:
                    dag[u_scc].add(v_scc)

        return dag
