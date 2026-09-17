"""Two-tier graph representation: P-graph (package level) vs V-graph (version level).
Implements Section 1.5.2 and Section 3.A.4 (semver-gated propagation).
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple
from monarch.common.models import RangeClass
from monarch.common.semver_utils import propagation_probability
from monarch.common.storage import Storage
from monarch.graph.epoch import Epoch


class TwoTierGraphResolver:
    """Resolves reachability across P-graph (upper bound) and V-graph (semver-gated)."""

    def __init__(self, storage: Storage, active_epoch: Epoch):
        self.storage = storage
        self.epoch = active_epoch

    def calculate_p_graph_reach(self, package_name: str) -> Tuple[int, Set[str]]:
        """Calculate naive P-graph reverse reachable upper bound."""
        nodes, _, _ = self.epoch.csr_graph.reverse_bfs_blast_radius(package_name)
        return len(nodes), nodes

    def calculate_semver_gated_reach(
        self, target_package: str, introduced_version: str, lockfile_damping: float = 0.5
    ) -> Tuple[int, Dict[str, float]]:
        """Calculate V-graph semver-gated propagation probabilities from an introduced version.
        Computes path-attenuated probability W(v, x) per §3.A.4.
        Returns (effective_affected_count, package_to_probability_map).
        """
        cur = self.storage.conn.cursor()
        # Query version edges for target package
        cur.execute(
            """
            SELECT p_from.name, de.range_raw, de.range_class
            FROM dependency_edge de
            JOIN package_version pv ON de.from_version_id = pv.version_id
            JOIN package p_from ON pv.package_id = p_from.package_id
            JOIN package p_to ON de.to_package_id = p_to.package_id
            WHERE p_to.name_normalized = ?
            """,
            (target_package.lower().strip(),),
        )
        rows = cur.fetchall()

        probabilities: Dict[str, float] = {target_package: 1.0}
        frontier: List[str] = [target_package]

        # 1-hop semver evaluation
        for row in rows:
            dep_consumer = row[0]
            r_raw = row[1]
            r_class = RangeClass(row[2])
            pi = propagation_probability(r_raw, r_class, introduced_version)
            pi_effective = pi * lockfile_damping
            if pi_effective > 0:
                probabilities[dep_consumer] = max(probabilities.get(dep_consumer, 0.0), pi_effective)
                frontier.append(dep_consumer)

        # Transitive propagation up the tree (attenuated by depth)
        for consumer in frontier[1:]:
            parents = self.epoch.csr_graph.get_direct_dependents(consumer)
            for parent in parents:
                if parent not in probabilities:
                    probabilities[parent] = probabilities[consumer] * 0.8

        affected_count = sum(1 for p in probabilities.values() if p >= 0.1)
        return affected_count, probabilities
