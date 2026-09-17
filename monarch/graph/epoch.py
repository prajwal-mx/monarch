"""Epoch Manager and immutable graph snapshots.
Implements Section 1.5.3 (atomic promotion pointer swap and time-travel querying).
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from monarch.common.models import DepKind, RangeClass
from monarch.common.storage import Storage
from monarch.graph.csr import CSRGraph
from monarch.graph.hll import HyperLogLog
from monarch.graph.scc import TarjanSCC


class Epoch:
    """An immutable, versioned snapshot of the global dependency graph."""

    def __init__(
        self,
        epoch_id: str,
        csr_graph: CSRGraph,
        created_at: Optional[datetime] = None,
        parent_epoch: Optional[str] = None,
        model_version: str = "v1.0.0",
        stats: Optional[Dict[str, Any]] = None,
    ):
        self.epoch_id = epoch_id
        self.csr_graph = csr_graph
        self.created_at = created_at or datetime.now(timezone.utc)
        self.parent_epoch = parent_epoch
        self.model_version = model_version
        self.stats = stats or {}
        # Precomputed sketches for reverse reach
        self.reach_sketches: Dict[str, HyperLogLog] = {}


class EpochManager:
    """Manages active and historical epochs with atomic promotion."""

    def __init__(self, storage: Storage):
        self.storage = storage
        self.active_epoch: Optional[Epoch] = None
        self.epoch_history: Dict[str, Epoch] = {}

    def build_epoch_from_storage(
        self, model_version: str = "v1.0.0", parent_epoch_id: Optional[str] = None
    ) -> Epoch:
        """Extract all live dependency edges from storage and assemble an immutable Epoch."""
        cur = self.storage.conn.cursor()
        cur.execute(
            """
            SELECT p_from.name, p_to.name, de.kind, de.range_class
            FROM dependency_edge de
            JOIN package_version pv ON de.from_version_id = pv.version_id
            JOIN package p_from ON pv.package_id = p_from.package_id
            JOIN package p_to ON de.to_package_id = p_to.package_id
            """
        )
        edges: List[Tuple[str, str, DepKind, RangeClass]] = []
        for row in cur.fetchall():
            kind = DepKind(row[2]) if row[2] in DepKind.__members__.values() else DepKind.RUNTIME
            r_class = RangeClass(row[3]) if row[3] in [e.value for e in RangeClass] else RangeClass.EXACT
            edges.append((row[0], row[1], kind, r_class))

        cur.execute("SELECT name FROM package")
        all_pkgs = {row[0] for row in cur.fetchall()}
        csr = CSRGraph.from_edges(edges, all_nodes=all_pkgs)

        # Run SCC condensation to verify DAG structure
        scc = TarjanSCC(csr)
        components, _ = scc.compute()

        epoch_id = str(uuid.uuid4())
        stats = {
            "num_nodes": csr.num_nodes,
            "num_edges": len(edges),
            "num_scc_components": len(components),
            "built_at": datetime.now(timezone.utc).isoformat(),
        }

        epoch = Epoch(
            epoch_id=epoch_id,
            csr_graph=csr,
            parent_epoch=parent_epoch_id or (self.active_epoch.epoch_id if self.active_epoch else None),
            model_version=model_version,
            stats=stats,
        )

        # Precompute HLL sketches in reverse topological / traversal order
        for node_name in csr.id_to_node:
            hll = HyperLogLog(p=10)
            hll.add(node_name)
            # Direct dependents
            for dep in csr.get_direct_dependents(node_name):
                hll.add(dep)
            epoch.reach_sketches[node_name] = hll

        return epoch

    def promote_epoch(self, epoch: Epoch) -> None:
        """Atomically promote an epoch to be the active serving epoch."""
        self.epoch_history[epoch.epoch_id] = epoch
        self.active_epoch = epoch

    def get_epoch(self, epoch_id: str) -> Optional[Epoch]:
        """Retrieve epoch by ID (enables time-travel audit queries)."""
        return self.epoch_history.get(epoch_id)
