"""Unit tests for Phase 1 In-Memory CSR Graph, SCC condensation, and HLL sketches."""

from monarch.common.models import DepKind, RangeClass
from monarch.common.storage import Storage
from monarch.graph.csr import CSRGraph
from monarch.graph.hll import HyperLogLog
from monarch.graph.scc import TarjanSCC
from monarch.graph.epoch import EpochManager
from monarch.ingestion.bootstrap import bootstrap_database
from monarch.ingestion.cas import ContentAddressedStorage


def test_csr_forward_and_reverse_bfs():
    # Edges: A -> B -> C -> D
    edges = [
        ("A", "B", DepKind.RUNTIME, RangeClass.CARET),
        ("B", "C", DepKind.RUNTIME, RangeClass.CARET),
        ("C", "D", DepKind.RUNTIME, RangeClass.CARET),
        ("X", "B", DepKind.RUNTIME, RangeClass.CARET),
    ]
    csr = CSRGraph.from_edges(edges)

    assert csr.get_direct_dependencies("A") == ["B"]
    # Dependents of B are A and X
    assert sorted(csr.get_direct_dependents("B")) == ["A", "X"]

    # Reverse blast radius from D: reaches C, B, A, X
    reach_set, depths, _ = csr.reverse_bfs_blast_radius("D")
    assert reach_set == {"D", "C", "B", "A", "X"}
    assert depths["D"] == 0
    assert depths["C"] == 1
    assert depths["B"] == 2
    assert depths["A"] == 3


def test_tarjan_scc_cycle_condensation():
    # Cycle: 1 -> 2 -> 3 -> 1, and 3 -> 4
    edges = [
        ("pkg1", "pkg2", DepKind.RUNTIME, RangeClass.CARET),
        ("pkg2", "pkg3", DepKind.RUNTIME, RangeClass.CARET),
        ("pkg3", "pkg1", DepKind.RUNTIME, RangeClass.CARET),  # cycle!
        ("pkg3", "pkg4", DepKind.RUNTIME, RangeClass.CARET),
    ]
    csr = CSRGraph.from_edges(edges)
    scc = TarjanSCC(csr)
    components, node_to_scc = scc.compute()

    # The 3 nodes in cycle must share the same SCC component
    scc1 = node_to_scc[csr.node_to_id["pkg1"]]
    scc2 = node_to_scc[csr.node_to_id["pkg2"]]
    scc3 = node_to_scc[csr.node_to_id["pkg3"]]
    scc4 = node_to_scc[csr.node_to_id["pkg4"]]

    assert scc1 == scc2 == scc3
    assert scc4 != scc1

    dag = scc.get_condensed_dag()
    # In DAG, scc1 has edge to scc4, but no cycles exist!
    assert scc4 in dag[scc1]


def test_hyperloglog_cardinality_and_merge():
    hll1 = HyperLogLog(p=10)
    for i in range(500):
        hll1.add(f"pkg_{i}")

    hll2 = HyperLogLog(p=10)
    for i in range(400, 900):
        hll2.add(f"pkg_{i}")

    merged = hll1.merge(hll2)
    est = merged.cardinality()
    # Total unique elements is 900. Error should be within ~5%
    assert 800 <= est <= 1000


def test_epoch_manager_promotion():
    storage = Storage(":memory:")
    cas = ContentAddressedStorage(storage)
    bootstrap_database(storage, cas)

    mgr = EpochManager(storage)
    epoch = mgr.build_epoch_from_storage(model_version="test-1.0")
    mgr.promote_epoch(epoch)

    assert mgr.active_epoch is not None
    assert mgr.active_epoch.epoch_id == epoch.epoch_id
    assert mgr.get_epoch(epoch.epoch_id) is not None
