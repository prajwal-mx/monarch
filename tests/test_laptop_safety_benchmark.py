"""Hardware safety and memory footprint benchmark.
Verifies Requirement R6: resident memory stays strictly below 2.0 GiB RAM.
"""

import random
from monarch.common.models import DepKind, RangeClass
from monarch.common.resource_guard import ResourceGuard, MAX_RSS_BYTES
from monarch.graph.csr import CSRGraph
from monarch.graph.hll import HyperLogLog
from monarch.graph.scc import TarjanSCC


def test_laptop_memory_safety_benchmark():
    initial_rss = ResourceGuard.get_current_rss_bytes()
    assert initial_rss < MAX_RSS_BYTES

    # Synthesize a graph with 2,000 nodes and 10,000 edges
    nodes = [f"pkg_{i}" for i in range(2000)]
    edges = []
    for _ in range(10000):
        src = random.choice(nodes)
        dst = random.choice(nodes)
        if src != dst:
            edges.append((src, dst, DepKind.RUNTIME, RangeClass.CARET))

    csr = CSRGraph.from_edges(edges)
    scc = TarjanSCC(csr)
    components, _ = scc.compute()

    # Verify memory after building CSR and SCC
    current_rss = ResourceGuard.get_current_rss_bytes()
    rss_mb = current_rss / (1024 * 1024)

    # Must stay comfortably below the 2.0 GiB limit (typically < 350 MB)
    assert current_rss < MAX_RSS_BYTES, f"Memory exceeded safety limit: {rss_mb:.1f} MB"
    assert current_rss < 1024 * 1024 * 1024  # Under 1 GiB for this workload
