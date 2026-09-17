"""Consequence / Blast Radius Engine.
Implements the exact scoring formulation, sampled betweenness, depth decay, and
percentile rank normalisation specified in Section 3.A.
"""

from __future__ import annotations

import math
import random
from typing import Dict, List, Optional, Set, Tuple
from monarch.common.storage import Storage
from monarch.graph.epoch import Epoch


class ConsequenceEngine:
    """Computes Consequence Score C(v) in [0, 100] with percentile rank normalisation."""

    def __init__(
        self,
        storage: Storage,
        epoch: Epoch,
        alpha1: float = 2.0,  # log reach
        alpha2: float = 1.5,  # log download-weighted depth decay
        alpha3: float = 3.0,  # betweenness
        alpha4: float = 1.0,  # depth penetration
        alpha5: float = 1.5,  # install hook multiplier
        alpha6: float = 1.2,  # asymmetry ratio (left-pad)
        gamma: float = 0.8,   # depth decay factor
    ):
        self.storage = storage
        self.epoch = epoch
        self.alpha1 = alpha1
        self.alpha2 = alpha2
        self.alpha3 = alpha3
        self.alpha4 = alpha4
        self.alpha5 = alpha5
        self.alpha6 = alpha6
        self.gamma = gamma

    def _approximate_betweenness(self, k_samples: int = 100) -> Dict[str, float]:
        """Brandes algorithm with k-source sampling pivots (§3.A.5)."""
        graph = self.epoch.csr_graph
        nodes = graph.id_to_node
        n = len(nodes)
        betweenness: Dict[int, float] = {i: 0.0 for i in range(n)}
        if n <= 1:
            return {nodes[i]: 0.0 for i in range(n)}

        # Stratified degree sampling
        sample_size = min(k_samples, n)
        pivots = random.sample(range(n), sample_size)

        for s in pivots:
            # BFS from pivot s
            stack: List[int] = []
            pred: Dict[int, List[int]] = {w: [] for w in range(n)}
            sigma = [0] * n
            sigma[s] = 1
            d = [-1] * n
            d[s] = 0
            queue: List[int] = [s]

            while queue:
                v = queue.pop(0)
                stack.append(v)
                start = graph.fwd_offsets[v]
                end = graph.fwd_offsets[v + 1]
                for idx in range(start, end):
                    w = graph.fwd_targets[idx]
                    if d[w] < 0:
                        queue.append(w)
                        d[w] = d[v] + 1
                    if d[w] == d[v] + 1:
                        sigma[w] += sigma[v]
                        pred[w].append(v)

            delta = [0.0] * n
            while stack:
                w = stack.pop()
                for v in pred[w]:
                    if sigma[w] > 0:
                        delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w])
                if w != s:
                    betweenness[w] += delta[w]

        # Normalise by (n/sample_size) and scale to [0, 1]
        scale = (n / sample_size) / max(1.0, (n - 1) * (n - 2))
        return {nodes[i]: betweenness[i] * scale for i in range(n)}

    def compute_all_consequence_scores(
        self, download_map: Optional[Dict[str, int]] = None
    ) -> Dict[str, float]:
        """Compute raw C_raw and convert to percentile rank C(v) in [0, 100]."""
        graph = self.epoch.csr_graph
        nodes = graph.id_to_node
        if not nodes:
            return {}

        download_map = download_map or {}
        betweenness_map = self._approximate_betweenness(k_samples=min(100, len(nodes)))

        # Fetch install hooks from DB
        cur = self.storage.conn.cursor()
        cur.execute(
            """
            SELECT p.name, MAX(pv.has_install_hook)
            FROM package p
            JOIN package_version pv ON p.package_id = pv.package_id
            GROUP BY p.name
            """
        )
        hooks_map = {row[0]: bool(row[1]) for row in cur.fetchall()}

        raw_scores: Dict[str, float] = {}

        for pkg in nodes:
            # 1. Reverse reach set & depth map
            reach_set, depth_map, _ = graph.reverse_bfs_blast_radius(pkg)
            r_card = len(reach_set)

            # 2. Download-weighted depth decay
            weighted_dl = 0.0
            for u in reach_set:
                u_dl = download_map.get(u, 1000)  # default baseline downloads
                u_depth = depth_map.get(u, 1)
                weighted_dl += u_dl * (self.gamma ** u_depth)

            # 3. Betweenness
            betw = betweenness_map.get(pkg, 0.0)

            # 4. Depth penetration (mean depth in dependent trees)
            penetration = (sum(depth_map.values()) / max(1, len(depth_map))) if depth_map else 1.0

            # 5. Install hook multiplier (1.5x for hooks per §3.A.5)
            hook_term = 1.5 if hooks_map.get(pkg, False) else 1.0

            # 6. Asymmetry ratio (left-pad metric)
            direct_deps = len(graph.get_direct_dependencies(pkg))
            asymmetry = r_card / max(1, direct_deps)

            c_raw = (
                self.alpha1 * math.log10(1 + r_card)
                + self.alpha2 * math.log10(1 + weighted_dl)
                + self.alpha3 * betw
                + self.alpha4 * penetration
                + self.alpha5 * hook_term
                + self.alpha6 * math.log10(1 + asymmetry)
            )
            raw_scores[pkg] = c_raw

        # Continuous normalisation preserving true structural blast-radius distances (§3.A.5)
        c_min = min(raw_scores.values()) if raw_scores else 0.0
        c_max = max(raw_scores.values()) if raw_scores else 1.0
        consequence_scores: Dict[str, float] = {}

        for pkg, c_raw in raw_scores.items():
            if c_max > c_min:
                scaled = ((c_raw - c_min) / (c_max - c_min)) * 100.0
            else:
                scaled = 50.0
            consequence_scores[pkg] = round(scaled, 1)

        return consequence_scores

    def compute_all_consequence_details(
        self, download_map: Optional[Dict[str, int]] = None
    ) -> Dict[str, Dict[str, Any]]:
        """Compute consequence scores alongside all constituent raw metrics."""
        graph = self.epoch.csr_graph
        nodes = graph.id_to_node
        if not nodes:
            return {}

        download_map = download_map or {}
        betweenness_map = self._approximate_betweenness(k_samples=min(100, len(nodes)))

        cur = self.storage.conn.cursor()
        cur.execute(
            """
            SELECT p.name, MAX(pv.has_install_hook)
            FROM package p
            JOIN package_version pv ON p.package_id = pv.package_id
            GROUP BY p.name
            """
        )
        hooks_map = {row[0]: bool(row[1]) for row in cur.fetchall()}

        details: Dict[str, Dict[str, Any]] = {}
        raw_scores: Dict[str, float] = {}

        for pkg in nodes:
            reach_set, depth_map, _ = graph.reverse_bfs_blast_radius(pkg)
            r_card = len(reach_set)

            weighted_dl = 0.0
            for u in reach_set:
                u_dl = download_map.get(u, 1000)
                u_depth = depth_map.get(u, 1)
                weighted_dl += u_dl * (self.gamma ** u_depth)

            betw = betweenness_map.get(pkg, 0.0)
            penetration = (sum(depth_map.values()) / max(1, len(depth_map))) if depth_map else 1.0
            hook_term = 1.5 if hooks_map.get(pkg, False) else 1.0
            direct_deps = len(graph.get_direct_dependencies(pkg))
            asymmetry = r_card / max(1, direct_deps)

            c_raw = (
                self.alpha1 * math.log10(1 + r_card)
                + self.alpha2 * math.log10(1 + weighted_dl)
                + self.alpha3 * betw
                + self.alpha4 * penetration
                + self.alpha5 * hook_term
                + self.alpha6 * math.log10(1 + asymmetry)
            )
            raw_scores[pkg] = c_raw
            details[pkg] = {
                "raw_score": round(c_raw, 4),
                "reverse_reach": r_card,
                "mean_depth": round(penetration, 2),
                "betweenness": round(betw, 4),
                "has_install_hook": bool(hooks_map.get(pkg, False)),
                "asymmetry_ratio": round(asymmetry, 2),
                "direct_deps_count": direct_deps,
            }

        c_min = min(raw_scores.values()) if raw_scores else 0.0
        c_max = max(raw_scores.values()) if raw_scores else 1.0

        for pkg, c_raw in raw_scores.items():
            if c_max > c_min:
                scaled = ((c_raw - c_min) / (c_max - c_min)) * 100.0
            else:
                scaled = 50.0
            details[pkg]["consequence_score"] = round(scaled, 1)

        return details
