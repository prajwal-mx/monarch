"""Monarch Watch Public Ranking Index Generator.
Implements the public index and critical dependency fund attribution per Section 4.3.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from monarch.common.storage import Storage
from monarch.graph.epoch import Epoch


class MonarchWatchIndex:
    """Produces the public index ranking high-consequence packages with sponsorship routing."""

    def __init__(self, storage: Storage, epoch: Epoch):
        self.storage = storage
        self.epoch = epoch

    def generate_index(
        self, consequence_scores: Dict[str, float], top_n: int = 25
    ) -> List[Dict[str, Any]]:
        """Generate top-N consequence ranking table with sponsorship and blast radius metrics."""
        sorted_pkgs = sorted(
            consequence_scores.keys(), key=lambda p: consequence_scores[p], reverse=True
        )[:top_n]

        cur = self.storage.conn.cursor()
        items = []

        for rank, pkg in enumerate(sorted_pkgs, 1):
            cur.execute(
                """
                SELECT p.repo_owner, p.repo_name, p.poll_tier, MAX(pv.has_install_hook)
                FROM package p
                LEFT JOIN package_version pv ON p.package_id = pv.package_id
                WHERE p.name_normalized = ?
                GROUP BY p.package_id
                """,
                (pkg.lower().strip(),),
            )
            row = cur.fetchone()
            repo_owner = row[0] if row and row[0] else None
            poll_tier = row[2] if row else 3
            has_hook = bool(row[3]) if row else False

            reach_set, _, _ = self.epoch.csr_graph.reverse_bfs_blast_radius(pkg)

            sponsor_url = f"https://github.com/sponsors/{repo_owner}" if repo_owner else f"https://opencollective.com/{pkg}"

            items.append({
                "rank": rank,
                "package": pkg,
                "consequence_score": consequence_scores[pkg],
                "reverse_reach": len(reach_set),
                "poll_tier": poll_tier,
                "has_install_hook": has_hook,
                "sponsor_link": sponsor_url,
            })

        return items
