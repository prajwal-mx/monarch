"""Dynamic Poll-Tier Assignment Loop.
Closes the feedback loop from consequence scoring to risk-weighted polling per Section 1.3.1.
"""

from __future__ import annotations

from typing import Dict
from monarch.common.storage import Storage


class TierManager:
    """Updates database poll_tier based on consequence scores."""

    def __init__(self, storage: Storage):
        self.storage = storage

    def assign_tiers_from_scores(self, scores: Dict[str, float]) -> Dict[str, int]:
        """Assign tiers 0-3 based on consequence percentiles and persist to database."""
        sorted_pkgs = sorted(scores.keys(), key=lambda p: scores[p], reverse=True)
        total = len(sorted_pkgs)

        tier_assignments: Dict[str, int] = {}
        cur = self.storage.conn.cursor()

        for idx, pkg in enumerate(sorted_pkgs):
            ratio = idx / max(1, total)
            if ratio <= 0.10:  # Top 10%
                tier = 0
            elif ratio <= 0.30:  # Next 20%
                tier = 1
            elif ratio <= 0.60:  # Next 30%
                tier = 2
            else:
                tier = 3

            tier_assignments[pkg] = tier
            cur.execute(
                """
                UPDATE package SET poll_tier = ?
                WHERE ecosystem = 'npm' AND name_normalized = ?
                """,
                (tier, pkg.lower().strip()),
            )

        self.storage.conn.commit()
        return tier_assignments
