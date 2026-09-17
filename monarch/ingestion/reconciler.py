"""Reconciliation sweep engine and FEED_GAP metrics tracker.
Implements Channel C of Section 1.3.1 and Section 5.7.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

from monarch.common.storage import Storage
from monarch.ingestion.hydrator import Hydrator

logger = logging.getLogger("monarch.reconciler")


class Reconciler:
    """Sweeps registry packages to catch events lost by replication feeds."""

    def __init__(self, storage: Storage, hydrator: Hydrator):
        self.storage = storage
        self.hydrator = hydrator
        self.feed_gaps: List[Dict[str, Any]] = []

    def reconcile_package(
        self,
        package_name: str,
        observed_packument: Dict[str, Any],
        observed_at: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Compare stored state against registry packument and record FEED_GAP if missed."""
        if observed_at is None:
            observed_at = datetime.now(timezone.utc)

        cur = self.storage.conn.cursor()
        norm = package_name.lower().strip()
        cur.execute(
            "SELECT package_id, last_polled_at, poll_tier FROM package WHERE name_normalized = ?",
            (norm,),
        )
        row = cur.fetchone()

        missed_versions: List[str] = []
        feed_gap_detected = False

        if row:
            pkg_id = row[0]
            # Fetch known versions from DB
            cur.execute("SELECT version FROM package_version WHERE package_id = ?", (pkg_id,))
            stored_versions: Set[str] = {r[0] for r in cur.fetchall()}
            registry_versions: Set[str] = set(observed_packument.get("versions", {}).keys())

            missed_versions = sorted(list(registry_versions - stored_versions))
            if missed_versions:
                feed_gap_detected = True
                gap_record = {
                    "package": package_name,
                    "missed_versions": missed_versions,
                    "observed_at": observed_at.isoformat(),
                    "reason": "upstream_replication_loss",
                }
                self.feed_gaps.append(gap_record)
                logger.warning(
                    f"FEED_GAP detected: {package_name} had {len(missed_versions)} versions missed by stream: {missed_versions}"
                )

        # Re-hydrate package with the authoritative document
        pkg_id = self.hydrator.hydrate_packument_json(
            packument_dict=observed_packument,
            observed_at=observed_at,
        )

        return {
            "package": package_name,
            "package_id": pkg_id,
            "feed_gap_detected": feed_gap_detected,
            "missed_versions": missed_versions,
            "reconciled_at": observed_at.isoformat(),
        }

    def get_feed_gap_metrics(self) -> List[Dict[str, Any]]:
        return list(self.feed_gaps)
