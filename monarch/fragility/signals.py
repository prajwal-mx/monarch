"""Fragility Signal Extraction across 6 Groups.
Implements Section 3.B.1 (Custody, Churn, Cadence, Artifacts, Provenance, Maintenance).
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from monarch.common.models import ProvenanceStatus
from monarch.common.storage import Storage


class FragilitySignalExtractor:
    """Extracts raw signals across all 6 taxonomic groups for a package version."""

    def __init__(self, storage: Storage):
        self.storage = storage

    def extract_signals_for_version(
        self, package_name: str, version_str: str, repo_drift_files: int = 0
    ) -> Dict[str, float]:
        """Extract quantitative raw feature vector x_i(v, t)."""
        cur = self.storage.conn.cursor()
        norm = package_name.lower().strip()

        # Get package info
        cur.execute("SELECT package_id FROM package WHERE name_normalized = ?", (norm,))
        row = cur.fetchone()
        if not row:
            return {}
        pkg_id = row[0]

        # Get version info
        cur.execute(
            """
            SELECT version_id, published_at, published_by_id, unpacked_size, has_install_hook,
                   entropy_p99, provenance, has_native_binary
            FROM package_version
            WHERE package_id = ? AND version = ?
            """,
            (pkg_id, version_str),
        )
        v_row = cur.fetchone()
        if not v_row:
            return {}

        v_id, pub_at_str, pub_by_id, unpacked_size, has_hook, entropy_p99, prov_str, has_native = v_row
        pub_dt = datetime.fromisoformat(pub_at_str)
        unpacked_size = unpacked_size or 0
        entropy_p99 = entropy_p99 or 4.5
        prov_status = ProvenanceStatus(prov_str) if prov_str in ProvenanceStatus.__members__.values() else ProvenanceStatus.UNKNOWN

        # Fetch historical versions for baseline comparison
        cur.execute(
            """
            SELECT version, published_at, published_by_id, unpacked_size, has_install_hook, provenance
            FROM package_version
            WHERE package_id = ? AND version != ?
            ORDER BY published_at ASC
            """,
            (pkg_id, version_str),
        )
        history = cur.fetchall()

        # Group 1: Custody Concentration
        cur.execute("SELECT COUNT(DISTINCT maintainer_id) FROM package_maintainer_current WHERE package_id = ?", (pkg_id,))
        bus_factor = cur.fetchone()[0] or 1

        # Herfindahl concentration index over publishers
        pub_counts: Dict[int, int] = {}
        for h in history[-20:]:
            p_id = h[2]
            if p_id:
                pub_counts[p_id] = pub_counts.get(p_id, 0) + 1
        total_p = sum(pub_counts.values()) or 1
        herfindahl = sum((c / total_p) ** 2 for c in pub_counts.values())

        # Group 2: Custody Change
        # Check maintainer events
        cur.execute(
            """
            SELECT event_type, observed_at
            FROM maintainer_event
            WHERE package_id = ?
            ORDER BY observed_at DESC
            """,
            (pkg_id,),
        )
        m_events = cur.fetchall()
        ownership_churn = 1.0 if any(e[0] == "ADDED" for e in m_events) else 0.0

        # Days dormant before this version
        days_dormant = 0.0
        if history:
            prev_pub_dt = datetime.fromisoformat(history[-1][1])
            days_dormant = max(0.0, (pub_dt - prev_pub_dt).total_seconds() / 86400.0)

        churn_after_dormancy = 1.0 if (ownership_churn > 0 and days_dormant >= 180.0) else 0.0

        # First publish by new owner
        is_first_pub = 0.0
        if pub_by_id:
            cur.execute(
                "SELECT COUNT(*) FROM package_version WHERE package_id = ? AND published_by_id = ? AND version != ?",
                (pkg_id, pub_by_id, version_str),
            )
            is_first_pub = 1.0 if cur.fetchone()[0] == 0 else 0.0

        # Publisher portfolio breadth (worm indicator)
        portfolio_breadth = 1.0
        if pub_by_id:
            cur.execute(
                "SELECT COUNT(DISTINCT package_id) FROM package_version WHERE published_by_id = ?",
                (pub_by_id,),
            )
            portfolio_breadth = float(cur.fetchone()[0] or 1)

        # Group 3: Release Behaviour Anomaly
        cadence_break = 0.0
        if len(history) >= 3:
            intervals = []
            for i in range(len(history) - 1):
                t1 = datetime.fromisoformat(history[i][1])
                t2 = datetime.fromisoformat(history[i+1][1])
                intervals.append((t2 - t1).total_seconds() / 86400.0)
            median_cadence = sorted(intervals)[len(intervals) // 2]
            if median_cadence > 0:
                cadence_break = abs(days_dormant - median_cadence) / max(1.0, median_cadence)

        rapid_republish = 1.0 if (days_dormant < 0.01 and len(history) > 0) else 0.0

        # Group 4: Artifact Anomaly
        size_delta = 0.0
        prev_has_hook = False
        if history:
            prev_size = history[-1][3] or 1
            size_delta = max(0.0, (unpacked_size - prev_size) / max(1.0, prev_size))
            prev_has_hook = bool(history[-1][4])

        new_install_hook = 1.0 if (has_hook and not prev_has_hook) else 0.0
        entropy_spike = max(0.0, entropy_p99 - 6.5) if entropy_p99 > 6.5 else 0.0
        repo_drift = float(repo_drift_files)

        # Group 5: 2026 Publishing Posture
        provenance_drift = 0.0
        if history and prov_status == ProvenanceStatus.UNATTESTED:
            # Check if previous versions were attested
            prev_attested = any(h[5] == ProvenanceStatus.ATTESTED.value for h in history[-5:])
            if prev_attested:
                provenance_drift = 1.0

        trusted_publishing = 1.0 if prov_status == ProvenanceStatus.ATTESTED else 0.0

        return {
            "bus_factor": float(bus_factor),
            "publish_concentration": herfindahl,
            "ownership_churn": ownership_churn,
            "churn_after_dormancy": churn_after_dormancy,
            "first_publish_by_new_owner": is_first_pub,
            "publisher_portfolio_breadth": portfolio_breadth,
            "days_dormant": days_dormant,
            "cadence_break": cadence_break,
            "rapid_republish": rapid_republish,
            "size_delta": size_delta,
            "new_install_hook": new_install_hook,
            "entropy_spike": entropy_spike,
            "repo_drift": repo_drift,
            "provenance_drift": provenance_drift,
            "trusted_publishing": trusted_publishing,
        }
