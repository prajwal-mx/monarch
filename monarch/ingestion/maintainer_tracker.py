"""Maintainer transition tracking and observation gap calculation.
Implements the moat table logic and ethical governance specified in Sections 2.2, 8.2, and 8.3.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from monarch.common.models import (
    Ecosystem,
    MaintainerEventType,
)
from monarch.common.storage import Storage


def hash_email(email: str) -> Tuple[str, str]:
    """Hash raw email with sha256 and extract domain only. Never store raw PII (§8.3)."""
    cleaned = email.strip().lower()
    email_hash = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()
    domain = cleaned.split("@")[-1] if "@" in cleaned else ""
    return email_hash, domain


class MaintainerTracker:
    def __init__(self, storage: Storage):
        self.storage = storage

    def get_current_maintainers(self, package_id: int) -> Set[str]:
        cur = self.storage.conn.cursor()
        cur.execute(
            """
            SELECT m.handle
            FROM package_maintainer_current pmc
            JOIN maintainer m ON pmc.maintainer_id = m.maintainer_id
            WHERE pmc.package_id = ?
            """,
            (package_id,),
        )
        return {row[0] for row in cur.fetchall()}

    def process_packument_maintainers(
        self,
        package_id: int,
        observed_maintainers: List[Dict[str, str]],
        observed_at: datetime,
        last_observed_at: Optional[datetime] = None,
        version_id: Optional[int] = None,
        publisher_handle: Optional[str] = None,
    ) -> List[int]:
        """Diff maintainer sets and record events with observation_gap."""
        cur_handles = self.get_current_maintainers(package_id)
        new_handles = {m["name"] for m in observed_maintainers if "name" in m}

        # Calculate uncertainty window (§2.2, §8.2)
        observation_gap_sec: Optional[float] = None
        if last_observed_at:
            observation_gap_sec = (observed_at - last_observed_at).total_seconds()

        added = new_handles - cur_handles
        removed = cur_handles - new_handles
        event_ids = []

        cur = self.storage.conn.cursor()

        # Handle ADDED
        for handle in added:
            m_info = next((m for m in observed_maintainers if m.get("name") == handle), {})
            email = m_info.get("email", "")
            email_hash, email_domain = hash_email(email) if email else (None, None)

            m_id = self.storage.upsert_maintainer(
                handle=handle,
                ecosystem=Ecosystem.NPM,
                email_hash=email_hash,
                email_domain=email_domain,
            )

            # Insert into package_maintainer_current
            cur.execute(
                """
                INSERT OR IGNORE INTO package_maintainer_current (package_id, maintainer_id, since)
                VALUES (?, ?, ?)
                """,
                (package_id, m_id, observed_at.isoformat()),
            )

            evidence = {
                "fact": "maintainer_set_delta",
                "value": f"+{handle}",
                "observation_gap_seconds": observation_gap_sec,
                "observed_at": observed_at.isoformat(),
            }
            eid = self.storage.add_maintainer_event(
                package_id=package_id,
                maintainer_id=m_id,
                event_type=MaintainerEventType.ADDED,
                observed_at=observed_at,
                observation_gap_seconds=observation_gap_sec,
                version_id=version_id,
                evidence_blob=json.dumps(evidence),
            )
            event_ids.append(eid)

        # Handle REMOVED
        for handle in removed:
            cur.execute("SELECT maintainer_id FROM maintainer WHERE handle = ?", (handle,))
            row = cur.fetchone()
            if row:
                m_id = row[0]
                cur.execute(
                    "DELETE FROM package_maintainer_current WHERE package_id = ? AND maintainer_id = ?",
                    (package_id, m_id),
                )
                evidence = {
                    "fact": "maintainer_set_delta",
                    "value": f"-{handle}",
                    "observation_gap_seconds": observation_gap_sec,
                    "observed_at": observed_at.isoformat(),
                }
                eid = self.storage.add_maintainer_event(
                    package_id=package_id,
                    maintainer_id=m_id,
                    event_type=MaintainerEventType.REMOVED,
                    observed_at=observed_at,
                    observation_gap_seconds=observation_gap_sec,
                    version_id=version_id,
                    evidence_blob=json.dumps(evidence),
                )
                event_ids.append(eid)

        # Handle Sole Owner transitions
        prior_count = len(cur_handles)
        new_count = len(new_handles)
        if prior_count > 1 and new_count == 1:
            sole_handle = list(new_handles)[0]
            cur.execute("SELECT maintainer_id FROM maintainer WHERE handle = ?", (sole_handle,))
            row = cur.fetchone()
            if row:
                eid = self.storage.add_maintainer_event(
                    package_id=package_id,
                    maintainer_id=row[0],
                    event_type=MaintainerEventType.SOLE_OWNER_BEGIN,
                    observed_at=observed_at,
                    observation_gap_seconds=observation_gap_sec,
                    version_id=version_id,
                    evidence_blob=json.dumps({"fact": "sole_owner_begin", "maintainer": sole_handle}),
                )
                event_ids.append(eid)
        elif prior_count == 1 and new_count > 1:
            for handle in new_handles:
                cur.execute("SELECT maintainer_id FROM maintainer WHERE handle = ?", (handle,))
                row = cur.fetchone()
                if row:
                    eid = self.storage.add_maintainer_event(
                        package_id=package_id,
                        maintainer_id=row[0],
                        event_type=MaintainerEventType.SOLE_OWNER_END,
                        observed_at=observed_at,
                        observation_gap_seconds=observation_gap_sec,
                        version_id=version_id,
                        evidence_blob=json.dumps({"fact": "sole_owner_end", "maintainer_count": new_count}),
                    )
                    event_ids.append(eid)
                    break

        # Check publisher first publish
        if publisher_handle:
            cur.execute("SELECT maintainer_id FROM maintainer WHERE handle = ?", (publisher_handle,))
            row = cur.fetchone()
            if row:
                pub_id = row[0]
                cur.execute(
                    """
                    SELECT COUNT(*) FROM package_version
                    WHERE package_id = ? AND published_by_id = ?
                    """,
                    (package_id, pub_id),
                )
                prior_publishes = cur.fetchone()[0]
                if prior_publishes == 0:
                    eid = self.storage.add_maintainer_event(
                        package_id=package_id,
                        maintainer_id=pub_id,
                        event_type=MaintainerEventType.FIRST_PUBLISH,
                        observed_at=observed_at,
                        observation_gap_seconds=observation_gap_sec,
                        version_id=version_id,
                        evidence_blob=json.dumps({"fact": "first_publish_by_new_owner", "handle": publisher_handle}),
                    )
                    event_ids.append(eid)

        self.storage.conn.commit()
        return event_ids
