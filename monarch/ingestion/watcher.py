"""npm replication change feed watcher with sequence checkpointing.
Implements Channel A of Section 1.3.1 and Section 5.4.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from monarch.common.storage import Storage


class ReplicationWatcher:
    """Watches npm _changes replication feed with durable sequence checkpoints."""

    def __init__(self, storage: Storage, checkpoint_file: str = "watcher_seq.checkpoint"):
        self.storage = storage
        self.checkpoint_file = checkpoint_file
        self.last_seq: int = self._load_checkpoint()

    def _load_checkpoint(self) -> int:
        try:
            with open(self.checkpoint_file, "r") as f:
                return int(f.read().strip())
        except Exception:
            return 0

    def save_checkpoint(self, seq: int) -> None:
        self.last_seq = seq
        with open(self.checkpoint_file, "w") as f:
            f.write(str(seq))

    def fetch_live_changes(
        self, limit: int = 20, timeout: float = 10.0
    ) -> List[Dict[str, Any]]:
        """Poll live https://replicate.npmjs.com/_changes?since={seq}&limit={limit}."""
        import urllib.request
        import urllib.error

        url = f"https://replicate.npmjs.com/_changes?since={self.last_seq}&limit={limit}&include_docs=false"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "monarch-watcher/1.0", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("results", [])
        except Exception:
            return []

    def process_change_event(
        self, change_event: Dict[str, Any], hydrator_fn: Optional[Callable[[str], Any]] = None
    ) -> Dict[str, Any]:
        """Process a single change item from _changes."""
        seq = change_event.get("seq", self.last_seq)
        pkg_name = change_event.get("id", "")
        deleted = change_event.get("deleted", False)

        result = {
            "seq": seq,
            "package": pkg_name,
            "deleted": deleted,
            "status": "processed",
        }

        cur = self.storage.conn.cursor()

        if deleted and pkg_name:
            cur.execute(
                """
                UPDATE package SET is_unpublished = 1
                WHERE ecosystem = 'npm' AND name_normalized = ?
                """,
                (pkg_name.lower(),),
            )
            self.storage.conn.commit()
            result["status"] = "marked_unpublished"
        elif pkg_name and hydrator_fn:
            hydrator_fn(pkg_name)
            result["status"] = "hydrated"

        if isinstance(seq, int) and seq > self.last_seq:
            self.save_checkpoint(seq)

        return result
