"""Content-Addressed Storage (CAS) for immutable raw payloads.
Implements the moat substrate specified in Section 1.1 and 1.3.2.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Optional, Tuple
from monarch.common.storage import Storage


class ContentAddressedStorage:
    """Manages immutable, content-addressed storage of raw API responses and tarballs."""

    def __init__(self, storage: Storage, local_blob_dir: Optional[str] = None):
        self.storage = storage
        self.blob_dir = Path(local_blob_dir) if local_blob_dir else None
        if self.blob_dir:
            self.blob_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def compute_sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def put(self, data: bytes) -> str:
        """Store content and return its sha256 hash."""
        sha256 = self.compute_sha256(data)
        # Store in relational CAS table
        self.storage.put_blob(data, sha256)

        # Optionally store in filesystem blob store
        if self.blob_dir:
            blob_path = self.blob_dir / sha256[:2] / sha256[2:4] / sha256
            blob_path.parent.mkdir(parents=True, exist_ok=True)
            if not blob_path.exists():
                with open(blob_path, "wb") as f:
                    f.write(data)
        return sha256

    def get(self, sha256: str) -> Optional[bytes]:
        """Retrieve content by sha256 hash."""
        if self.blob_dir:
            blob_path = self.blob_dir / sha256[:2] / sha256[2:4] / sha256
            if blob_path.exists():
                with open(blob_path, "rb") as f:
                    return f.read()
        return self.storage.get_blob(sha256)
