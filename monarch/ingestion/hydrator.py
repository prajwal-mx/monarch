"""Packument Hydrator and Tarball Signal Extractor.
Parses npm packuments, populates CAS, extracts dependencies, hooks, and provenance.
Implements Section 1.3.2, 1.3.3, and 1.3.4.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from monarch.common.models import (
    DepKind,
    Ecosystem,
    ProvenanceStatus,
    RangeClass,
)
from monarch.common.semver_utils import classify_range
from monarch.common.storage import Storage
from monarch.ingestion.cas import ContentAddressedStorage
from monarch.ingestion.maintainer_tracker import MaintainerTracker, hash_email


class Hydrator:
    def __init__(self, storage: Storage, cas: ContentAddressedStorage):
        self.storage = storage
        self.cas = cas
        self.maintainer_tracker = MaintainerTracker(storage)

    def fetch_from_registry(
        self, package_name: str, etag: Optional[str] = None, timeout: float = 10.0
    ) -> Tuple[Optional[int], int]:
        """Live HTTP fetch from https://registry.npmjs.org/{pkg}.
        Returns (package_id, http_status_code). Handles 304 Not Modified.
        """
        import urllib.request
        import urllib.error

        url = f"https://registry.npmjs.org/{package_name}"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "monarch-crawler/1.0",
                "Accept": "application/json",
            },
        )
        if etag:
            req.add_header("If-None-Match", etag)

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                new_etag = resp.headers.get("ETag")
                raw_bytes = resp.read()
                data = json.loads(raw_bytes.decode("utf-8"))
                pkg_id = self.hydrate_packument_json(
                    packument_dict=data, raw_bytes=raw_bytes, etag=new_etag
                )
                return pkg_id, status
        except urllib.error.HTTPError as e:
            if e.code == 304:
                return None, 304
            return None, e.code
        except Exception:
            return None, 500

    def hydrate_packument_json(
        self,
        packument_dict: Dict[str, Any],
        raw_bytes: Optional[bytes] = None,
        etag: Optional[str] = None,
        observed_at: Optional[datetime] = None,
    ) -> int:
        """Process a packument JSON dictionary and persist all derived entities."""
        if observed_at is None:
            observed_at = datetime.now(timezone.utc)

        pkg_name = packument_dict.get("name", "")
        if not pkg_name:
            raise ValueError("Packument missing required 'name' field")

        # 1. Store in CAS
        if raw_bytes is None:
            raw_bytes = json.dumps(packument_dict, sort_keys=True).encode("utf-8")
        raw_sha256 = self.cas.put(raw_bytes)
        self.storage.record_packument_pointer(pkg_name, observed_at, etag, raw_sha256)

        # 2. Extract repository metadata
        repo_data = packument_dict.get("repository", {})
        repo_url = repo_data.get("url") if isinstance(repo_data, dict) else str(repo_data) if repo_data else None
        repo_owner, repo_name = None, None
        if repo_url and "github.com" in repo_url:
            parts = repo_url.rstrip("/").replace(".git", "").split("/")
            if len(parts) >= 2:
                repo_owner, repo_name = parts[-2], parts[-1]

        # 3. Check prior package state for observation gap
        prior_pkg = self.storage.get_package(pkg_name, Ecosystem.NPM)
        last_polled_at = None
        if prior_pkg and prior_pkg.get("last_polled_at"):
            try:
                last_polled_at = datetime.fromisoformat(prior_pkg["last_polled_at"])
            except Exception:
                pass

        package_id = self.storage.upsert_package(
            name=pkg_name,
            ecosystem=Ecosystem.NPM,
            repo_url=repo_url,
            repo_owner=repo_owner,
            repo_name=repo_name,
            is_deprecated=bool(packument_dict.get("deprecated")),
        )

        # 4. Ingest Maintainers & Events
        maintainers = packument_dict.get("maintainers", [])
        self.maintainer_tracker.process_packument_maintainers(
            package_id=package_id,
            observed_maintainers=maintainers,
            observed_at=observed_at,
            last_observed_at=last_polled_at,
        )

        # 5. Ingest Versions & Dependencies
        versions_dict = packument_dict.get("versions", {})
        time_dict = packument_dict.get("time", {})

        for v_str, v_data in versions_dict.items():
            if not isinstance(v_data, dict):
                continue

            # Publication timestamp
            pub_time_str = time_dict.get(v_str)
            if pub_time_str:
                try:
                    pub_dt = datetime.fromisoformat(pub_time_str.replace("Z", "+00:00"))
                except Exception:
                    pub_dt = observed_at
            else:
                pub_dt = observed_at

            # Publisher info (_npmUser)
            npm_user = v_data.get("_npmUser", {})
            published_by_id = None
            if npm_user and "name" in npm_user:
                u_handle = npm_user["name"]
                u_email = npm_user.get("email", "")
                e_hash, e_dom = hash_email(u_email) if u_email else (None, None)
                published_by_id = self.storage.upsert_maintainer(
                    handle=u_handle,
                    ecosystem=Ecosystem.NPM,
                    email_hash=e_hash,
                    email_domain=e_dom,
                )

            # Install hooks
            scripts = v_data.get("scripts", {}) or {}
            hooks = [h for h in ("preinstall", "install", "postinstall") if h in scripts]
            has_hook = len(hooks) > 0

            # Distribution metrics
            dist = v_data.get("dist", {}) or {}
            unpacked_size = dist.get("unpackedSize")
            file_count = dist.get("fileCount")

            # Check native binaries
            has_native = bool(v_data.get("gypfile")) or any(
                f.endswith((".node", ".so", ".dll", ".wasm")) for f in v_data.get("files", [])
            )

            # Provenance & trusted publishing (§1.3.4, §3.B.5)
            has_prov = bool(dist.get("attestations")) or bool(v_data.get("_hasProvenance"))
            prov_status = ProvenanceStatus.ATTESTED if has_prov else ProvenanceStatus.UNATTESTED

            v_id = self.storage.upsert_package_version(
                package_id=package_id,
                version=v_str,
                published_at=pub_dt,
                published_by_id=published_by_id,
                unpacked_size=unpacked_size,
                file_count=file_count,
                has_install_hook=has_hook,
                install_hook_kind=hooks if has_hook else None,
                has_native_binary=has_native,
                provenance=prov_status,
                raw_blob_sha256=raw_sha256,
            )

            # Ingest dependency edges
            deps = v_data.get("dependencies", {}) or {}
            for dep_name, dep_range in deps.items():
                if not isinstance(dep_range, str):
                    continue
                dep_pkg_id = self.storage.upsert_package(name=dep_name, ecosystem=Ecosystem.NPM)
                r_class = classify_range(dep_range)
                self.storage.add_dependency_edge(
                    from_version_id=v_id,
                    to_package_id=dep_pkg_id,
                    kind=DepKind.RUNTIME,
                    range_raw=dep_range,
                    range_class=r_class,
                )

        # Update last_polled_at
        cur = self.storage.conn.cursor()
        cur.execute("UPDATE package SET last_polled_at = ? WHERE package_id = ?", (observed_at.isoformat(), package_id))
        self.storage.conn.commit()

        return package_id
