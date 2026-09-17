"""Relational and Content-Addressed Storage layer.
Implements the exact schemas from Section 2 using SQLite (with PostgreSQL compatibility).
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from monarch.common.models import (
    DepKind,
    Ecosystem,
    MaintainerEventType,
    ProvenanceStatus,
    RangeClass,
    ReachabilityTier,
    SignalClass,
    SignalStatus,
)
from monarch.common.semver_utils import semver_sort_key


class Storage:
    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self.conn.cursor()
        cur.executescript(
            """
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS cas_blob (
                sha256 TEXT PRIMARY KEY,
                content BLOB NOT NULL,
                size_bytes INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS packument_pointer (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL,
                fetched_at TEXT NOT NULL,
                etag TEXT,
                raw_blob_sha256 TEXT NOT NULL,
                FOREIGN KEY (raw_blob_sha256) REFERENCES cas_blob(sha256)
            );

            CREATE TABLE IF NOT EXISTS package (
                package_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ecosystem TEXT NOT NULL,
                name TEXT NOT NULL,
                name_normalized TEXT NOT NULL,
                purl TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                last_polled_at TEXT,
                poll_tier INTEGER NOT NULL DEFAULT 3,
                repo_url TEXT,
                repo_host TEXT,
                repo_owner TEXT,
                repo_name TEXT,
                is_deprecated INTEGER NOT NULL DEFAULT 0,
                is_unpublished INTEGER NOT NULL DEFAULT 0,
                latest_version_id INTEGER,
                UNIQUE (ecosystem, name_normalized)
            );

            CREATE TABLE IF NOT EXISTS maintainer (
                maintainer_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ecosystem TEXT NOT NULL,
                handle TEXT NOT NULL,
                email_hash TEXT,
                email_domain TEXT,
                first_seen_at TEXT NOT NULL,
                account_created_at TEXT,
                github_login TEXT,
                is_org_account INTEGER,
                UNIQUE (ecosystem, handle)
            );

            CREATE TABLE IF NOT EXISTS package_version (
                version_id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_id INTEGER NOT NULL REFERENCES package(package_id),
                version TEXT NOT NULL,
                version_semver TEXT,
                version_sort BLOB NOT NULL,
                published_at TEXT NOT NULL,
                published_by_id INTEGER REFERENCES maintainer(maintainer_id),
                is_prerelease INTEGER NOT NULL DEFAULT 0,
                is_yanked INTEGER NOT NULL DEFAULT 0,
                deprecated_msg TEXT,
                tarball_url TEXT,
                shasum TEXT,
                integrity TEXT,
                unpacked_size INTEGER,
                file_count INTEGER,
                file_list_hash TEXT,
                has_install_hook INTEGER NOT NULL DEFAULT 0,
                install_hook_kind TEXT,
                install_hook_hash TEXT,
                has_native_binary INTEGER NOT NULL DEFAULT 0,
                entropy_p99 REAL,
                provenance TEXT NOT NULL DEFAULT 'UNKNOWN',
                prov_source_repo TEXT,
                prov_build_wf TEXT,
                prov_verified_at TEXT,
                files_not_in_repo INTEGER,
                repo_drift_score REAL,
                raw_blob_sha256 TEXT,
                ingested_at TEXT NOT NULL,
                UNIQUE (package_id, version)
            );

            CREATE TABLE IF NOT EXISTS maintainer_event (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_id INTEGER NOT NULL REFERENCES package(package_id),
                maintainer_id INTEGER NOT NULL REFERENCES maintainer(maintainer_id),
                event_type TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                effective_at TEXT,
                observation_gap_seconds REAL,
                version_id INTEGER REFERENCES package_version(version_id),
                prev_state_hash TEXT,
                new_state_hash TEXT,
                evidence_blob TEXT NOT NULL,
                confidence REAL NOT NULL DEFAULT 1.0
            );

            CREATE TABLE IF NOT EXISTS package_maintainer_current (
                package_id INTEGER NOT NULL REFERENCES package(package_id),
                maintainer_id INTEGER NOT NULL REFERENCES maintainer(maintainer_id),
                since TEXT NOT NULL,
                PRIMARY KEY (package_id, maintainer_id)
            );

            CREATE TABLE IF NOT EXISTS dependency_edge (
                edge_id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_version_id INTEGER NOT NULL REFERENCES package_version(version_id),
                to_package_id INTEGER NOT NULL REFERENCES package(package_id),
                kind TEXT NOT NULL,
                range_raw TEXT NOT NULL,
                range_class INTEGER NOT NULL,
                range_min TEXT,
                range_max TEXT,
                range_includes_prerelease INTEGER NOT NULL DEFAULT 0,
                alias_target TEXT,
                is_optional INTEGER NOT NULL DEFAULT 0,
                UNIQUE (from_version_id, to_package_id, kind)
            );

            CREATE TABLE IF NOT EXISTS security_signal (
                signal_id INTEGER PRIMARY KEY AUTOINCREMENT,
                signal_class TEXT NOT NULL,
                signal_type TEXT NOT NULL,
                canonical_id TEXT,
                aliases TEXT,
                package_id INTEGER REFERENCES package(package_id),
                affected_ranges TEXT,
                severity_cvss REAL,
                severity_vector TEXT,
                epss_score REAL,
                kev_listed INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                source TEXT NOT NULL,
                published_at TEXT,
                ingested_at TEXT NOT NULL,
                evidence TEXT NOT NULL,
                model_version TEXT,
                epoch_id TEXT,
                confidence REAL,
                UNIQUE (source, canonical_id, package_id)
            );

            CREATE TABLE IF NOT EXISTS tenant (
                tenant_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                plan TEXT NOT NULL,
                data_region TEXT NOT NULL DEFAULT 'eu-west-1',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS project (
                project_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL REFERENCES tenant(tenant_id),
                name TEXT NOT NULL,
                repo_url TEXT,
                default_branch TEXT NOT NULL DEFAULT 'main',
                policy_id TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS project_snapshot (
                snapshot_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL REFERENCES project(project_id),
                git_sha TEXT,
                source_kind TEXT NOT NULL,
                source_hash TEXT NOT NULL,
                ingested_at TEXT NOT NULL,
                epoch_id TEXT NOT NULL,
                node_count INTEGER NOT NULL,
                direct_count INTEGER NOT NULL,
                max_depth INTEGER NOT NULL,
                UNIQUE (project_id, source_hash, epoch_id)
            );

            CREATE TABLE IF NOT EXISTS project_component (
                snapshot_id TEXT NOT NULL REFERENCES project_snapshot(snapshot_id),
                version_id INTEGER NOT NULL REFERENCES package_version(version_id),
                package_name TEXT NOT NULL,
                version_str TEXT NOT NULL,
                is_direct INTEGER NOT NULL,
                min_depth INTEGER NOT NULL,
                path_count INTEGER NOT NULL DEFAULT 1,
                dominator_of INTEGER NOT NULL DEFAULT 0,
                introduced_by TEXT,
                reachability INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (snapshot_id, version_id)
            );

            CREATE INDEX IF NOT EXISTS idx_pkg_tier ON package(poll_tier, last_polled_at);
            CREATE INDEX IF NOT EXISTS idx_pkg_norm ON package(ecosystem, name_normalized);
            CREATE INDEX IF NOT EXISTS idx_dep_reverse ON dependency_edge(to_package_id, kind);
            CREATE INDEX IF NOT EXISTS idx_proj_comp_ver ON project_component(version_id);
            """
        )
        self.conn.commit()

    # --- CAS Blob Operations ---
    def put_blob(self, content_bytes: bytes, sha256_hash: str) -> None:
        cur = self.conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()
        cur.execute(
            """
            INSERT OR IGNORE INTO cas_blob (sha256, content, size_bytes, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (sha256_hash, content_bytes, len(content_bytes), now_iso),
        )
        self.conn.commit()

    def get_blob(self, sha256_hash: str) -> Optional[bytes]:
        cur = self.conn.cursor()
        cur.execute("SELECT content FROM cas_blob WHERE sha256 = ?", (sha256_hash,))
        row = cur.fetchone()
        return bytes(row["content"]) if row else None

    def record_packument_pointer(
        self, package_name: str, fetched_at: datetime, etag: Optional[str], raw_blob_sha256: str
    ) -> None:
        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT INTO packument_pointer (package_name, fetched_at, etag, raw_blob_sha256)
            VALUES (?, ?, ?, ?)
            """,
            (package_name, fetched_at.isoformat(), etag, raw_blob_sha256),
        )
        self.conn.commit()

    # --- Package & Maintainer CRUD ---
    def upsert_package(
        self,
        name: str,
        ecosystem: Ecosystem = Ecosystem.NPM,
        poll_tier: int = 3,
        repo_url: Optional[str] = None,
        repo_owner: Optional[str] = None,
        repo_name: Optional[str] = None,
        is_deprecated: bool = False,
    ) -> int:
        norm = name.strip().lower()
        purl = f"pkg:{ecosystem.value}/{name}"
        now_iso = datetime.now(timezone.utc).isoformat()
        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT INTO package (ecosystem, name, name_normalized, purl, first_seen_at, poll_tier, repo_url, repo_owner, repo_name, is_deprecated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ecosystem, name_normalized) DO UPDATE SET
                poll_tier = excluded.poll_tier,
                repo_url = COALESCE(excluded.repo_url, package.repo_url),
                repo_owner = COALESCE(excluded.repo_owner, package.repo_owner),
                repo_name = COALESCE(excluded.repo_name, package.repo_name),
                is_deprecated = excluded.is_deprecated
            RETURNING package_id
            """,
            (ecosystem.value, name, norm, purl, now_iso, poll_tier, repo_url, repo_owner, repo_name, 1 if is_deprecated else 0),
        )
        row = cur.fetchone()
        self.conn.commit()
        return row[0]

    def get_package(self, name: str, ecosystem: Ecosystem = Ecosystem.NPM) -> Optional[dict]:
        norm = name.strip().lower()
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM package WHERE ecosystem = ? AND name_normalized = ?", (ecosystem.value, norm))
        row = cur.fetchone()
        return dict(row) if row else None

    def upsert_maintainer(
        self,
        handle: str,
        ecosystem: Ecosystem = Ecosystem.NPM,
        email_hash: Optional[str] = None,
        email_domain: Optional[str] = None,
        github_login: Optional[str] = None,
        account_created_at: Optional[datetime] = None,
    ) -> int:
        now_iso = datetime.now(timezone.utc).isoformat()
        acc_iso = account_created_at.isoformat() if account_created_at else None
        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT INTO maintainer (ecosystem, handle, email_hash, email_domain, first_seen_at, account_created_at, github_login)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ecosystem, handle) DO UPDATE SET
                email_hash = COALESCE(excluded.email_hash, maintainer.email_hash),
                email_domain = COALESCE(excluded.email_domain, maintainer.email_domain),
                github_login = COALESCE(excluded.github_login, maintainer.github_login),
                account_created_at = COALESCE(excluded.account_created_at, maintainer.account_created_at)
            RETURNING maintainer_id
            """,
            (ecosystem.value, handle, email_hash, email_domain, now_iso, acc_iso, github_login),
        )
        row = cur.fetchone()
        self.conn.commit()
        return row[0]

    def upsert_package_version(
        self,
        package_id: int,
        version: str,
        published_at: datetime,
        published_by_id: Optional[int] = None,
        unpacked_size: Optional[int] = None,
        file_count: Optional[int] = None,
        has_install_hook: bool = False,
        install_hook_kind: Optional[List[str]] = None,
        has_native_binary: bool = False,
        entropy_p99: Optional[float] = None,
        provenance: ProvenanceStatus = ProvenanceStatus.UNKNOWN,
        prov_source_repo: Optional[str] = None,
        prov_build_wf: Optional[str] = None,
        files_not_in_repo: Optional[int] = None,
        repo_drift_score: Optional[float] = None,
        raw_blob_sha256: str = "",
    ) -> int:
        v_sort = semver_sort_key(version)
        pub_iso = published_at.isoformat()
        ing_iso = datetime.now(timezone.utc).isoformat()
        hook_kind_json = json.dumps(install_hook_kind) if install_hook_kind else None

        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT INTO package_version (
                package_id, version, version_semver, version_sort, published_at, published_by_id,
                unpacked_size, file_count, has_install_hook, install_hook_kind, has_native_binary,
                entropy_p99, provenance, prov_source_repo, prov_build_wf, files_not_in_repo,
                repo_drift_score, raw_blob_sha256, ingested_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(package_id, version) DO UPDATE SET
                unpacked_size = COALESCE(excluded.unpacked_size, package_version.unpacked_size),
                file_count = COALESCE(excluded.file_count, package_version.file_count),
                has_install_hook = excluded.has_install_hook,
                install_hook_kind = excluded.install_hook_kind,
                has_native_binary = excluded.has_native_binary,
                entropy_p99 = COALESCE(excluded.entropy_p99, package_version.entropy_p99),
                provenance = excluded.provenance,
                prov_source_repo = COALESCE(excluded.prov_source_repo, package_version.prov_source_repo),
                prov_build_wf = COALESCE(excluded.prov_build_wf, package_version.prov_build_wf),
                files_not_in_repo = COALESCE(excluded.files_not_in_repo, package_version.files_not_in_repo),
                repo_drift_score = COALESCE(excluded.repo_drift_score, package_version.repo_drift_score)
            RETURNING version_id
            """,
            (
                package_id, version, version, v_sort, pub_iso, published_by_id,
                unpacked_size, file_count, 1 if has_install_hook else 0, hook_kind_json,
                1 if has_native_binary else 0, entropy_p99, provenance.value,
                prov_source_repo, prov_build_wf, files_not_in_repo, repo_drift_score,
                raw_blob_sha256, ing_iso
            ),
        )
        row = cur.fetchone()
        v_id = row[0]
        # Update latest_version_id
        cur.execute("UPDATE package SET latest_version_id = ? WHERE package_id = ?", (v_id, package_id))
        self.conn.commit()
        return v_id

    def add_maintainer_event(
        self,
        package_id: int,
        maintainer_id: int,
        event_type: MaintainerEventType,
        observed_at: datetime,
        effective_at: Optional[datetime] = None,
        observation_gap_seconds: Optional[float] = None,
        version_id: Optional[int] = None,
        evidence_blob: str = "",
        confidence: float = 1.0,
    ) -> int:
        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT INTO maintainer_event (
                package_id, maintainer_id, event_type, observed_at, effective_at,
                observation_gap_seconds, version_id, evidence_blob, confidence
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING event_id
            """,
            (
                package_id, maintainer_id, event_type.value, observed_at.isoformat(),
                effective_at.isoformat() if effective_at else None,
                observation_gap_seconds, version_id, evidence_blob, confidence
            ),
        )
        row = cur.fetchone()
        self.conn.commit()
        return row[0]

    def add_dependency_edge(
        self,
        from_version_id: int,
        to_package_id: int,
        kind: DepKind,
        range_raw: str,
        range_class: RangeClass,
        alias_target: Optional[str] = None,
        is_optional: bool = False,
    ) -> int:
        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT INTO dependency_edge (
                from_version_id, to_package_id, kind, range_raw, range_class, alias_target, is_optional
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(from_version_id, to_package_id, kind) DO UPDATE SET
                range_raw = excluded.range_raw,
                range_class = excluded.range_class,
                alias_target = excluded.alias_target,
                is_optional = excluded.is_optional
            RETURNING edge_id
            """,
            (
                from_version_id, to_package_id, kind.value, range_raw,
                int(range_class), alias_target, 1 if is_optional else 0
            ),
        )
        row = cur.fetchone()
        self.conn.commit()
        return row[0]
