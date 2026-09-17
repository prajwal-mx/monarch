"""Core data models and type definitions for MONARCH.
Implements the exact schemas specified in MONARCH_SDD Section 2.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any, Dict, List, Optional
import uuid


class Ecosystem(str, Enum):
    NPM = "npm"
    PYPI = "pypi"
    MAVEN = "maven"
    GO = "go"
    CARGO = "cargo"
    NUGET = "nuget"
    RUBYGEMS = "rubygems"
    PACKAGIST = "packagist"


class DepKind(str, Enum):
    RUNTIME = "runtime"
    DEV = "dev"
    PEER = "peer"
    OPTIONAL = "optional"
    BUNDLED = "bundled"


class ProvenanceStatus(str, Enum):
    ATTESTED = "ATTESTED"
    UNATTESTED = "UNATTESTED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


class RangeClass(IntEnum):
    EXACT = 0
    TILDE = 1
    CARET = 2
    WILDCARD = 3
    RANGE = 4
    URL = 5
    GIT = 6
    ALIAS = 7
    WORKSPACE = 8


class MaintainerEventType(str, Enum):
    ADDED = "ADDED"
    REMOVED = "REMOVED"
    FIRST_PUBLISH = "FIRST_PUBLISH"
    PUBLISH = "PUBLISH"
    EMAIL_CHANGED = "EMAIL_CHANGED"
    HANDLE_OBSERVED = "HANDLE_OBSERVED"
    SOLE_OWNER_BEGIN = "SOLE_OWNER_BEGIN"
    SOLE_OWNER_END = "SOLE_OWNER_END"


class SignalClass(str, Enum):
    VULNERABILITY = "VULNERABILITY"
    MALWARE = "MALWARE"
    FRAGILITY = "FRAGILITY"
    ANOMALY = "ANOMALY"
    POLICY = "POLICY"


class SignalStatus(str, Enum):
    ACTIVE = "ACTIVE"
    WITHDRAWN = "WITHDRAWN"
    SUPERSEDED = "SUPERSEDED"
    DISPUTED = "DISPUTED"
    RESOLVED = "RESOLVED"


class ReachabilityTier(IntEnum):
    UNKNOWN = 0
    NOT_REACHABLE = 1
    REACHABLE = 2
    REACHABLE_INSTALL = 3


@dataclass
class Package:
    package_id: int
    ecosystem: Ecosystem
    name: str
    name_normalized: str
    purl: str
    first_seen_at: datetime
    last_polled_at: Optional[datetime] = None
    poll_tier: int = 3
    repo_url: Optional[str] = None
    repo_host: Optional[str] = None
    repo_owner: Optional[str] = None
    repo_name: Optional[str] = None
    is_deprecated: bool = False
    is_unpublished: bool = False
    latest_version_id: Optional[int] = None


@dataclass
class PackageVersion:
    version_id: int
    package_id: int
    version: str
    version_semver: Optional[str]
    version_sort: bytes
    published_at: datetime
    published_by_id: Optional[int] = None
    is_prerelease: bool = False
    is_yanked: bool = False
    deprecated_msg: Optional[str] = None
    tarball_url: Optional[str] = None
    shasum: Optional[str] = None
    integrity: Optional[str] = None
    unpacked_size: Optional[int] = None
    file_count: Optional[int] = None
    file_list_hash: Optional[str] = None
    has_install_hook: bool = False
    install_hook_kind: List[str] = field(default_factory=list)
    install_hook_hash: Optional[str] = None
    has_native_binary: bool = False
    entropy_p99: Optional[float] = None
    provenance: ProvenanceStatus = ProvenanceStatus.UNKNOWN
    prov_source_repo: Optional[str] = None
    prov_build_wf: Optional[str] = None
    prov_verified_at: Optional[datetime] = None
    files_not_in_repo: Optional[int] = None
    repo_drift_score: Optional[float] = None
    raw_blob_sha256: str = ""
    ingested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Maintainer:
    maintainer_id: int
    ecosystem: Ecosystem
    handle: str
    email_hash: Optional[str] = None
    email_domain: Optional[str] = None
    first_seen_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    account_created_at: Optional[datetime] = None
    github_login: Optional[str] = None
    is_org_account: Optional[bool] = None


@dataclass
class MaintainerEvent:
    event_id: int
    package_id: int
    maintainer_id: int
    event_type: MaintainerEventType
    observed_at: datetime
    effective_at: Optional[datetime] = None
    observation_gap_seconds: Optional[float] = None
    version_id: Optional[int] = None
    prev_state_hash: Optional[str] = None
    new_state_hash: Optional[str] = None
    evidence_blob: str = ""
    confidence: float = 1.0


@dataclass
class DependencyEdge:
    edge_id: int
    from_version_id: int
    to_package_id: int
    kind: DepKind
    range_raw: str
    range_class: RangeClass
    range_min: Optional[str] = None
    range_max: Optional[str] = None
    range_includes_prerelease: bool = False
    alias_target: Optional[str] = None
    is_optional: bool = False


@dataclass
class SecuritySignal:
    signal_id: int
    signal_class: SignalClass
    signal_type: str
    canonical_id: Optional[str] = None
    aliases: List[str] = field(default_factory=list)
    package_id: Optional[int] = None
    affected_ranges: Optional[Dict[str, Any]] = None
    severity_cvss: Optional[float] = None
    severity_vector: Optional[str] = None
    epss_score: Optional[float] = None
    kev_listed: bool = False
    status: SignalStatus = SignalStatus.ACTIVE
    source: str = "monarch"
    published_at: Optional[datetime] = None
    ingested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    evidence: Dict[str, Any] = field(default_factory=dict)
    model_version: Optional[str] = None
    epoch_id: Optional[str] = None
    confidence: Optional[float] = None


@dataclass
class Tenant:
    tenant_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "default-tenant"
    plan: str = "business"
    data_region: str = "eu-west-1"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Project:
    project_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default-tenant"
    name: str = "default-project"
    repo_url: Optional[str] = None
    default_branch: str = "main"
    policy_id: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ProjectSnapshot:
    snapshot_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    project_id: str = ""
    git_sha: Optional[str] = None
    source_kind: str = "lockfile"  # lockfile | cyclonedx | spdx | api
    source_hash: str = ""
    ingested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    epoch_id: str = ""
    node_count: int = 0
    direct_count: int = 0
    max_depth: int = 0


@dataclass
class ProjectComponent:
    snapshot_id: str
    version_id: int
    package_name: str
    version_str: str
    is_direct: bool
    min_depth: int
    path_count: int = 1
    dominator_of: int = 0
    introduced_by: List[int] = field(default_factory=list)
    reachability: ReachabilityTier = ReachabilityTier.UNKNOWN
