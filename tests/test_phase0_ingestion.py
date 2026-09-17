"""Unit tests for Phase 0 Ingestion Moat (CAS, hydrator, maintainer tracker, reconciler)."""

import json
from datetime import datetime, timezone, timedelta
from monarch.common.models import MaintainerEventType, ProvenanceStatus
from monarch.common.storage import Storage
from monarch.ingestion.cas import ContentAddressedStorage
from monarch.ingestion.hydrator import Hydrator
from monarch.ingestion.maintainer_tracker import MaintainerTracker, hash_email
from monarch.ingestion.watcher import ReplicationWatcher
from monarch.ingestion.reconciler import Reconciler


def test_cas_blob_storage():
    storage = Storage(":memory:")
    cas = ContentAddressedStorage(storage)

    data = b'{"name": "test-pkg", "version": "1.0.0"}'
    sha256 = cas.put(data)
    assert len(sha256) == 64

    retrieved = cas.get(sha256)
    assert retrieved == data


def test_maintainer_tracker_observation_gap():
    storage = Storage(":memory:")
    tracker = MaintainerTracker(storage)

    pkg_id = storage.upsert_package("alpha-pkg")
    t1 = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    t2 = t1 + timedelta(days=30)

    # First observation: maintainer Alice
    tracker.process_packument_maintainers(
        package_id=pkg_id,
        observed_maintainers=[{"name": "alice", "email": "alice@corp.com"}],
        observed_at=t1,
    )
    assert tracker.get_current_maintainers(pkg_id) == {"alice"}

    # Second observation 30 days later: Bob added, Alice removed
    events = tracker.process_packument_maintainers(
        package_id=pkg_id,
        observed_maintainers=[{"name": "bob", "email": "bob@personal.io"}],
        observed_at=t2,
        last_observed_at=t1,
    )
    assert tracker.get_current_maintainers(pkg_id) == {"bob"}

    # Verify maintainer_event records observation_gap
    cur = storage.conn.cursor()
    cur.execute("SELECT event_type, observation_gap_seconds FROM maintainer_event WHERE package_id = ?", (pkg_id,))
    rows = cur.fetchall()
    assert len(rows) >= 2
    # 30 days in seconds = 2592000
    for r in rows:
        if r[1] is not None:
            assert r[1] == 2592000.0


def test_hydrator_packument_and_edges():
    storage = Storage(":memory:")
    cas = ContentAddressedStorage(storage)
    hydrator = Hydrator(storage, cas)

    packument = {
        "name": "my-tool",
        "maintainers": [{"name": "charlie", "email": "charlie@test.org"}],
        "time": {"1.0.0": "2026-03-01T00:00:00Z"},
        "versions": {
            "1.0.0": {
                "name": "my-tool",
                "version": "1.0.0",
                "scripts": {"preinstall": "node setup.js"},
                "dependencies": {"chalk": "^4.1.0"},
                "dist": {"unpackedSize": 50000, "fileCount": 8, "attestations": True},
            }
        },
    }

    pkg_id = hydrator.hydrate_packument_json(packument)
    assert pkg_id > 0

    cur = storage.conn.cursor()
    cur.execute("SELECT has_install_hook, provenance FROM package_version WHERE package_id = ?", (pkg_id,))
    row = cur.fetchone()
    assert row[0] == 1  # has install hook
    assert row[1] == ProvenanceStatus.ATTESTED.value


def test_reconciler_feed_gap_detection():
    storage = Storage(":memory:")
    cas = ContentAddressedStorage(storage)
    hydrator = Hydrator(storage, cas)
    reconciler = Reconciler(storage, hydrator)

    # 1. Initial state with 1 version
    packument_v1 = {
        "name": "gap-pkg",
        "versions": {"1.0.0": {"name": "gap-pkg", "version": "1.0.0"}},
    }
    hydrator.hydrate_packument_json(packument_v1)

    # 2. Upstream feed had version 1.1.0 and 1.2.0 that stream never delivered
    packument_v2 = {
        "name": "gap-pkg",
        "versions": {
            "1.0.0": {"name": "gap-pkg", "version": "1.0.0"},
            "1.1.0": {"name": "gap-pkg", "version": "1.1.0"},
            "1.2.0": {"name": "gap-pkg", "version": "1.2.0"},
        },
    }
    res = reconciler.reconcile_package("gap-pkg", packument_v2)
    assert res["feed_gap_detected"] is True
    assert res["missed_versions"] == ["1.1.0", "1.2.0"]
    assert len(reconciler.get_feed_gap_metrics()) == 1
