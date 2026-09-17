"""Unit tests for Phase 2 Consequence Scoring, Poll-tier feedback, and Monarch Watch."""

from monarch.common.storage import Storage
from monarch.consequence.engine import ConsequenceEngine
from monarch.consequence.tiering import TierManager
from monarch.consequence.monarch_watch import MonarchWatchIndex
from monarch.graph.epoch import EpochManager
from monarch.ingestion.bootstrap import bootstrap_database
from monarch.ingestion.cas import ContentAddressedStorage


def test_consequence_score_computation_and_rank_stability():
    storage = Storage(":memory:")
    cas = ContentAddressedStorage(storage)
    bootstrap_database(storage, cas)

    mgr = EpochManager(storage)
    epoch = mgr.build_epoch_from_storage()
    mgr.promote_epoch(epoch)

    engine = ConsequenceEngine(storage, epoch)
    scores = engine.compute_all_consequence_scores()

    # Scores must be bounded in [0, 100]
    for pkg, score in scores.items():
        assert 0.0 <= score <= 100.0

    # Highly depended leaf packages (e.g. color-name, color-convert) must rank higher than top-level apps
    assert scores["color-name"] > scores["express"]

    # Poll tier assignment
    tm = TierManager(storage)
    assignments = tm.assign_tiers_from_scores(scores)
    assert assignments["color-name"] in (0, 1)

    # Check DB was updated
    cur = storage.conn.cursor()
    cur.execute("SELECT poll_tier FROM package WHERE name_normalized = 'color-name'")
    db_tier = cur.fetchone()[0]
    assert db_tier == assignments["color-name"]


def test_monarch_watch_index_generation():
    storage = Storage(":memory:")
    cas = ContentAddressedStorage(storage)
    bootstrap_database(storage, cas)

    mgr = EpochManager(storage)
    epoch = mgr.build_epoch_from_storage()
    mgr.promote_epoch(epoch)

    engine = ConsequenceEngine(storage, epoch)
    scores = engine.compute_all_consequence_scores()

    mw = MonarchWatchIndex(storage, epoch)
    index_items = mw.generate_index(scores, top_n=5)

    assert len(index_items) <= 5
    assert index_items[0]["rank"] == 1
    assert "sponsor_link" in index_items[0]
    assert index_items[0]["consequence_score"] >= index_items[1]["consequence_score"]
