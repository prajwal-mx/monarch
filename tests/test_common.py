"""Unit tests for monarch.common (semver, models, storage, resource guards)."""

import pytest
from monarch.common.models import RangeClass
from monarch.common.semver_utils import (
    parse_semver,
    semver_sort_key,
    classify_range,
    semver_satisfies,
    propagation_probability,
)
from monarch.common.resource_guard import ResourceGuard, TraversalBudget, MAX_RSS_BYTES
from monarch.common.storage import Storage


def test_semver_parsing_and_sorting():
    parsed = parse_semver("1.2.3-alpha.1+build.4")
    assert parsed == (1, 2, 3, "alpha.1", "build.4")

    # Prerelease must sort lower than final release
    k_pre = semver_sort_key("1.0.0-alpha")
    k_final = semver_sort_key("1.0.0")
    assert k_pre < k_final

    k1 = semver_sort_key("1.2.3")
    k2 = semver_sort_key("1.2.4")
    k3 = semver_sort_key("2.0.0")
    assert k1 < k2 < k3


def test_range_classification():
    assert classify_range("1.2.3") == RangeClass.EXACT
    assert classify_range("=1.2.3") == RangeClass.EXACT
    assert classify_range("~1.2.0") == RangeClass.TILDE
    assert classify_range("^1.2.0") == RangeClass.CARET
    assert classify_range("*") == RangeClass.WILDCARD
    assert classify_range(">=1.0.0 <2.0.0") == RangeClass.RANGE
    assert classify_range("npm:foo@^1.0.0") == RangeClass.ALIAS
    assert classify_range("workspace:*") == RangeClass.WORKSPACE
    assert classify_range("git+https://github.com/foo/bar.git") == RangeClass.GIT


def test_semver_satisfaction_and_propagation():
    # Caret rules (§5.2)
    assert semver_satisfies("1.2.3", "^1.2.0")
    assert semver_satisfies("1.9.9", "^1.2.0")
    assert not semver_satisfies("2.0.0", "^1.2.0")

    # Caret below 1.0.0: ^0.2.3 does not match 0.3.0
    assert semver_satisfies("0.2.5", "^0.2.3")
    assert not semver_satisfies("0.3.0", "^0.2.3")

    # Propagation probabilities (§3.A.4)
    assert propagation_probability("1.2.3", RangeClass.EXACT, "1.2.4") == 0.0
    assert propagation_probability("^1.2.0", RangeClass.CARET, "1.3.0") == 1.0
    assert propagation_probability("^1.2.0", RangeClass.CARET, "2.0.0") == 0.0


def test_resource_guard_and_traversal_budget():
    rss_mb = ResourceGuard.get_current_rss_mb()
    assert rss_mb > 0
    # Process must not exceed the 2.0 GiB safety limit
    ResourceGuard.check_memory_safe(MAX_RSS_BYTES)

    budget = TraversalBudget(max_nodes=5, max_depth=3)
    assert budget.step(1)
    assert budget.step(2)
    assert budget.step(3)
    # Depth exceed
    assert not budget.step(4)
    assert budget.truncated


def test_storage_initialization():
    storage = Storage(":memory:")
    cur = storage.conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {r[0] for r in cur.fetchall()}
    assert "package" in tables
    assert "package_version" in tables
    assert "maintainer" in tables
    assert "maintainer_event" in tables
    assert "dependency_edge" in tables
    assert "cas_blob" in tables
