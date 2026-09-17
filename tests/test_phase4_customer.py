"""Unit tests for Phase 4 Lockfile/SBOM Ingestion, Dominators, and Intervention Solver."""

import json
from monarch.customer.lockfile_parser import LockfileParser
from monarch.customer.sbom_parser import SBOMParser
from monarch.customer.dominator import DominatorTree
from monarch.customer.solver import InterventionSolver


def test_lockfile_and_sbom_parsers():
    npm_lock_v2 = json.dumps({
        "lockfileVersion": 2,
        "packages": {
            "": {"dependencies": {"express": "^4.18.2"}},
            "node_modules/express": {"version": "4.18.2", "dependencies": {"chalk": "^4.1.0"}},
            "node_modules/chalk": {"version": "4.1.2"},
        }
    })
    deps = LockfileParser.parse_npm_lockfile(npm_lock_v2)
    assert "express" in deps
    assert deps["express"].is_direct is True
    assert "chalk" in deps
    assert deps["chalk"].is_direct is False

    # CycloneDX SBOM
    cdx = json.dumps({
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {"name": "lodash", "version": "4.17.21"},
            {"name": "debug", "version": "4.3.4"}
        ]
    })
    sbom_deps = SBOMParser.parse_cyclonedx(cdx)
    assert "lodash" in sbom_deps
    assert sbom_deps["lodash"].version == "4.17.21"


def test_lengauer_tarjan_dominators():
    # Root: app
    # app -> libA -> dep1 -> target_vuln
    # app -> libB -> dep2
    adj = {
        "app": ["libA", "libB"],
        "libA": ["dep1"],
        "dep1": ["target_vuln"],
        "libB": ["dep2"],
    }
    dt = DominatorTree("app", adj)
    dominated = dt.get_dominated_sets()

    # libA must dominate dep1 and target_vuln
    assert "dep1" in dominated["libA"]
    assert "target_vuln" in dominated["libA"]
    # libB does not dominate target_vuln
    assert "target_vuln" not in dominated["libB"]


def test_intervention_solver_approximation():
    adj = {
        "root": ["direct1", "direct2"],
        "direct1": ["vuln1", "vuln2"],
        "direct2": ["vuln3"],
    }
    risks = {"vuln1": 50.0, "vuln2": 40.0, "vuln3": 30.0}

    # Budget allows fixing 1 direct dependency (cost 1.0)
    res = InterventionSolver.solve(
        root_project="root",
        adjacency=adj,
        direct_dependencies={"direct1", "direct2"},
        at_risk_components=risks,
        budget=1.0,
    )

    # Greedy should pick direct1 (gain = 90.0) over direct2 (gain = 30.0)
    assert res["interventions"][0]["target_dependency"] == "direct1"
    assert res["eliminated_risk"] == 90.0
    assert "vuln1" in res["interventions"][0]["eliminated_packages"]
    assert "vuln2" in res["interventions"][0]["eliminated_packages"]
