"""Unit tests for Phase 5 AST indexer, T2 Symbol Reachability, and OpenVEX generation."""

from monarch.common.models import ReachabilityTier
from monarch.reachability.ast_indexer import ASTIndexer
from monarch.reachability.symbol_resolver import SymbolReachabilityResolver
from monarch.reachability.vex import VEXGenerator


def test_ast_indexer_import_and_symbol_extraction():
    code = """
    import { parse, stringify as str } from 'yaml';
    import express from 'express';
    const lodash = require('lodash');
    const { cloneDeep } = require('lodash/fp');
    import('./async-dep');
    """
    index = ASTIndexer.parse_source_code(code)

    assert "yaml" in index
    assert "parse" in index["yaml"].symbols
    assert "express" in index
    assert "default" in index["express"].symbols
    assert "lodash" in index
    assert index["lodash"].is_namespace is True
    assert "async-dep" in index
    assert index["async-dep"].is_dynamic is True


def test_symbol_reachability_and_confidence():
    code = "import { safeFunc } from 'target-lib';"
    idx = ASTIndexer.parse_source_code(code)

    # 1. Target function is exploitedFunction (not safeFunc) -> NOT_REACHABLE (HIGH)
    tier, conf, expl = SymbolReachabilityResolver.evaluate_reachability(
        package_name="target-lib",
        import_index=idx,
        affected_symbols={"exploitedFunction"},
    )
    assert tier == ReachabilityTier.NOT_REACHABLE
    assert conf == "HIGH"

    # 2. Target function is safeFunc -> REACHABLE (HIGH)
    tier2, conf2, _ = SymbolReachabilityResolver.evaluate_reachability(
        package_name="target-lib",
        import_index=idx,
        affected_symbols={"safeFunc"},
    )
    assert tier2 == ReachabilityTier.REACHABLE
    assert conf2 == "HIGH"

    # 3. Install hooks run regardless of imports
    tier3, conf3, _ = SymbolReachabilityResolver.evaluate_reachability(
        package_name="target-lib",
        import_index=idx,
        has_install_hook=True,
    )
    assert tier3 == ReachabilityTier.REACHABLE_INSTALL
    assert conf3 == "HIGH"


def test_openvex_and_cyclonedx_compliance():
    stmts = [
        {
            "package": "lodash",
            "version": "4.17.21",
            "vulnerability_id": "CVE-2021-23337",
            "reachability_tier": ReachabilityTier.NOT_REACHABLE,
            "confidence": "HIGH",
            "explanation": "Vulnerable symbol 'template' not imported.",
        },
        {
            "package": "shai-hulud",
            "version": "2.0.0",
            "vulnerability_id": "MAL-2026-001",
            "reachability_tier": ReachabilityTier.REACHABLE_INSTALL,
            "confidence": "HIGH",
            "explanation": "Preinstall hook executes on install.",
        },
    ]

    openvex = VEXGenerator.create_openvex_document(stmts)
    assert openvex["statements"][0]["status"] == "not_affected"
    assert openvex["statements"][0]["justification"] == "vulnerable_code_not_in_execute_path"
    assert openvex["statements"][1]["status"] == "affected"

    cdx = VEXGenerator.create_cyclonedx_vex(stmts)
    assert cdx["bomFormat"] == "CycloneDX"
