"""Unit tests for Phase 6 Policy Engine and CLI execution."""

from click.testing import CliRunner
from monarch.cli.policy import PolicyEngine
from monarch.cli.main import cli
from monarch.common.models import ProvenanceStatus, ReachabilityTier


def test_policy_engine_cra_timers_and_rules():
    engine = PolicyEngine()

    # Test 1: High consequence single-maintainer rule
    v1 = engine.evaluate_component(
        package_name="crit-pkg",
        consequence_score=85.0,
        fragility_score=40.0,
        maintainer_count=1,
    )
    assert any(v.rule_id == "no-unmaintained-critical" and v.action == "warn" for v in v1)

    # Test 2: CISA KEV actively exploited vulnerability -> CRA 24h SLA rule
    v2 = engine.evaluate_component(
        package_name="exploited-pkg",
        consequence_score=90.0,
        fragility_score=80.0,
        kev_listed=True,
        reachability=ReachabilityTier.REACHABLE,
    )
    assert any(v.rule_id == "block-active-exploitation" and v.action == "block" and v.sla_hours == 24 for v in v2)


def test_cli_commands_via_runner():
    runner = CliRunner()

    # 1. blast
    res1 = runner.invoke(cli, ["blast", "chalk"])
    assert res1.exit_code == 0
    assert "chalk" in res1.output

    # 2. simulate
    res2 = runner.invoke(cli, ["simulate", "express"])
    assert res2.exit_code == 0
    assert "Compromise Propagation" in res2.output

    # 3. fix
    res3 = runner.invoke(cli, ["fix"])
    assert res3.exit_code == 0
    assert "Intervention Solver" in res3.output

    # 4. scan
    res4 = runner.invoke(cli, ["scan"])
    assert res4.exit_code == 0
    assert "express" in res4.output

    # 5. diff
    res5 = runner.invoke(cli, ["diff"])
    assert res5.exit_code == 0
    assert "Lockfile Diff Intelligence" in res5.output

    # 6. vex
    res6 = runner.invoke(cli, ["vex"])
    assert res6.exit_code == 0
    assert "openvex" in res6.output

    # 7. sbom
    res7 = runner.invoke(cli, ["sbom"])
    assert res7.exit_code == 0
    assert "CycloneDX" in res7.output
