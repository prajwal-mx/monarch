"""Unit tests for Phase 3 Fragility Engine, Gating, Evidence, and Incident Backtesting."""

from monarch.common.storage import Storage
from monarch.fragility.signals import FragilitySignalExtractor
from monarch.fragility.baseline import AnomalyNormalizer
from monarch.fragility.model import FragilityModel
from monarch.fragility.gating import ConsequenceGater
from monarch.fragility.evidence import EvidenceContractFormatter
from monarch.fragility.backtest import BacktestHarness
from monarch.ingestion.bootstrap import bootstrap_database
from monarch.ingestion.cas import ContentAddressedStorage


def test_fragility_incident_backtest_precision_recall():
    harness = BacktestHarness()
    res = harness.run_backtest(threshold=70.0)

    # Acceptance criteria: must detect all known attacks with 0 false positives on benign controls
    assert res["precision"] >= 0.90
    assert res["recall"] >= 0.90
    assert res["false_positives"] == 0
    assert res["true_positives"] >= 4

    # Specifically verify detection of xz-utils, event-stream, and shai-hulud
    details_map = {r["incident_id"]: r for r in res["details"]}
    assert details_map["xz-utils-cve-2024-3094"]["status"] == "TRUE_POSITIVE"
    assert details_map["event-stream-2018"]["status"] == "TRUE_POSITIVE"
    assert details_map["shai-hulud-v2"]["status"] == "TRUE_POSITIVE"
    assert details_map["chalk-4.1.2-benign"]["status"] == "TRUE_NEGATIVE"


def test_consequence_gating_and_alert_budget():
    gater = ConsequenceGater(fragility_threshold=70.0, consequence_threshold=50.0, daily_alert_budget=2)

    # 1. High fragility, but low consequence -> posture only, NO event alert
    res1 = gater.evaluate_gate("low-consequence-pkg", fragility_score=85.0, consequence_score=20.0, is_in_customer_tree=True, calibrated_p=0.8)
    assert res1["should_alert_event"] is False

    # 2. High fragility, high consequence, but NOT in customer tree -> NO event alert
    res2 = gater.evaluate_gate("not-in-tree-pkg", fragility_score=85.0, consequence_score=80.0, is_in_customer_tree=False, calibrated_p=0.8)
    assert res2["should_alert_event"] is False

    # 3. High fragility, high consequence, in tree -> ALERTS!
    res3 = gater.evaluate_gate("critical-compromised-pkg", fragility_score=85.0, consequence_score=80.0, is_in_customer_tree=True, calibrated_p=0.8)
    assert res3["should_alert_event"] is True


def test_evidence_contract_formatting():
    alert = EvidenceContractFormatter.format_alert(
        package_name="event-stream",
        version_str="3.3.6",
        fragility_score=94.0,
        consequence_score=78.0,
        calibrated_p=0.88,
        evidence_items=[{"fact": "maintainer_set_delta", "value": "+right9ctrl"}],
        recommended_action="Pin to 3.3.4",
    )
    # Section 8.1 mandatory non-accusatory clause
    assert alert["NOT_an_assertion"] == "This maintainer is malicious."
    assert "base_rate_note" in alert
    assert alert["assessment"]["confidence"] == "HIGH"
