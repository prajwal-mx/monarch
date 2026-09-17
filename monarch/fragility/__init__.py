"""Fragility Detection Engine & Historical Backtesting (Phase 3)."""

from monarch.fragility.signals import FragilitySignalExtractor
from monarch.fragility.baseline import AnomalyNormalizer
from monarch.fragility.model import FragilityModel
from monarch.fragility.gating import ConsequenceGater
from monarch.fragility.evidence import EvidenceContractFormatter
from monarch.fragility.backtest import BacktestHarness, HISTORICAL_INCIDENTS

__all__ = [
    "FragilitySignalExtractor",
    "AnomalyNormalizer",
    "FragilityModel",
    "ConsequenceGater",
    "EvidenceContractFormatter",
    "BacktestHarness",
    "HISTORICAL_INCIDENTS",
]
