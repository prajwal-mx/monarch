"""Stage 1: Self-Referential Baseline Normalization using Median & MAD.
Implements Section 3.B.2 Stage 1 (per-package robust anomaly score s_i in [0, 1]).
"""

from __future__ import annotations

from typing import Dict, List, Optional
import numpy as np


class AnomalyNormalizer:
    """Computes robust z-scores and normalized anomaly scores s_i in [0, 1]."""

    @staticmethod
    def compute_mad(values: List[float]) -> Tuple[float, float]:
        """Compute median and MAD (Median Absolute Deviation)."""
        if not values:
            return 0.0, 1.0
        med = float(np.median(values))
        devs = [abs(x - med) for x in values]
        mad = float(np.median(devs))
        return med, max(1e-4, mad)

    @classmethod
    def normalize_signals(
        cls,
        raw_signals: Dict[str, float],
        historical_signals: Optional[List[Dict[str, float]]] = None,
        z_max: float = 5.0,
    ) -> Dict[str, float]:
        """Convert raw signal vector x_i into normalized self-referential anomaly score s_i in [0, 1]."""
        normalized: Dict[str, float] = {}

        for feature, val in raw_signals.items():
            # Direct binary or bounded features
            if feature in (
                "ownership_churn",
                "churn_after_dormancy",
                "first_publish_by_new_owner",
                "new_install_hook",
                "rapid_republish",
                "provenance_drift",
            ):
                normalized[feature] = min(1.0, max(0.0, val))
                continue

            if feature == "bus_factor":
                # Lower bus factor is more fragile: 1 -> 1.0, 2 -> 0.5, >=4 -> 0.0
                normalized[feature] = max(0.0, min(1.0, 1.0 - (val - 1.0) / 3.0))
                continue

            if feature == "trusted_publishing":
                # 1 if attested, 0 if not -> fragility penalty when NOT trusted
                normalized[feature] = 0.0 if val > 0.5 else 1.0
                continue

            if feature == "repo_drift":
                # Any files not in repo indicates severe drift (the xz signal!)
                normalized[feature] = min(1.0, val / 10.0) if val > 0 else 0.0
                continue

            # Continuous signals with history: use median and MAD
            if historical_signals and len(historical_signals) >= 3:
                hist_vals = [h.get(feature, 0.0) for h in historical_signals]
                med, mad = cls.compute_mad(hist_vals)
                z = (val - med) / (1.4826 * mad)
                s = max(0.0, min(z_max, z)) / z_max
                normalized[feature] = round(s, 4)
            else:
                # Cohort fallback for packages without deep history
                if feature == "size_delta":
                    normalized[feature] = min(1.0, val / 5.0)
                elif feature == "entropy_spike":
                    normalized[feature] = min(1.0, val / 2.0)
                elif feature == "cadence_break":
                    normalized[feature] = min(1.0, val / 4.0)
                elif feature == "publisher_portfolio_breadth":
                    normalized[feature] = min(1.0, val / 20.0)
                else:
                    normalized[feature] = min(1.0, max(0.0, val))

        return normalized
