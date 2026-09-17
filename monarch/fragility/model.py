"""Stage 2: Supervised Calibrated Fragility Model with Multiplicative Interactions.
Implements Section 3.B.2 Stage 2 and Section 3.B.3.
"""

from __future__ import annotations

import math
from typing import Dict, Optional, Tuple


def sigmoid(x: float) -> float:
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    else:
        z = math.exp(x)
        return z / (1.0 + z)


class FragilityModel:
    """Computes Fragility Score F(v, t) in [0, 100] and calibrated probability P."""

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        interaction_weights: Optional[Dict[str, float]] = None,
        beta_0: float = -3.5,
        platt_a: float = 1.0,
        platt_b: float = 0.0,
    ):
        self.beta_0 = beta_0
        self.weights = weights or {
            "churn_after_dormancy": 3.2,
            "repo_drift": 4.5,            # decisive xz signal
            "new_install_hook": 2.8,       # decisive Shai-Hulud / event-stream signal
            "publisher_portfolio_breadth": 2.2,
            "provenance_drift": 2.2,
            "ownership_churn": 1.5,
            "cadence_break": 1.2,
            "size_delta": 1.2,
            "entropy_spike": 1.5,
            "bus_factor": 1.0,
            "trusted_publishing": 1.0,
            "rapid_republish": 1.5,
            "first_publish_by_new_owner": 1.8,
        }
        self.interaction_weights = interaction_weights or {
            "churn_x_dormancy": 3.5,       # event-stream / xz pattern
            "new_hook_x_portfolio": 2.5,   # Shai-Hulud worm pattern
            "entropy_x_size": 2.0,         # obfuscated payload
            "prov_drift_x_churn": 2.5,     # pipeline compromise
        }
        self.platt_a = platt_a
        self.platt_b = platt_b

    def predict(
        self, s: Dict[str, float], consequence_score: float = 50.0
    ) -> Tuple[float, float, Dict[str, float]]:
        """Predict Fragility Score F in [0, 100], Calibrated P in [0, 1], and top feature contributions."""
        linear_term = self.beta_0
        contributions: Dict[str, float] = {}

        # 1. Linear features
        for feat, w in self.weights.items():
            val = s.get(feat, 0.0)
            contrib = w * val
            if contrib > 0:
                contributions[feat] = contrib
            linear_term += contrib

        # 2. Multiplicative interaction terms (§3.B.2)
        # Interaction 1: churn x dormancy
        churn_dorm = s.get("ownership_churn", 0.0) * s.get("churn_after_dormancy", 0.0)
        c1 = self.interaction_weights.get("churn_x_dormancy", 3.5) * churn_dorm
        if c1 > 0:
            contributions["interaction:churn_x_dormancy"] = c1
        linear_term += c1

        # Interaction 2: new_hook x portfolio breadth
        hook_port = s.get("new_install_hook", 0.0) * s.get("publisher_portfolio_breadth", 0.0)
        c2 = self.interaction_weights.get("new_hook_x_portfolio", 2.5) * hook_port
        if c2 > 0:
            contributions["interaction:new_hook_x_portfolio"] = c2
        linear_term += c2

        # Interaction 3: entropy x size
        ent_sz = s.get("entropy_spike", 0.0) * s.get("size_delta", 0.0)
        c3 = self.interaction_weights.get("entropy_x_size", 2.0) * ent_sz
        if c3 > 0:
            contributions["interaction:entropy_x_size"] = c3
        linear_term += c3

        # Interaction 4: provenance drift x ownership churn
        prov_churn = s.get("provenance_drift", 0.0) * s.get("ownership_churn", 0.0)
        c4 = self.interaction_weights.get("prov_drift_x_churn", 2.5) * prov_churn
        if c4 > 0:
            contributions["interaction:prov_drift_x_churn"] = c4
        linear_term += c4

        # Uncalibrated probability
        raw_prob = sigmoid(linear_term)

        # Platt scaling calibration
        calibrated_p = sigmoid(self.platt_a * linear_term + self.platt_b)

        fragility_score = round(raw_prob * 100.0, 2)
        return fragility_score, round(calibrated_p, 4), contributions
