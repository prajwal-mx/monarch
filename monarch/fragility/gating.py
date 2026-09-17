"""Consequence Gating and Alert Budgeting.
Solves the base-rate false positive dilemma per Section 3.B.3.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class ConsequenceGater:
    """Enforces F high AND C high AND E > 0 gating with daily alert budget."""

    def __init__(
        self,
        fragility_threshold: float = 70.0,
        consequence_threshold: float = 50.0,
        daily_alert_budget: int = 10,
    ):
        self.f_thresh = fragility_threshold
        self.c_thresh = consequence_threshold
        self.daily_budget = daily_alert_budget
        self.tenant_alert_counts: Dict[str, int] = {}

    def evaluate_gate(
        self,
        package_name: str,
        fragility_score: float,
        consequence_score: float,
        is_in_customer_tree: bool,
        calibrated_p: float,
        tenant_id: str = "default",
    ) -> Dict[str, Any]:
        """Determine whether finding produces an active EVENT alert or passive POSTURE item."""
        cleared_consequence = consequence_score >= self.c_thresh
        cleared_fragility = fragility_score >= self.f_thresh
        exposed = is_in_customer_tree

        # Posture item (always available in dashboard, zero false-positive panic)
        is_posture = cleared_fragility and cleared_consequence

        # Alert event: F high AND C high AND E > 0 AND within daily budget (§3.B.3)
        current_count = self.tenant_alert_counts.get(tenant_id, 0)
        within_budget = current_count < self.daily_budget

        should_alert = cleared_consequence and cleared_fragility and exposed and within_budget

        if should_alert:
            self.tenant_alert_counts[tenant_id] = current_count + 1

        return {
            "package": package_name,
            "should_alert_event": should_alert,
            "is_posture_finding": is_posture,
            "fragility_score": fragility_score,
            "consequence_score": consequence_score,
            "exposed_in_tree": exposed,
            "calibrated_prob": calibrated_p,
            "budget_remaining": max(0, self.daily_budget - self.tenant_alert_counts.get(tenant_id, 0)),
            "reason": (
                "Cleared consequence gate (F >= 70, C >= 50, Exposed=True)"
                if should_alert
                else "Filtered by consequence gate or customer exposure"
            ),
        }
