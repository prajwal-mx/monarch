"""Declarative YAML Policy Engine with EU CRA Reporting Clocks.
Implements Section 4.2 (Declarative policy evaluation, 24h CRA SLA timers).
"""

from __future__ import annotations

import yaml
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from monarch.common.models import ProvenanceStatus, ReachabilityTier


@dataclass
class PolicyViolation:
    rule_id: str
    action: str  # block | warn
    package: str
    message: str
    sla_hours: Optional[int] = None


class PolicyEngine:
    """Evaluates declarative security and compliance rules against resolved components."""

    DEFAULT_POLICY_YAML = """
policy: standard-production
rules:
  - id: no-unmaintained-critical
    when: "consequence > 80 and maintainer_count == 1"
    action: warn
    message: "Single-maintainer dependency on critical path"

  - id: block-new-install-hooks
    when: "has_install_hook and provenance != 'ATTESTED'"
    action: block
    message: "Unattested package with install-time execution script"

  - id: provenance-required-critical
    when: "consequence > 70 and provenance == 'UNATTESTED'"
    action: warn
    message: "High consequence package lacking OIDC provenance attestation"

  - id: block-active-exploitation
    when: "kev_listed and reachability in ['REACHABLE', 'REACHABLE_INSTALL']"
    action: block
    message: "Actively exploited vulnerability (CISA KEV) reachable in application code"
    sla_hours: 24
"""

    def __init__(self, policy_yaml: Optional[str] = None):
        self.raw_yaml = policy_yaml or self.DEFAULT_POLICY_YAML
        self.policy_data = yaml.safe_load(self.raw_yaml)
        self.rules = self.policy_data.get("rules", [])

    def evaluate_component(
        self,
        package_name: str,
        consequence_score: float,
        fragility_score: float,
        maintainer_count: int = 1,
        has_install_hook: bool = False,
        provenance: ProvenanceStatus = ProvenanceStatus.UNKNOWN,
        kev_listed: bool = False,
        reachability: ReachabilityTier = ReachabilityTier.UNKNOWN,
        is_added: bool = False,
    ) -> List[PolicyViolation]:
        """Evaluate all policy rules against a package component."""
        violations: List[PolicyViolation] = []

        context = {
            "consequence": consequence_score,
            "fragility": fragility_score,
            "maintainer_count": maintainer_count,
            "has_install_hook": has_install_hook,
            "provenance": provenance.value if hasattr(provenance, "value") else str(provenance),
            "kev_listed": kev_listed,
            "reachability": reachability.name if hasattr(reachability, "name") else str(reachability),
            "added": is_added,
        }

        for rule in self.rules:
            rule_id = rule.get("id", "rule")
            condition = rule.get("when", "")
            action = rule.get("action", "warn")
            msg = rule.get("message", "Policy condition triggered")
            sla = rule.get("sla_hours")

            try:
                # Safe evaluation of boolean condition
                passed = eval(condition, {"__builtins__": None}, context)
                if passed:
                    violations.append(
                        PolicyViolation(
                            rule_id=rule_id,
                            action=action,
                            package=package_name,
                            message=msg,
                            sla_hours=sla,
                        )
                    )
            except Exception:
                pass

        return violations

    def get_sla_summary(self) -> Dict[str, Any]:
        """Summary of regulatory reporting clocks under CRA Article 14."""
        sla_rules = [r for r in self.rules if r.get("sla_hours")]
        return {
            "early_warning_window_hours": 24,
            "full_notification_window_hours": 72,
            "final_report_window_days": 14,
            "active_sla_rules_count": len(sla_rules),
            "cra_compliance_status": "MONITORING_ACTIVE",
            "sla_rules": [
                {
                    "id": r.get("id"),
                    "sla_hours": r.get("sla_hours"),
                    "action": r.get("action"),
                    "message": r.get("message"),
                }
                for r in sla_rules
            ],
        }
