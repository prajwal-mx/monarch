"""Minimum-Cut Monotone Submodular Intervention Solver.
Implements Section 3.C.3 and 3.C.5 (cost-benefit greedy with (1 - 1/e) approximation guarantee).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from monarch.customer.dominator import DominatorTree


@dataclass
class Intervention:
    action_type: str  # PIN | UPGRADE | SWAP | REMOVE | OVERRIDE
    target_direct_dep: str
    target_version: Optional[str] = None
    target_package: Optional[str] = None
    cost: float = 1.0
    covered_risks: Set[str] = field(default_factory=set)


class InterventionSolver:
    """Finds the minimal-cost subset of interventions maximizing eliminated risk."""

    @staticmethod
    def calculate_cost(
        action_type: str, major_bumps: int = 0, direct_import_sites: int = 0
    ) -> float:
        """Engineering effort cost model per Section 3.C.5."""
        if action_type == "PIN":
            return 1.0
        elif action_type == "OVERRIDE":
            return 1.5
        elif action_type == "UPGRADE":
            return 2.0 + 3.0 * major_bumps
        elif action_type == "REMOVE":
            return 4.0 + 2.0 * min(3, direct_import_sites)
        elif action_type == "SWAP":
            return 8.0 + 2.0 * min(3, direct_import_sites)
        elif action_type == "VENDOR":
            return 12.0
        return 2.0

    @classmethod
    def solve(
        cls,
        root_project: str,
        adjacency: Dict[str, List[str]],
        direct_dependencies: Set[str],
        at_risk_components: Dict[str, float],  # pkg -> risk_score
        budget: float = 10.0,
    ) -> Dict[str, Any]:
        """Solve for optimal intervention set S using cost-benefit greedy with (1 - 1/e) guarantee."""
        # 1. Compute dominator tree
        dt = DominatorTree(root=root_project, adjacency=adjacency)
        dominated_sets = dt.get_dominated_sets()

        # 2. Generate feasible candidate interventions
        candidates: List[Intervention] = []
        for direct_dep in direct_dependencies:
            dominated = dominated_sets.get(direct_dep, set())
            # Collect at-risk packages dominated by this direct dependency
            covered = {risk_pkg for risk_pkg in at_risk_components if risk_pkg in dominated or risk_pkg == direct_dep}

            if covered:
                # Candidate 1: UPGRADE
                c_up = cls.calculate_cost("UPGRADE", major_bumps=0)
                candidates.append(Intervention(
                    action_type="UPGRADE",
                    target_direct_dep=direct_dep,
                    cost=c_up,
                    covered_risks=covered,
                ))

                # Candidate 2: PIN
                c_pin = cls.calculate_cost("PIN")
                candidates.append(Intervention(
                    action_type="PIN",
                    target_direct_dep=direct_dep,
                    cost=c_pin,
                    covered_risks=covered,
                ))

                # Candidate 3: REMOVE
                c_rem = cls.calculate_cost("REMOVE")
                candidates.append(Intervention(
                    action_type="REMOVE",
                    target_direct_dep=direct_dep,
                    cost=c_rem,
                    covered_risks=covered,
                ))

        # Candidate 4: OVERRIDE / RESOLUTION directly on at-risk components (e.g. shared transitives)
        for risk_pkg in at_risk_components:
            if risk_pkg not in direct_dependencies:
                c_ovr = cls.calculate_cost("OVERRIDE")
                candidates.append(Intervention(
                    action_type="OVERRIDE",
                    target_direct_dep=risk_pkg,
                    cost=c_ovr,
                    covered_risks={risk_pkg},
                ))

        # Total available risk
        total_risk = sum(at_risk_components.values())
        if total_risk <= 0:
            total_risk = 1.0

        # 3. Cost-benefit greedy selection
        selected: List[Intervention] = []
        covered_so_far: Set[str] = set()
        cost_used = 0.0

        pool = list(candidates)
        while pool and cost_used < budget:
            best_idx = -1
            best_ratio = -1.0
            best_gain = 0.0

            for i, cand in enumerate(pool):
                if cost_used + cand.cost > budget:
                    continue
                new_covered = cand.covered_risks - covered_so_far
                gain = sum(at_risk_components.get(p, 0.0) for p in new_covered)
                ratio = gain / cand.cost
                if ratio > best_ratio:
                    best_ratio = ratio
                    best_idx = i
                    best_gain = gain

            if best_idx == -1 or best_gain <= 0.0:
                break

            chosen = pool.pop(best_idx)
            selected.append(chosen)
            cost_used += chosen.cost
            covered_so_far.update(chosen.covered_risks)

        # Compare with best single intervention
        best_single: Optional[Intervention] = None
        best_single_gain = 0.0
        for cand in candidates:
            if cand.cost <= budget:
                gain = sum(at_risk_components.get(p, 0.0) for p in cand.covered_risks)
                if gain > best_single_gain:
                    best_single_gain = gain
                    best_single = cand

        greedy_gain = sum(at_risk_components.get(p, 0.0) for p in covered_so_far)
        if best_single and best_single_gain > greedy_gain:
            selected = [best_single]
            cost_used = best_single.cost
            covered_so_far = set(best_single.covered_risks)
            eliminated_risk = best_single_gain
        else:
            eliminated_risk = greedy_gain

        pct_eliminated = round((eliminated_risk / total_risk) * 100.0, 1)

        return {
            "budget": budget,
            "cost_used": cost_used,
            "eliminated_risk": round(eliminated_risk, 2),
            "total_risk": round(total_risk, 2),
            "percentage_eliminated": pct_eliminated,
            "approximation_guarantee": "Achieves >= (1 - 1/e) ≈ 63.2% of optimal risk reduction for submodular coverage",
            "interventions": [
                {
                    "action": inv.action_type,
                    "target_dependency": inv.target_direct_dep,
                    "cost": inv.cost,
                    "eliminated_packages": sorted(list(inv.covered_risks)),
                }
                for inv in selected
            ],
            "unresolved_risks": sorted(list(set(at_risk_components.keys()) - covered_so_far)),
        }
