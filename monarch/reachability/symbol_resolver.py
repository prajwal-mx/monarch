"""T2 Symbol-Level Reachability Resolver.
Implements the algorithm and failure mode guards specified in Section 3.D.2 and 3.D.3.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple
from monarch.common.models import ReachabilityTier
from monarch.reachability.ast_indexer import ImportedModule


class SymbolReachabilityResolver:
    """Evaluates whether a vulnerable component and its specific symbols are reachable."""

    @classmethod
    def evaluate_reachability(
        cls,
        package_name: str,
        import_index: Dict[str, ImportedModule],
        affected_symbols: Optional[Set[str]] = None,
        has_install_hook: bool = False,
        is_transitive: bool = False,
    ) -> Tuple[ReachabilityTier, str, str]:
        """Returns (reachability_tier, confidence_level, explanation).
        Confidence levels: HIGH, MEDIUM, LOW.
        """
        # Rule 1: Install-time execution bypasses import graph (§3.D.2)
        if has_install_hook:
            return (
                ReachabilityTier.REACHABLE_INSTALL,
                "HIGH",
                "Install-time scripts (preinstall/postinstall) execute automatically during dependency installation.",
            )

        # Rule 2: Package not in first-party import index
        if package_name not in import_index:
            if is_transitive:
                return (
                    ReachabilityTier.NOT_REACHABLE,
                    "MEDIUM",
                    "Transitive package not directly referenced in application code.",
                )
            return (
                ReachabilityTier.NOT_REACHABLE,
                "HIGH",
                "Package is not imported anywhere in source code.",
            )

        mod = import_index[package_name]

        # Rule 3: Advisory specifies affected export symbols
        if affected_symbols:
            matching_symbols = mod.symbols.intersection(affected_symbols)
            if matching_symbols:
                first_sym = list(matching_symbols)[0]
                site_info = f" at {mod.sites[0][0]}:{mod.sites[0][1]}" if mod.sites else ""
                return (
                    ReachabilityTier.REACHABLE,
                    "HIGH",
                    f"Vulnerable symbol '{first_sym}' is explicitly imported{site_info}.",
                )

            # Failure modes (§3.D.3): namespace imports or dynamic requires cannot be ruled out
            if mod.is_dynamic or mod.is_namespace:
                return (
                    ReachabilityTier.UNKNOWN,
                    "LOW",
                    "Namespace ('* as') or dynamic require obscures symbol usage; cannot guarantee safety.",
                )

            # Package imported, but specific vulnerable export is NOT imported
            return (
                ReachabilityTier.NOT_REACHABLE,
                "HIGH",
                f"Package is imported, but vulnerable symbols {sorted(list(affected_symbols))} are not referenced.",
            )

        # Rule 4: Package imported, but advisory has no symbol granularity
        return (
            ReachabilityTier.REACHABLE,
            "LOW",
            "Package is imported in application code, but advisory lacks symbol granularity.",
        )
