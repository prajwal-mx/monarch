"""Evidence Contract and Alert Formatting.
Implements the legal, ethical, and non-accusatory evidence contract per Section 8.1 and 4.3.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


class EvidenceContractFormatter:
    """Formats findings adhering strictly to the Section 8.1 Evidence Contract."""

    @staticmethod
    def format_alert(
        package_name: str,
        version_str: str,
        fragility_score: float,
        consequence_score: float,
        calibrated_p: float,
        evidence_items: List[Dict[str, Any]],
        recommended_action: str,
        exposure_paths: Optional[List[str]] = None,
        model_version: str = "fragility-1.0.0",
        epoch_id: str = "epoch-active",
    ) -> Dict[str, Any]:
        """Produce the verifiable, compliant evidence contract payload."""
        return {
            "signal_type": "CUSTODY_OR_ARTIFACT_ANOMALY",
            "assertion": f"Observed custody or structural anomalies in {package_name}@{version_str}.",
            "NOT_an_assertion": "This maintainer is malicious.",
            "package": package_name,
            "version": version_str,
            "assessment": {
                "fragility_score": fragility_score,
                "consequence_score": consequence_score,
                "calibrated_probability": calibrated_p,
                "confidence": "HIGH" if calibrated_p >= 0.5 else "MEDIUM",
            },
            "evidence": evidence_items,
            "exposure": {
                "project_paths": exposure_paths or [],
                "distinct_paths_count": len(exposure_paths or []),
            },
            "base_rate_note": (
                "Pattern observed in historical compromise incidents; also occurs in benign "
                "ownership handovers. Review recommended before taking disruptive action."
            ),
            "model_version": model_version,
            "epoch_id": epoch_id,
            "recommended_action": recommended_action,
        }
