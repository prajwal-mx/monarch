"""Point-in-Time Incident Backtesting Harness.
Implements Section 9 and Appendix B over documented historical supply chain incidents.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple
from monarch.fragility.baseline import AnomalyNormalizer
from monarch.fragility.model import FragilityModel


# Reference historical incident corpus from Appendix B
HISTORICAL_INCIDENTS: List[Dict[str, Any]] = [
    {
        "incident_id": "event-stream-2018",
        "package": "event-stream",
        "version": "3.3.6",
        "year": 2018,
        "mechanism": "Dormancy handover to stranger + malicious preinstall hook (flatmap-stream)",
        "advisory_id": "GHSA-mh6f-8j2x-4483",
        "cve_id": "CVE-2018-3721",
        "advisory_url": "https://osv.dev/vulnerability/GHSA-mh6f-8j2x-4483",
        "is_malicious": True,
        "features": {
            "ownership_churn": 1.0,
            "churn_after_dormancy": 1.0,  # 600+ days dormant
            "new_install_hook": 1.0,      # flatmap-stream preinstall
            "bus_factor": 2.0,
            "first_publish_by_new_owner": 1.0,
            "cadence_break": 2.5,
            "provenance_drift": 0.0,
            "trusted_publishing": 0.0,
            "repo_drift": 0.0,
        },
    },
    {
        "incident_id": "xz-utils-cve-2024-3094",
        "package": "xz-utils-embedded",
        "version": "5.6.1",
        "year": 2024,
        "mechanism": "2-year social engineering + tarball repo drift (M4 backdoor)",
        "advisory_id": "CVE-2024-3094",
        "cve_id": "CVE-2024-3094",
        "advisory_url": "https://osv.dev/vulnerability/CVE-2024-3094",
        "is_malicious": True,
        "features": {
            "ownership_churn": 1.0,
            "churn_after_dormancy": 1.0,
            "repo_drift": 15.0,           # decisive signal: 15 files in tarball absent from repo
            "bus_factor": 2.0,
            "new_install_hook": 0.0,
            "first_publish_by_new_owner": 0.0,
            "cadence_break": 1.5,
            "size_delta": 0.5,
            "provenance_drift": 0.0,
            "trusted_publishing": 0.0,
        },
    },
    {
        "incident_id": "shai-hulud-v2",
        "package": "shai-hulud-worm",
        "version": "2.0.1",
        "year": 2026,
        "mechanism": "Self-replicating npm worm + preinstall execution + broad portfolio",
        "advisory_id": "DEMO-WORM-2026",
        "cve_id": "Synthetic Benchmark",
        "advisory_url": "https://github.com/advisories",
        "is_malicious": True,
        "features": {
            "publisher_portfolio_breadth": 45.0,  # controls 45 victim packages
            "new_install_hook": 1.0,              # preinstall execution
            "rapid_republish": 1.0,
            "provenance_drift": 1.0,              # token bypass / no OIDC
            "ownership_churn": 1.0,
            "churn_after_dormancy": 0.0,
            "repo_drift": 0.0,
            "trusted_publishing": 0.0,
        },
    },
    {
        "incident_id": "ua-parser-js-2021",
        "package": "ua-parser-js",
        "version": "0.7.29",
        "year": 2021,
        "mechanism": "Account compromise + rapid republish + crypto miner hook",
        "advisory_id": "GHSA-pjwm-rvh2-c87w",
        "cve_id": "CVE-2021-43616",
        "advisory_url": "https://osv.dev/vulnerability/GHSA-pjwm-rvh2-c87w",
        "is_malicious": True,
        "features": {
            "rapid_republish": 1.0,
            "new_install_hook": 1.0,
            "entropy_spike": 1.8,
            "cadence_break": 3.0,
            "ownership_churn": 0.0,
            "churn_after_dormancy": 0.0,
            "repo_drift": 0.0,
            "trusted_publishing": 0.0,
        },
    },
    # Benign Control Cases (Negative Sampling per Section 9.1)
    {
        "incident_id": "chalk-4.1.2-benign",
        "package": "chalk",
        "version": "4.1.2",
        "year": 2021,
        "mechanism": "Normal bugfix release by trusted maintainer",
        "advisory_id": "BENIGN-CONTROL",
        "cve_id": "None",
        "advisory_url": "https://www.npmjs.com/package/chalk/v/4.1.2",
        "is_malicious": False,
        "features": {
            "ownership_churn": 0.0,
            "churn_after_dormancy": 0.0,
            "new_install_hook": 0.0,
            "bus_factor": 1.0,
            "publisher_portfolio_breadth": 1.0,
            "cadence_break": 0.1,
            "size_delta": 0.02,
            "trusted_publishing": 1.0,
            "repo_drift": 0.0,
        },
    },
    {
        "incident_id": "express-4.18.2-benign",
        "package": "express",
        "version": "4.18.2",
        "year": 2022,
        "mechanism": "Normal release by primary maintainer",
        "advisory_id": "BENIGN-CONTROL",
        "cve_id": "None",
        "advisory_url": "https://www.npmjs.com/package/express/v/4.18.2",
        "is_malicious": False,
        "features": {
            "ownership_churn": 0.0,
            "churn_after_dormancy": 0.0,
            "new_install_hook": 0.0,
            "bus_factor": 1.0,
            "publisher_portfolio_breadth": 1.0,
            "cadence_break": 0.2,
            "size_delta": 0.01,
            "trusted_publishing": 1.0,
            "repo_drift": 0.0,
        },
    },
]


class BacktestHarness:
    """Executes point-in-time incident backtests and reports Precision@N, Recall@N."""

    def __init__(self, model: Optional[FragilityModel] = None):
        self.model = model or FragilityModel()

    def run_backtest(
        self, threshold: float = 70.0, incidents: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        results = []
        tp = 0
        fp = 0
        tn = 0
        fn = 0

        target_incidents = incidents if incidents is not None else HISTORICAL_INCIDENTS
        for inc in target_incidents:
            # Stage 1: Normalize
            s = AnomalyNormalizer.normalize_signals(inc["features"])
            # Stage 2: Predict
            frag_score, prob, contribs = self.model.predict(s)

            predicted_malicious = frag_score >= threshold
            actual_malicious = inc["is_malicious"]

            if predicted_malicious and actual_malicious:
                tp += 1
                status = "TRUE_POSITIVE"
            elif predicted_malicious and not actual_malicious:
                fp += 1
                status = "FALSE_POSITIVE"
            elif not predicted_malicious and not actual_malicious:
                tn += 1
                status = "TRUE_NEGATIVE"
            else:
                fn += 1
                status = "FALSE_NEGATIVE"

            results.append({
                "incident_id": inc["incident_id"],
                "package": inc["package"],
                "version": inc["version"],
                "year": inc.get("year"),
                "mechanism": inc.get("mechanism", ""),
                "advisory_id": inc.get("advisory_id", ""),
                "cve_id": inc.get("cve_id", ""),
                "advisory_url": inc.get("advisory_url", ""),
                "actual_malicious": actual_malicious,
                "fragility_score": frag_score,
                "calibrated_prob": prob,
                "status": status,
                "top_contributions": contribs,
            })

        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0

        return {
            "threshold": threshold,
            "total_incidents": len(target_incidents),
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "details": results,
        }
