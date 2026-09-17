"""OpenVEX and CycloneDX VEX document emission.
Implements the formal compliance bridge and CRA reporting assertions specified in Section 3.D.4.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from monarch.common.models import ReachabilityTier


class VEXGenerator:
    """Generates specification-compliant OpenVEX and CycloneDX VEX documents."""

    @classmethod
    def create_openvex_document(
        cls,
        statements: List[Dict[str, Any]],
        author: str = "Monarch Software Supply Chain Security Platform",
    ) -> Dict[str, Any]:
        """Generate OpenVEX 0.2.0 document from reachability determinations."""
        doc_id = f"https://monarch.dev/vex/{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()

        vex_statements = []
        for s in statements:
            pkg = s["package"]
            version = s["version"]
            vuln_id = s.get("vulnerability_id", "MAL-MONARCH-001")
            tier: ReachabilityTier = s["reachability_tier"]
            conf: str = s.get("confidence", "LOW")
            justification = None
            impact_statement = s.get("explanation", "")

            # Strict compliance mapping per Section 3.D.4
            if tier == ReachabilityTier.NOT_REACHABLE and conf == "HIGH":
                status = "not_affected"
                justification = "vulnerable_code_not_in_execute_path"
            elif tier in (ReachabilityTier.REACHABLE, ReachabilityTier.REACHABLE_INSTALL):
                status = "affected"
            else:
                # Any MEDIUM or LOW confidence NOT_REACHABLE or UNKNOWN MUST be under_investigation (§3.D.4)
                status = "under_investigation"

            stmt = {
                "vulnerability": {"name": vuln_id},
                "products": [{"@id": f"pkg:npm/{pkg}@{version}"}],
                "status": status,
            }
            if justification:
                stmt["justification"] = justification
            if impact_statement:
                stmt["impact_statement"] = impact_statement

            vex_statements.append(stmt)

        return {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": doc_id,
            "author": author,
            "timestamp": now_iso,
            "version": 1,
            "statements": vex_statements,
        }

    @classmethod
    def create_cyclonedx_vex(
        cls,
        statements: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Generate CycloneDX 1.5 VEX document."""
        now_iso = datetime.now(timezone.utc).isoformat()
        analyses = []

        for s in statements:
            pkg = s["package"]
            version = s["version"]
            vuln_id = s.get("vulnerability_id", "MAL-MONARCH-001")
            tier: ReachabilityTier = s["reachability_tier"]
            conf: str = s.get("confidence", "LOW")

            if tier == ReachabilityTier.NOT_REACHABLE and conf == "HIGH":
                state = "not_affected"
                justification = "code_not_reachable"
            elif tier in (ReachabilityTier.REACHABLE, ReachabilityTier.REACHABLE_INSTALL):
                state = "exploitable"
                justification = None
            else:
                state = "in_triage"
                justification = None

            item = {
                "ref": f"pkg:npm/{pkg}@{version}",
                "state": state,
                "detail": s.get("explanation", ""),
            }
            if justification:
                item["justification"] = justification
            analyses.append(item)

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": now_iso,
                "tools": [{"vendor": "Monarch", "name": "Monarch VEX Engine", "version": "1.0.0"}],
            },
            "vulnerabilities": [
                {
                    "id": statements[0].get("vulnerability_id", "MAL-MONARCH-001") if statements else "UNKNOWN",
                    "analysis": analyses[0] if analyses else {},
                }
            ],
        }
