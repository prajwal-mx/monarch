"""SBOM parsers for CycloneDX and SPDX formats.
Implements Section 4.1 and Section 10 (client-side privacy-first SBOM ingestion).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from monarch.customer.lockfile_parser import ParsedDependency


class SBOMParser:
    """Parses standard CycloneDX and SPDX SBOM documents."""

    @staticmethod
    def parse_cyclonedx(content: str) -> Dict[str, ParsedDependency]:
        data = json.loads(content)
        result: Dict[str, ParsedDependency] = {}
        components = data.get("components", [])

        # Build dep graph if dependencies section is present
        deps_map: Dict[str, List[str]] = {}
        for d in data.get("dependencies", []):
            ref = d.get("ref", "")
            deps_map[ref] = d.get("dependsOn", [])

        for comp in components:
            name = comp.get("name", "")
            version = comp.get("version", "0.0.0")
            bom_ref = comp.get("bom-ref", "")

            # Direct if listed in top-level metadata.component
            result[name] = ParsedDependency(
                name=name,
                version=version,
                is_direct=False,
                dependencies={dep_ref: "*" for dep_ref in deps_map.get(bom_ref, [])},
            )

        return result

    @staticmethod
    def parse_spdx(content: str) -> Dict[str, ParsedDependency]:
        data = json.loads(content)
        result: Dict[str, ParsedDependency] = {}
        packages = data.get("packages", [])

        for pkg in packages:
            name = pkg.get("name", "")
            version = pkg.get("versionInfo", "0.0.0")
            result[name] = ParsedDependency(
                name=name,
                version=version,
                is_direct=False,
            )

        return result
