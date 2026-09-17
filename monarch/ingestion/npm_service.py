"""Live NPM Registry Integration Service with In-Memory and Local Caching.
Fetches and extracts genuine maintainer, cadence, install hook, and provenance telemetry.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("monarch.npm_service")


class NPMRegistryService:
    """Fetches and caches live package packuments from registry.npmjs.org."""

    _cache: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def get_package_telemetry(cls, package_name: str, version: Optional[str] = None) -> Optional[Dict[str, Any]]:
        clean_name = package_name.strip()
        if not clean_name or clean_name in (
            "root-application",
            "customer-repo",
            "my-project",
            "ecommerce-portal",
            "internal-service",
        ):
            return None

        # Check cache
        if clean_name in cls._cache:
            return cls._extract_telemetry(cls._cache[clean_name], version)

        # Live fetch from registry.npmjs.org
        url = f"https://registry.npmjs.org/{clean_name}"
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "monarch-security-platform/1.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                cls._cache[clean_name] = data
                return cls._extract_telemetry(data, version)
        except Exception as e:
            logger.debug(f"Failed to fetch {clean_name} from npm registry: {e}")
            return None

    @classmethod
    def _extract_telemetry(cls, packument: Dict[str, Any], target_ver: Optional[str] = None) -> Dict[str, Any]:
        dist_tags = packument.get("dist-tags", {})
        versions_dict = packument.get("versions", {})
        latest_version = target_ver or dist_tags.get("latest") or (
            list(versions_dict.keys())[-1] if versions_dict else "1.0.0"
        )
        ver_info = versions_dict.get(latest_version, {})

        # 1. Maintainers
        maintainers = packument.get("maintainers", [])
        m_count = len(maintainers) if maintainers else 1

        # 2. Scripts and Install hooks
        scripts = ver_info.get("scripts", {}) if isinstance(ver_info.get("scripts"), dict) else {}
        has_install_hook = any(h in scripts for h in ["preinstall", "install", "postinstall"])

        # 3. Provenance & Attestations
        dist = ver_info.get("dist", {})
        has_provenance = bool(dist.get("attestations") or dist.get("signatures"))

        # 4. Release cadence & dormancy
        times = packument.get("time", {})
        sorted_times = []
        for v, t_str in times.items():
            if v not in ("created", "modified"):
                try:
                    dt = datetime.fromisoformat(t_str.replace("Z", "+00:00"))
                    sorted_times.append((dt, v))
                except Exception:
                    pass
        sorted_times.sort(key=lambda x: x[0])

        days_dormant = 0
        cadence_break = 0.1
        if len(sorted_times) >= 2:
            last_dt = sorted_times[-1][0]
            prev_dt = sorted_times[-2][0]
            diff_days = max(0, (last_dt - prev_dt).total_seconds() / 86400.0)
            days_dormant = int(diff_days)

            # Compare to historical median interval
            intervals = [
                (sorted_times[i][0] - sorted_times[i - 1][0]).total_seconds() / 86400.0
                for i in range(1, len(sorted_times))
            ]
            if intervals:
                intervals.sort()
                med_interval = intervals[len(intervals) // 2]
                if med_interval > 0:
                    cadence_break = round(diff_days / max(1.0, med_interval), 2)

        unpacked_size = dist.get("unpackedSize", 0)
        file_count = dist.get("fileCount", 0)

        return {
            "name": packument.get("name"),
            "latest_version": latest_version,
            "maintainer_count": m_count,
            "maintainers": [m.get("name") if isinstance(m, dict) else str(m) for m in maintainers],
            "has_install_hook": has_install_hook,
            "install_hook_names": [h for h in ["preinstall", "install", "postinstall"] if h in scripts],
            "provenance_attested": has_provenance,
            "days_dormant": days_dormant,
            "cadence_break": cadence_break,
            "unpacked_size_bytes": unpacked_size,
            "file_count": file_count,
            "repository": (
                str(packument.get("repository", {}).get("url", ""))
                if isinstance(packument.get("repository"), dict)
                else str(packument.get("repository", ""))
            ),
        }
