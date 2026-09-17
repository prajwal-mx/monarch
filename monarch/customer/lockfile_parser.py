"""Lockfile parsers for npm (v1/v2/v3), yarn, and pnpm.
Implements Section 4.1 and 5.3 (always prefer lockfile as source of truth).
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import yaml


class ParsedDependency:
    def __init__(
        self,
        name: str,
        version: str,
        is_direct: bool = False,
        dependencies: Optional[Dict[str, str]] = None,
        integrity: Optional[str] = None,
    ):
        self.name = name
        self.version = version
        self.is_direct = is_direct
        self.dependencies = dependencies or {}
        self.integrity = integrity


class LockfileParser:
    """Parses npm, yarn, and pnpm lockfiles into resolved dependency trees."""

    @staticmethod
    def parse_npm_lockfile(content: str) -> Dict[str, ParsedDependency]:
        data = json.loads(content)
        lockfile_version = data.get("lockfileVersion", 1)
        result: Dict[str, ParsedDependency] = {}

        if lockfile_version in (2, 3) and "packages" in data:
            # v2/v3 format
            pkgs = data["packages"]
            root = pkgs.get("", {})
            root_deps = set((root.get("dependencies") or {}).keys())

            for path, info in pkgs.items():
                if not path:
                    continue  # skip root
                # path like "node_modules/chalk" or "node_modules/foo/node_modules/bar"
                parts = path.split("node_modules/")
                pkg_name = parts[-1]
                version = info.get("version", "0.0.0")
                is_direct = pkg_name in root_deps and len(parts) == 2
                deps = info.get("dependencies", {}) or {}

                result[pkg_name] = ParsedDependency(
                    name=pkg_name,
                    version=version,
                    is_direct=is_direct,
                    dependencies=deps,
                    integrity=info.get("integrity"),
                )
        else:
            # v1 format
            deps = data.get("dependencies", {})
            for name, info in deps.items():
                version = info.get("version", "0.0.0")
                sub_deps = info.get("dependencies", {}) or {}
                result[name] = ParsedDependency(
                    name=name,
                    version=version,
                    is_direct=True,
                    dependencies={k: v.get("version", "*") for k, v in sub_deps.items()},
                    integrity=info.get("integrity"),
                )
        return result

    @staticmethod
    def parse_yarn_lockfile(content: str) -> Dict[str, ParsedDependency]:
        """Parse Yarn v1 lockfile format."""
        result: Dict[str, ParsedDependency] = {}
        blocks = content.split("\n\n")

        for block in blocks:
            lines = [l.strip() for l in block.splitlines() if l.strip() and not l.startswith("#")]
            if not lines:
                continue
            header = lines[0]
            # e.g. "chalk@^4.1.0", "chalk@4.1.2:"
            m = re.match(r"^\"?(@?[^@]+)@", header)
            if not m:
                continue
            pkg_name = m.group(1).rstrip(":")
            version = "0.0.0"
            deps: Dict[str, str] = {}
            in_deps = False

            for line in lines[1:]:
                if line.startswith("version "):
                    version = line.split("version ")[1].strip('"\';')
                elif line.startswith("dependencies:"):
                    in_deps = True
                elif in_deps:
                    if line.endswith(":"):
                        in_deps = False
                    else:
                        d_parts = line.split()
                        if len(d_parts) >= 2:
                            deps[d_parts[0].strip('":')] = d_parts[1].strip('"\';')

            if pkg_name not in result:
                result[pkg_name] = ParsedDependency(
                    name=pkg_name, version=version, is_direct=True, dependencies=deps
                )

        return result

    @staticmethod
    def parse_pnpm_lockfile(content: str) -> Dict[str, ParsedDependency]:
        """Parse pnpm-lock.yaml format."""
        data = yaml.safe_load(content)
        result: Dict[str, ParsedDependency] = {}
        importers = data.get("importers", {}).get(".", {})
        direct_deps = set((importers.get("dependencies") or {}).keys())

        packages = data.get("packages", {}) or {}
        for pkg_key, pkg_info in packages.items():
            # e.g. "/chalk@4.1.2" or "chalk@4.1.2"
            clean_key = pkg_key.lstrip("/")
            parts = clean_key.split("@")
            if len(parts) >= 2:
                name = "@".join(parts[:-1]) if parts[0] == "" else parts[0]
                version = parts[-1]
            else:
                name = clean_key
                version = "0.0.0"

            deps = pkg_info.get("dependencies", {}) or {}
            result[name] = ParsedDependency(
                name=name,
                version=version,
                is_direct=(name in direct_deps),
                dependencies=deps,
            )

        return result
