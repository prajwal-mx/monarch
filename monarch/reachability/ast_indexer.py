"""JavaScript & TypeScript AST Import and Symbol Indexer.
Implements Section 3.D.2 (T2 Symbol-level reachability import extraction).
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


class ImportedModule:
    def __init__(self, specifier: str):
        self.specifier = specifier
        self.symbols: Set[str] = set()
        self.is_dynamic: bool = False
        self.is_namespace: bool = False
        self.sites: List[Tuple[str, int]] = []


class ASTIndexer:
    """Parses JS/TS files using regex-based AST tokens to extract module imports and symbol names."""

    # Regex patterns for static imports and requires
    ESM_IMPORT = re.compile(
        r"""import\s+(?:(?:\*\s+as\s+([A-Za-z0-9_$]+))|([A-Za-z0-9_$,\s{}*]+))\s+from\s+['"]([^'"]+)['"]""",
        re.MULTILINE,
    )
    CJS_REQUIRE = re.compile(
        r"""(?:const|let|var)\s+([A-Za-z0-9_$,\s{}*]+)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)""",
        re.MULTILINE,
    )
    DYNAMIC_IMPORT = re.compile(
        r"""(?:import|require)\(\s*['"]([^'"]+)['"]\s*\)""",
        re.MULTILINE,
    )

    @classmethod
    def parse_source_code(cls, code: str, file_path: str = "main.js") -> Dict[str, ImportedModule]:
        """Extract imported packages and specific symbols from source text."""
        index: Dict[str, ImportedModule] = {}

        def get_or_create(spec: str) -> ImportedModule:
            clean_spec = spec.strip()
            # Strip relative paths e.g. "./async-dep" -> "async-dep"
            while clean_spec.startswith("./") or clean_spec.startswith("../"):
                if clean_spec.startswith("./"):
                    clean_spec = clean_spec[2:]
                elif clean_spec.startswith("../"):
                    clean_spec = clean_spec[3:]
            # Normalize module name (e.g. "lodash/fp" -> "lodash")
            pkg_name = clean_spec.split("/")[0] if not clean_spec.startswith("@") else "/".join(clean_spec.split("/")[:2])
            if pkg_name not in index:
                index[pkg_name] = ImportedModule(pkg_name)
            return index[pkg_name]

        # 1. ESM Imports
        for m in cls.ESM_IMPORT.finditer(code):
            ns_import = m.group(1)
            named_or_default = m.group(2)
            specifier = m.group(3)

            mod = get_or_create(specifier)
            line_no = code[: m.start()].count("\n") + 1
            mod.sites.append((file_path, line_no))

            if ns_import:
                mod.is_namespace = True
            elif named_or_default:
                clean = named_or_default.strip()
                if "{" in clean:
                    # Named imports: e.g. { foo, bar as b }
                    inner = clean[clean.find("{") + 1 : clean.rfind("}")]
                    for sym_token in inner.split(","):
                        sym = sym_token.strip().split(" as ")[0].strip()
                        if sym:
                            mod.symbols.add(sym)
                else:
                    # Default import
                    mod.symbols.add("default")

        # 2. CommonJS Requires
        for m in cls.CJS_REQUIRE.finditer(code):
            binding = m.group(1).strip()
            specifier = m.group(2)
            mod = get_or_create(specifier)
            line_no = code[: m.start()].count("\n") + 1
            mod.sites.append((file_path, line_no))

            if "{" in binding:
                inner = binding[binding.find("{") + 1 : binding.rfind("}")]
                for sym_token in inner.split(","):
                    sym = sym_token.strip().split(":")[0].strip()
                    if sym:
                        mod.symbols.add(sym)
            else:
                mod.is_namespace = True

        # 3. Dynamic Imports
        for m in cls.DYNAMIC_IMPORT.finditer(code):
            specifier = m.group(1)
            mod = get_or_create(specifier)
            mod.is_dynamic = True
            line_no = code[: m.start()].count("\n") + 1
            mod.sites.append((file_path, line_no))

        return index

    @classmethod
    def index_directory(cls, dir_path: str) -> Dict[str, ImportedModule]:
        """Recursively index all JS/TS files in a directory."""
        master_index: Dict[str, ImportedModule] = {}
        p = Path(dir_path)

        for root, dirs, files in os.walk(p):
            # Exclude node_modules, .git, dist, build
            dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "dist", "build", ".pytest_cache")]
            for f in files:
                if f.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
                    full_path = os.path.join(root, f)
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                            content = fh.read()
                            file_idx = cls.parse_source_code(content, full_path)
                            for pkg, mod in file_idx.items():
                                if pkg not in master_index:
                                    master_index[pkg] = mod
                                else:
                                    master_index[pkg].symbols.update(mod.symbols)
                                    master_index[pkg].sites.extend(mod.sites)
                                    master_index[pkg].is_dynamic |= mod.is_dynamic
                                    master_index[pkg].is_namespace |= mod.is_namespace
                    except Exception:
                        pass

        return master_index
