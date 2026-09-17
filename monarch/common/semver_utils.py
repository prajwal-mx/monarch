"""Semver normalization, sortable byte encoding, range classification and matching.
Implements the precise semver rules specified in Section 2.1, 2.3, 3.A.4, and 5.2.
"""

from __future__ import annotations

import re
import struct
from typing import Optional, Tuple
from monarch.common.models import RangeClass

# Regex for strict and loose semver
SEMVER_REGEX = re.compile(
    r"^[vV]?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$"
)


def parse_semver(v_str: str) -> Optional[Tuple[int, int, int, Optional[str], Optional[str]]]:
    """Parse version string into (major, minor, patch, prerelease, build)."""
    if not v_str:
        return None
    cleaned = v_str.strip()
    m = SEMVER_REGEX.match(cleaned)
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2)) if m.group(2) is not None else 0
    patch = int(m.group(3)) if m.group(3) is not None else 0
    prerelease = m.group(4)
    build = m.group(5)
    return (major, minor, patch, prerelease, build)


def semver_sort_key(version_str: str) -> bytes:
    """Precompute a lexicographically sortable byte encoding (version_sort BYTEA).
    Layout:
      - 4 bytes major (uint32)
      - 4 bytes minor (uint32)
      - 4 bytes patch (uint32)
      - 1 byte flag (0 for prerelease present, 1 for final release - because prerelease < final)
      - prerelease string bytes (if any) + null terminator
    """
    parsed = parse_semver(version_str)
    if not parsed:
        # Fallback for non-semver: zero numbers + ascii bytes
        return struct.pack(">IIIB", 0, 0, 0, 0) + version_str.encode("utf-8", "ignore")[:64]

    major, minor, patch, prerelease, _ = parsed
    flag = 0 if prerelease else 1
    header = struct.pack(">IIIB", major, minor, patch, flag)
    if prerelease:
        # Prerelease identifiers
        prerelease_bytes = prerelease.encode("utf-8", "ignore")[:64] + b"\x00"
        return header + prerelease_bytes
    return header


def classify_range(range_str: str) -> RangeClass:
    """Classify dependency version constraint into RangeClass 0-8 (§2.3)."""
    if not range_str:
        return RangeClass.WILDCARD
    s = range_str.strip()
    if s.startswith("workspace:"):
        return RangeClass.WORKSPACE
    if s.startswith("npm:"):
        return RangeClass.ALIAS
    if s.startswith("git+") or s.startswith("git://") or s.startswith("github:"):
        return RangeClass.GIT
    if s.startswith("http://") or s.startswith("https://") or s.startswith("file:"):
        return RangeClass.URL
    if s in ("*", "latest", "x", "X", ""):
        return RangeClass.WILDCARD
    if s.startswith("~"):
        return RangeClass.TILDE
    if s.startswith("^"):
        return RangeClass.CARET
    if s.startswith(">") or s.startswith("<") or " - " in s or "||" in s or " " in s:
        return RangeClass.RANGE
    if s.startswith("="):
        return RangeClass.EXACT
    # If it parses directly as a plain semver, it's exact
    if parse_semver(s) is not None:
        return RangeClass.EXACT
    return RangeClass.RANGE


def semver_satisfies(version_str: str, range_str: str) -> bool:
    """Check if version_str satisfies range_str according to npm semver semantics."""
    parsed_v = parse_semver(version_str)
    if not parsed_v:
        return False
    v_maj, v_min, v_pat, v_pre, _ = parsed_v

    r_class = classify_range(range_str)
    r_str = range_str.strip()

    if r_class == RangeClass.WILDCARD:
        # Wildcard matches anything except prerelease unless specified
        return v_pre is None

    if r_class == RangeClass.EXACT:
        clean_r = r_str.lstrip("=").strip()
        parsed_r = parse_semver(clean_r)
        if not parsed_r:
            return False
        return (v_maj, v_min, v_pat, v_pre) == (parsed_r[0], parsed_r[1], parsed_r[2], parsed_r[3])

    if r_class == RangeClass.CARET:
        target = r_str.lstrip("^").strip()
        parsed_r = parse_semver(target)
        if not parsed_r:
            return False
        r_maj, r_min, r_pat, r_pre, _ = parsed_r
        # Prerelease exclusion
        if v_pre and not r_pre:
            return False
        # Version must be >= target
        if (v_maj, v_min, v_pat) < (r_maj, r_min, r_pat):
            return False
        # Caret semantics (§5.2):
        if r_maj > 0:
            return v_maj == r_maj
        elif r_min > 0:
            return v_maj == 0 and v_min == r_min
        else:
            return v_maj == 0 and v_min == 0 and v_pat == r_pat

    if r_class == RangeClass.TILDE:
        target = r_str.lstrip("~").strip()
        parsed_r = parse_semver(target)
        if not parsed_r:
            return False
        r_maj, r_min, r_pat, r_pre, _ = parsed_r
        if v_pre and not r_pre:
            return False
        if (v_maj, v_min, v_pat) < (r_maj, r_min, r_pat):
            return False
        # Tilde matches same major & minor
        return v_maj == r_maj and v_min == r_min

    # For general ranges (e.g. >=1.0.0 <2.0.0)
    parts = [p.strip() for p in r_str.split() if p.strip()]
    for part in parts:
        if part.startswith(">="):
            tgt = parse_semver(part[2:])
            if not tgt or (v_maj, v_min, v_pat) < (tgt[0], tgt[1], tgt[2]):
                return False
        elif part.startswith(">"):
            tgt = parse_semver(part[1:])
            if not tgt or (v_maj, v_min, v_pat) <= (tgt[0], tgt[1], tgt[2]):
                return False
        elif part.startswith("<="):
            tgt = parse_semver(part[2:])
            if not tgt or (v_maj, v_min, v_pat) > (tgt[0], tgt[1], tgt[2]):
                return False
        elif part.startswith("<"):
            tgt = parse_semver(part[1:])
            if not tgt or (v_maj, v_min, v_pat) >= (tgt[0], tgt[1], tgt[2]):
                return False

    return True


def propagation_probability(range_raw: str, range_class: RangeClass, introduced_version: str) -> float:
    """Compute propagation probability pi(e, x) per §3.A.4.
    Exact pin: 0.0
    Tilde: 1.0 if x is patch, else 0.0
    Caret: 1.0 if x < 2.0.0 (compatible), else 0.0
    Wildcard: 1.0
    Git / URL: 0.0 for registry compromise
    """
    if range_class == RangeClass.EXACT:
        return 0.0
    if range_class in (RangeClass.GIT, RangeClass.URL):
        return 0.0
    if range_class == RangeClass.WILDCARD:
        return 1.0

    if semver_satisfies(introduced_version, range_raw):
        return 1.0
    return 0.0
